# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Observe-only code hooks for fuzz REACH on the VESC terminal (COMM_TERMINAL_CMD over USART3)
(lane s1011-laneS).

Every hook returns ``(False, None)``: the firmware's own instruction at that
address still runs. Nothing here answers, replaces or modifies guest state.

Hook kinds (``registration_args: {kind: ..., label: ...}``), all addresses from
``configs/fuzz_reach_targets.json`` (``tools/fuzz_reach_targets.py``, derived
from the image's own ``terminal_process_string`` dispatch):

``r4``        a built-in command's handler block (the EQUAL edge of its
              ``strcmp`` link). argv[0] is in r4 (the string just matched).
``argv_r1``   a registered callback ``cbf(argc, argv)``: argc r0, argv r1.
``decision``  an EMPTY case's conditional branch (``drv_reset_faults``, whose
              equal edge is the function's common exit): records r0 (strcmp's
              result; 0 == equal) and the r4 string.
``default``   the ``Invalid command: %s`` block; r4 = argv[0].
``exit``      the function's common exit, a SHARED LABEL every returning
              command runs; recorded for the weak-rule control only.
``isr``       ``SysTick_Handler`` and the USART3 IRQ handler. Records IPSR,
              the CONTROL for the thread-mode check; counted per IPSR, the
              IPSR-15 count is the guest clock (CH_CFG_ST_FREQUENCY 10 kHz).

Every non-isr record carries ``ipsr`` (thread mode iff 0) and ``argv`` read
from guest memory AT HIT TIME (for r4 kinds a one-element list), so the entry
is identified from guest state, never from what the harness sent.

Also, once per process (row-local, opt-in: only when this probe is in the
config):

* a CHUNK HOOK samples ``(pc, ipsr)`` at every instruction-chunk boundary and
  rewrites ``$FUZZ_REACH_PCRING`` (JSON: the last 64 samples, the per-IPSR
  exception counts, dropped-log counts) at most once a second. Read-only.
* a LOG CAP: a ``logging.Filter`` on the emulator's log handlers that passes at
  most ``FUZZ_REACH_LOG_CAP_PER_MSG`` copies of any one rendered message.

* a WATCHDOG THREAD: chunk boundaries can stop arriving (this row sets
  ``HAL_IRQ_CHUNK`` but a run can still stall inside one emu_start). A guest spinning with interrupts masked (a reset
  that is never performed) therefore produces no chunk samples at all. When no
  chunk sample has landed for 2 s the watchdog reads PC/IPSR from its own
  thread -- a RACY, read-only read; under TCG the PC is the current block's --
  and appends it to the ring flagged ``async``. It changes no guest state.

Per-key record cap: ``PER_KEY_CAP`` records per ``(pc, full argv)``, then one
``capped`` record, then counting only. The key is the FULL argv, not argv[0]:
the same design as the px4 row's probe, where a name-only key silenced an
entry's own later hit.

Evidence: one JSON object per line to ``$FUZZ_REACH_LOG``; the first line
carries this process's pid.
"""
from __future__ import annotations

import collections
import json
import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Any, cast

from halucinator.bp_handlers.bp_handler import (BPHandler, HandlerFunction,
                                                HandlerReturn, bp_handler)

if TYPE_CHECKING:  # pragma: no cover
    from halucinator.backends.hal_backend import HalBackend

_LOCK = threading.Lock()
_FH: Any = None
PER_KEY_CAP = int(os.environ.get("FUZZ_REACH_PER_PC_CAP", "20"))
LOG_CAP = int(os.environ.get("FUZZ_REACH_LOG_CAP_PER_MSG", "20"))
ISR_SAMPLES = 3
_COUNT: dict = {}
_EXC: "collections.Counter" = collections.Counter()
_RING: "collections.deque" = collections.deque(maxlen=64)
_RS: dict = {"n": 0, "last_write": 0.0, "installed": False, "path": None}
_DROPPED: "collections.Counter" = collections.Counter()


def _emit(rec: dict) -> None:
    global _FH
    with _LOCK:
        if _FH is None:
            path = os.environ.get("FUZZ_REACH_LOG")
            if not path:
                return
            _FH = open(path, "a", buffering=1)
            _FH.write(json.dumps({"k": "hello", "pid": os.getpid(),
                                  "t": time.time()}) + "\n")
        rec["t"] = time.time()
        _FH.write(json.dumps(rec) + "\n")


def _uc(qemu: "HalBackend"):
    return qemu._uc  # type: ignore[attr-defined]


def _reg(qemu: "HalBackend", name: str):
    try:
        from unicorn import arm_const as A  # type: ignore
        return int(_uc(qemu).reg_read(getattr(A, "UC_ARM_REG_" + name)))
    except Exception:  # noqa: BLE001
        return None


def _cstr(qemu: "HalBackend", addr, limit: int = 48):
    if not isinstance(addr, int) or addr == 0:
        return None
    try:
        b = bytes(_uc(qemu).mem_read(addr, limit))
    except Exception:  # noqa: BLE001
        return None
    return b.split(b"\x00", 1)[0].decode("latin-1", "replace")


def _argv(qemu: "HalBackend", argc, argv, cap: int = 6):
    if not isinstance(argc, int) or not isinstance(argv, int) or argv == 0:
        return None
    out = []
    for i in range(max(0, min(argc, cap))):
        try:
            p = int.from_bytes(bytes(_uc(qemu).mem_read(argv + 4 * i, 4)), "little")
        except Exception:  # noqa: BLE001
            out.append(None)
            continue
        out.append(_cstr(qemu, p))
    return out


def _write_ring(force: bool = False) -> None:
    path = _RS["path"]
    now = time.time()
    if not path or (not force and now - _RS["last_write"] < 1.0):
        return
    _RS["last_write"] = now
    try:
        tmp = path + ".w"
        with open(tmp, "w") as fh:
            json.dump({"pid": os.getpid(), "t": now, "chunks": _RS["n"],
                       "exc_by_ipsr": {str(k): v for k, v in sorted(_EXC.items())},
                       "ticks": _EXC.get(15, 0), "async_samples": _RS.get("async", 0),
                       "ring": list(_RING), "log_dropped": dict(_DROPPED)}, fh)
        os.replace(tmp, path)
    except OSError:
        pass


class _CapFilter(logging.Filter):
    """At most LOG_CAP copies of one rendered message; count the rest."""

    def __init__(self) -> None:
        super().__init__()
        self.seen: "collections.Counter" = collections.Counter()

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        self.seen[msg] += 1
        if self.seen[msg] <= LOG_CAP:
            return True
        _DROPPED[msg[:160]] += 1
        return False


def _install_once(qemu: "HalBackend") -> None:
    if _RS["installed"]:
        return
    _RS["installed"] = True
    _RS["path"] = os.environ.get("FUZZ_REACH_PCRING")
    flt = _CapFilter()
    handlers = set()
    names = ["", "HAL_LOG"] + list(logging.root.manager.loggerDict)
    for name in names:
        lg = logging.getLogger(name)
        for h in getattr(lg, "handlers", []):
            handlers.add(h)
    for h in handlers:
        h.addFilter(flt)

    def _sample() -> None:
        _RS["n"] += 1
        _RS["last_chunk"] = time.time()
        _RING.append((_reg(qemu, "PC"), _reg(qemu, "IPSR"), round(time.time(), 2)))
        _write_ring()

    def _watch() -> None:
        while True:
            time.sleep(1.0)
            if time.time() - _RS.get("last_chunk", time.time()) >= 2.0:
                _RS["async"] = _RS.get("async", 0) + 1
                _RING.append((_reg(qemu, "PC"), _reg(qemu, "IPSR"),
                              round(time.time(), 2), "async"))
                _write_ring(force=True)
    _RS["last_chunk"] = time.time()
    threading.Thread(target=_watch, daemon=True).start()
    try:
        qemu.add_chunk_hook(_sample)  # type: ignore[attr-defined]
        _emit({"k": "chunk_hook", "ok": True, "log_handlers_capped": len(handlers)})
    except Exception as exc:  # noqa: BLE001
        _emit({"k": "chunk_hook", "ok": False, "err": repr(exc)})


class FuzzReachProbe(BPHandler):
    """Observe-only; see the module docstring."""

    def __init__(self) -> None:
        self._kind: dict = {}
        self._label: dict = {}

    def register_handler(self, qemu: "HalBackend", addr: int, func_name: str,
                         kind: str = "main", label: str = "") -> HandlerFunction:
        _install_once(qemu)
        self._kind[addr] = kind
        self._label[addr] = label or func_name
        _emit({"k": "registered", "kind": kind, "pc": addr,
               "label": self._label[addr]})
        return cast(HandlerFunction, FuzzReachProbe.hit)

    @bp_handler([])
    def hit(self, qemu: "HalBackend", addr: int) -> HandlerReturn:
        kind = self._kind.get(addr, "?")
        ipsr = _reg(qemu, "IPSR")
        if kind == "isr":
            n = _EXC[ipsr] = _EXC.get(ipsr, 0) + 1
            if n <= ISR_SAMPLES:
                _emit({"k": "isr", "pc": addr, "ipsr": ipsr, "n": n,
                       "lr": _reg(qemu, "LR")})
            _write_ring()
            return False, None
        r0 = None
        if kind == "argv_r1":
            argc, argvp = _reg(qemu, "R0"), _reg(qemu, "R1")
            argv = _argv(qemu, argc, argvp)
        else:
            r0 = _reg(qemu, "R0")
            argc, argv = None, [_cstr(qemu, _reg(qemu, "R4"))]
        a0 = argv[0] if argv else None
        key = (addr, tuple(argv) if argv else None)
        c = _COUNT[key] = _COUNT.get(key, 0) + 1
        if c > PER_KEY_CAP:
            if c == PER_KEY_CAP + 1:
                _emit({"k": "capped", "kind": kind, "pc": addr, "argv": argv,
                       "after": PER_KEY_CAP})
            return False, None
        _emit({"k": kind, "pc": addr, "label": self._label.get(addr),
               "ipsr": ipsr, "argc": argc, "argv": argv, "r0": r0,
               "lr": _reg(qemu, "LR"), "sp": _reg(qemu, "SP"),
               "ticks": _EXC.get(15, 0)})
        return False, None          # observe only: the firmware's code runs
