# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Observation points: log that the firmware reached a named place, and let it
run.

VESC says nothing over any wire until its COMM stack is up, so without these a
stall has no location. Each handler returns "not handled", so the intercepted
function itself executes; they exist to turn "the rehost is quiet" into "the
firmware last reached ``mc_interface_init``".

Kept deliberately few — a breakpoint costs emulation speed (playbook §2.51, hence
``HAL_FAST_BP``).

``ChibiosHalt`` is the important one. ChibiOS' ``chSysHalt(const char *reason)``
masks interrupts and spins forever, so a kernel panic presents as an anonymous
hang; four lines that read the string turn it into a named cause (playbook
§2.67). VESC wraps it in ``main_system_halt()``, which takes the same argument.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, cast

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import (BPHandler, HandlerFunction,
                                                HandlerReturn, bp_handler)

if TYPE_CHECKING:  # pragma: no cover
    from halucinator.backends.hal_backend import HalBackend

log = hal_log.getHalLogger()


def _read_cstr(qemu: "HalBackend", addr: int, limit: int = 96) -> str:
    if not addr:
        return "<null>"
    try:
        raw = bytes(qemu.read_memory(addr, 1, limit, raw=True))
    except Exception:  # noqa: BLE001
        return "<unreadable 0x%08x>" % addr
    return raw.split(b"\x00", 1)[0].decode("latin-1")


class BootTrace(BPHandler):
    """Log a labelled milestone. One instance can serve several intercepts, so
    per-site state is keyed by address (playbook §2.32)."""

    def __init__(self) -> None:
        self.labels: dict = {}
        self.hits: dict = {}
        self.show_lr: dict = {}
        self.count_every: dict = {}

    def register_handler(self, qemu: "HalBackend", addr: int, func_name: str,
                         label: str = "", show_lr: bool = False,
                         count: bool = False,
                         ) -> HandlerFunction:
        self.labels[addr] = label or func_name
        self.hits[addr] = 0
        self.show_lr[addr] = show_lr
        # ``count`` turns a first-hit marker into a per-arrival counter. It is
        # set for ONE site, `commands_process_packet`, because that address is
        # reached exactly once per packet the firmware's OWN `packet.c`
        # decoder accepted -- so the running total is a GUEST-SIDE count of
        # accepted frames, which no host bookkeeping can produce without
        # reimplementing the decoder. It is deliberately not set anywhere else:
        # a per-hit log line on a hot address costs emulation speed.
        self.count_every[addr] = bool(count)
        return cast(HandlerFunction, BootTrace.trace)

    @bp_handler(["boot_trace"])
    def trace(self, qemu: "HalBackend", addr: int) -> HandlerReturn:
        n = self.hits.get(addr, 0) + 1
        self.hits[addr] = n
        if self.count_every.get(addr):
            log.info("BOOT-COUNT: %s n=%d", self.labels.get(addr, hex(addr)), n)
            return False, None
        if n == 1:
            if self.show_lr.get(addr):
                # At a function's FIRST instruction, lr IS the call site --
                # unlike a stack scan from deep inside, which returns stale
                # frames that read like a plausible call chain (playbook §2.110).
                try:
                    lr = qemu.read_register("lr")
                except Exception:  # noqa: BLE001
                    lr = 0
                log.info("BOOT: %s  (called from lr=0x%08x)",
                         self.labels.get(addr, hex(addr)), lr)
            else:
                log.info("BOOT: %s", self.labels.get(addr, hex(addr)))
        return False, None


class ChibiosHalt(BPHandler):
    """Name a kernel panic instead of letting it be an anonymous spin."""

    def __init__(self) -> None:
        self.count = 0

    def register_handler(self, qemu: "HalBackend", addr: int,
                         func_name: str) -> HandlerFunction:
        return cast(HandlerFunction, ChibiosHalt.halt)

    @bp_handler(["chSysHalt", "main_system_halt"])
    def halt(self, qemu: "HalBackend", addr: int) -> HandlerReturn:
        self.count += 1
        if self.count == 1:
            try:
                reason = _read_cstr(qemu, qemu.read_register("r0"))
            except Exception:  # noqa: BLE001
                reason = "<unreadable>"
            log.error("KERNEL PANIC: chSysHalt(%r) -- ChibiOS masks interrupts "
                      "and spins here forever; everything after this point is "
                      "the rehost merely looking slow", reason)
        return False, None
