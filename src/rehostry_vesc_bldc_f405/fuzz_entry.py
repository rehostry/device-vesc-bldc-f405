# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fuzz-REACH entry point for this row's VESC terminal, COMM_TERMINAL_CMD over
the USART3 COMM seam (lane s1011-laneS).

WHAT A FUZZER CALLS
-------------------
::

    from rehostry_vesc_bldc_f405.fuzz_entry import reach_one
    r = reach_one(entry="fw_info")                    # a declared terminal command
    r = reach_one(term=b"foc_openloop 1 100")         # any terminal string (framed for you)
    r = reach_one(raw=b"\\x02\\x01\\x14...")            # ARBITRARY bytes onto USART3
    r["handler_hit"], r["live_after"], r["entry_hits"], r["entry_prints"]

``reach_one`` is ONE FRESH BOOT: a pristine copy of ``configs/`` (image sha256
recorded before and after, for the pristine file and the copy), the bridge
listener checked to be THIS child's pid (``lsof``), the input sent FIRST, then
the liveness probe, then the process group is terminated. The CLI
``os._exit``s and ``--sweep`` runs every input in its own child process.

CLI::

    python -m rehostry_vesc_bldc_f405.fuzz_entry --entry fw_info --slot 0 --out x.json
    python -m rehostry_vesc_bldc_f405.fuzz_entry --term "foc_openloop 1 100" --slot 0 --out x.json
    python -m rehostry_vesc_bldc_f405.fuzz_entry --raw-hex 0201140... --slot 0 --out x.json
    python -m rehostry_vesc_bldc_f405.fuzz_entry --sweep --workers 4 --outdir DIR [--only fw_info ...]

HOW REACH IS SHOWN
------------------
``bp_handlers/fuzz_reach_probe.py`` (observe-only) hooks every command's own
handler as derived from ``terminal_process_string``'s dispatch by
``tools/fuzz_reach_targets.py``: a built-in's handler block (argv[0] in r4), a
registered callback's ``cbf`` (argv in r1), or -- for the one EMPTY case,
``drv_reset_faults`` -- the dispatch decision (r0 == 0 at its branch). Also the
``Invalid command`` default and the function's shared exit.

An entry is REACHED only if, after it was sent: a hook on ITS OWN handler fired
with argv[0] == its name (guest memory at hit time) in THREAD mode (IPSR 0),
it was the FIRST handler-class hook (own handler, another entry's handler, or
the default) to fire with that argv[0], and the default never fired with it.

``live_after``: the terminal string ``rh<nonce>`` (lower-case hex, in no byte of
the image) must come back as the firmware's own ``Invalid command: rh<nonce>``
on ONE COMM_PRINT line (the terminal echoes ``-> rh<nonce>`` on its own, so the
conjunction on one line is what makes it the guest's sentence), AND the default
hook must have fired with r4 == ``rh<nonce>`` in thread mode. A second probe
(new nonce) is sent if the first is unanswered at half the window.

Ports: slot k owns ``PORT_LOW + 5k .. +4`` (bridge tcp, zmq rx/tx ipc names),
each asserted inside 39850..39949 before anything is spawned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional

from . import paths, spawn
from . import vesc_comm as vc

PKG = "rehostry_vesc_bldc_f405"
PORT_LOW = int(os.environ.get("FUZZ_REACH_PORT_LOW", "39900"))
PORT_HIGH = int(os.environ.get("FUZZ_REACH_PORT_HIGH", "39949"))
PORTS_PER_SLOT = 5
BOOT_TIMEOUT = float(os.environ.get("FUZZ_REACH_BOOT_TIMEOUT", "900"))
PRE_TICKS = int(os.environ.get("FUZZ_REACH_PRE_TICKS", "5000"))
SETTLE_TICKS = int(os.environ.get("FUZZ_REACH_SETTLE_TICKS", "50000"))
ENTRY_QUIET = float(os.environ.get("FUZZ_REACH_ENTRY_QUIET", "3"))
ENTRY_MAX = float(os.environ.get("FUZZ_REACH_ENTRY_MAX", "120"))
LIVE_TIMEOUT = float(os.environ.get("FUZZ_REACH_LIVE_TIMEOUT", "90"))
FLOOD_BYTES = int(os.environ.get("FUZZ_REACH_EMU_LOG_CAP", str(40 << 20)))
RX_KEEP = 128 << 10
RX_ROLL = 64 << 10
READY = "USART3: enabled by the firmware"
BIND = "vesc uart: LISTENing on tcp/%d"
FAULT_RE = r"UC_ERR|Traceback|FETCH-DERAIL|unmapped (?:read|write|fetch)|KERNEL PANIC"
RESET_RE = r"firmware requested SYSRESETREQ|resets requested"
HANDLER_KINDS = ("r4", "argv_r1", "decision")


def targets() -> dict:
    return json.loads((paths.configs_dir() / "fuzz_reach_targets.json").read_text())


def sha256(p) -> Optional[str]:
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError:
        return None


def _ports(slot: int) -> List[int]:
    base = PORT_LOW + PORTS_PER_SLOT * slot
    ps = list(range(base, base + PORTS_PER_SLOT))
    for p in ps:
        if not (39850 <= p <= 39949 and PORT_LOW <= p <= PORT_HIGH):
            raise ValueError("port %d outside the lane block 39850..39949" % p)
    return ps


def _port_free(p: int) -> bool:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p))
    except OSError:
        return False
    finally:
        s.close()
    return True


def _listener_pids(p: int) -> List[int]:
    try:
        out = subprocess.run(["lsof", "-nP", "-iTCP:%d" % p, "-sTCP:LISTEN", "-t"],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:  # noqa: BLE001
        return []
    return sorted({int(x) for x in out.split() if x.isdigit()})


def overlay_yaml(tg: dict) -> str:
    cls = PKG + ".bp_handlers.fuzz_reach_probe.FuzzReachProbe"
    lines = ["intercepts:"]
    for h in tg["hooks"]:
        a = int(h["addr"], 16)
        lines.append("  - {class: %s, function: fuzzreach_%s_%x, addr: 0x%x, "
                     "registration_args: {kind: %s, label: \"%s\"}}"
                     % (cls, h["kind"], a, a, h["kind"], h["label"]))
    return "\n".join(lines) + "\n"


def _read_jsonl(path: Path) -> List[dict]:
    out = []
    try:
        for ln in path.read_text().splitlines():
            try:
                out.append(json.loads(ln))
            except ValueError:
                pass
    except OSError:
        pass
    return out


def _ring(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


class _Chan:
    """The USART3 bridge, captured per phase (entry: the first RX_KEEP bytes;
    liveness: a rolling RX_ROLL tail)."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.buf = bytearray()
        self.total = 0
        self.phase_total = 0
        self.rolling = False
        self.last_rx = 0.0

    def connect(self, deadline: float) -> None:
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection(("127.0.0.1", self.port), 2)
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                break
            except OSError:
                time.sleep(0.3)
        if self.sock is None:
            raise RuntimeError("bridge tcp/%d never accepted" % self.port)
        self.sock.settimeout(0.2)

    def pump(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            try:
                d = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not d:
                return
            self.total += len(d)
            self.phase_total += len(d)
            self.last_rx = time.time()
            if self.rolling:
                self.buf += d
                if len(self.buf) > RX_ROLL:
                    del self.buf[:len(self.buf) - RX_ROLL]
            else:
                room = RX_KEEP - len(self.buf)
                if room > 0:
                    self.buf += d[:room]

    def phase(self, rolling: bool) -> None:
        self.buf = bytearray()
        self.phase_total = 0
        self.rolling = rolling

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def _frames(raw: bytes) -> List[dict]:
    """Every CRC-valid frame in raw, in order; a byte that starts no valid frame
    is skipped (counted)."""
    out: List[dict] = []
    buf = bytes(raw)
    skipped = 0
    while buf:
        p, used = vc.unframe(buf)
        if p is not None:
            out.append({"id": p[0] if p else None,
                        "text": bytes(p[1:]).split(b"\x00")[0].decode("latin-1", "replace")
                        if p and p[0] == vc.COMM_PRINT else None,
                        "len": len(p), "hex": bytes(p[:24]).hex()})
            buf = buf[used:]
            continue
        if used:
            buf = buf[used:]
            continue
        # incomplete (stop) or garbage (drop one byte and resync) at the head
        if buf[0] == 2 and (len(buf) < 2 or len(buf) < 2 + buf[1] + 3):
            break
        if buf[0] == 3 and (len(buf) < 3 or len(buf) < 3 + ((buf[1] << 8) | buf[2]) + 3):
            break
        buf = buf[1:]
        skipped += 1
    if skipped:
        out.append({"id": "skipped", "len": skipped})
    return out


def _prints(raw: bytes) -> List[str]:
    return [f["text"] for f in _frames(raw) if f.get("text") is not None]


def build_input(tg: dict, entry: Optional[str], term: Optional[bytes],
                raw: Optional[bytes]):
    if raw is not None:
        return raw, {"id": "raw"}
    if term is not None:
        return vc.frame(bytes([vc.COMM_TERMINAL_CMD]) + term), {"id": "term", "term": term.decode("latin-1")}
    for e in tg["entries"]:
        if e["id"] == entry:
            return vc.frame(bytes([vc.COMM_TERMINAL_CMD]) + e["name"].encode()), e
    for c in tg["controls"]:
        if c["id"] == entry:
            if c["input"] is None:
                return b"", c
            return vc.frame(bytes([vc.COMM_TERMINAL_CMD]) + c["input"].encode()), c
    raise KeyError("unknown entry %r" % entry)


def _thread(h: dict) -> bool:
    return h.get("ipsr") == 0


def reach_one(entry: Optional[str] = None, term: Optional[bytes] = None,
              raw: Optional[bytes] = None, slot: int = 0,
              workdir: Optional[str] = None, python: Optional[str] = None,
              liveness: bool = True) -> dict:
    """ONE fresh boot: input first, then liveness, then teardown."""
    tg = targets()
    ports = _ports(slot)
    bridge_port, rx_port, tx_port = ports[0], ports[1], ports[2]
    wd = Path(workdir or ("fuzzreach-%d" % os.getpid())).resolve()
    if wd.exists():
        shutil.rmtree(wd)
    cfg = wd / "cfg"
    shutil.copytree(paths.configs_dir(), cfg,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tmp"))
    (cfg / "fuzz_reach_overlay.yaml").write_text(overlay_yaml(tg))
    hook_log, emu_log, ring = wd / "hooks.jsonl", wd / "emulator.txt", wd / "pcring.json"
    data, meta = build_input(tg, entry, term, raw)
    res: Dict = {"row": tg["row"], "entry": meta.get("id"), "input_hex": data.hex(),
                 "entry_meta": meta, "ports": ports, "slot": slot,
                 "load_at_start": os.getloadavg()[0]}
    pristine = paths.configs_dir() / tg["bin"]
    res["bin_sha256_pristine_before"] = sha256(pristine)
    res["bin_sha256_copy"] = sha256(cfg / tg["bin"])
    t0 = time.time()
    while not _port_free(bridge_port) and time.time() - t0 < 60:
        time.sleep(1)
    if not _port_free(bridge_port):
        res["boot_error"] = "port %d busy" % bridge_port
        return res
    argv = spawn.spawn_argv(python=python, rx_port=rx_port, tx_port=tx_port)
    argv += ["-c", "fuzz_reach_overlay.yaml"]
    extra = {"FUZZ_REACH_LOG": str(hook_log), "FUZZ_REACH_PCRING": str(ring)}
    env = spawn.spawn_env(extra=extra, uart_port=bridge_port)
    proc = subprocess.Popen(argv, cwd=str(cfg), env=env, stdout=open(emu_log, "w"),
                            stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    res["pid"] = proc.pid
    ch: Optional[_Chan] = None
    t_spawn = time.time()
    default_pc = int(tg["default"], 16)
    try:
        ok_b = ok_r = False
        while time.time() - t_spawn < BOOT_TIMEOUT:
            if proc.poll() is not None or _size(emu_log) > FLOOD_BYTES:
                break
            txt = emu_log.read_text(errors="replace")
            ok_b = ok_b or (BIND % bridge_port) in txt
            ok_r = ok_r or READY in txt
            if ok_b and ok_r:
                break
            time.sleep(0.5)
        if not (ok_b and ok_r):
            res["boot_error"] = "bind=%s ready=%s rc=%s" % (ok_b, ok_r, proc.poll())
            return res
        lp = _listener_pids(bridge_port)
        res["listener_pids"] = lp
        if lp != [proc.pid]:
            res["boot_error"] = "tcp/%d listener %r is not our child %d" % (
                bridge_port, lp, proc.pid)
            return res
        ch = _Chan(bridge_port)
        ch.connect(time.time() + 30)
        tick0 = _ring(ring).get("ticks", 0)
        while time.time() - t_spawn < BOOT_TIMEOUT:
            ch.pump(0.5)
            if _ring(ring).get("ticks", 0) - tick0 >= PRE_TICKS or proc.poll() is not None:
                break
        res["boot_s"] = round(time.time() - t_spawn, 1)
        res["boot_rx_bytes"] = ch.total
        hk = _read_jsonl(hook_log)
        hello = [h for h in hk if h.get("k") == "hello"]
        if not hello or hello[0]["pid"] != proc.pid:
            res["boot_error"] = "hook-log identity mismatch %r" % hello[:1]
            return res
        res["hooks_registered"] = sum(1 for h in hk if h.get("k") == "registered")
        res["hooks_expected"] = len(tg["hooks"])
        res["chunk_hook"] = next((h for h in hk if h.get("k") == "chunk_hook"), None)
        boot_hits = [h for h in hk if h.get("k") in HANDLER_KINDS + ("default", "exit", "capped")]
        res["boot_hit_count"] = len(boot_hits)
        res["boot_hits"] = boot_hits[:20]
        res["boot_isr"] = [h for h in hk if h.get("k") == "isr"][:12]
        mark_in = len(hk)
        tick_in = _ring(ring).get("ticks", 0)
        res["ticks_at_input"] = tick_in
        ch.phase(rolling=False)
        # ---- the input, FIRST ----------------------------------------------
        t_in = time.time()
        if data:
            ch.send(data)
        while True:
            ch.pump(0.5)
            el = time.time() - t_in
            if _size(emu_log) > FLOOD_BYTES:
                res["log_flood"] = True
                break
            if proc.poll() is not None or el >= ENTRY_MAX:
                break
            dt = _ring(ring).get("ticks", 0) - tick_in
            quiet = time.time() - max(ch.last_rx, t_in) >= ENTRY_QUIET
            if dt >= SETTLE_TICKS and quiet:
                break
        res["entry_window_s"] = round(time.time() - t_in, 1)
        res["entry_guest_ticks"] = _ring(ring).get("ticks", 0) - tick_in
        hk = _read_jsonl(hook_log)
        mark_live = len(hk)
        res["entry_hits"] = [h for h in hk[mark_in:mark_live]
                             if h.get("k") in HANDLER_KINDS + ("default", "exit", "capped")][:60]
        res["entry_hit_count"] = len(res["entry_hits"])
        res["entry_rx_bytes"] = ch.phase_total
        res["entry_prints"] = [t[:200] for t in _prints(ch.buf)][:40]
        res["entry_frames"] = [f for f in _frames(ch.buf) if f.get("id") != vc.COMM_PRINT][:10]
        ch.phase(rolling=True)
        toks: List[str] = []
        got = None
        if liveness and proc.poll() is None and not res.get("log_flood"):
            t_l = time.time()
            toks.append("rh" + secrets.token_hex(6))
            ch.send(vc.frame(bytes([vc.COMM_TERMINAL_CMD]) + toks[-1].encode()))
            while time.time() - t_l < LIVE_TIMEOUT:
                ch.pump(0.5)
                pr = _prints(ch.buf)
                got = next((t for t in toks for ln in pr
                            if "Invalid command" in ln and t in ln), None)
                if got:
                    break
                if len(toks) == 1 and time.time() - t_l >= LIVE_TIMEOUT / 2:
                    toks.append("rh" + secrets.token_hex(6))
                    ch.send(vc.frame(bytes([vc.COMM_TERMINAL_CMD]) + toks[-1].encode()))
                if _size(emu_log) > FLOOD_BYTES:
                    res["log_flood"] = True
                    break
                if proc.poll() is not None:
                    break
            ch.pump(0.5)
            res["live_wait_s"] = round(time.time() - t_l, 1)
        hk = _read_jsonl(hook_log)
        live = [h for h in hk[mark_live:] if h.get("k") in HANDLER_KINDS + ("default", "capped")]
        res["live_hits"] = live[:20]
        res["live_prints_tail"] = [t[:200] for t in _prints(ch.buf)][-10:]
        res["live_rx_bytes"] = ch.phase_total
        res["live_tokens"] = toks
        if liveness:
            own = [h for h in live if h.get("k") == "default" and h.get("pc") == default_pc
                   and (h.get("argv") or [None])[0] == got] if got else []
            res["live_reply_ok"] = bool(got)
            res["live_probe_used"] = (toks.index(got) + 1) if got else None
            res["live_handler_hit"] = bool(own)
            res["live_thread_mode"] = bool(own) and all(_thread(h) for h in own)
            res["live_after"] = bool(got and own and res["live_thread_mode"])
        res["alive_at_end"] = proc.poll() is None
        res["pcring"] = _ring(ring) or None
        return res
    except Exception as exc:  # noqa: BLE001
        res["harness_error"] = "%s: %s" % (type(exc).__name__, exc)
        return res
    finally:
        if ch is not None:
            ch.close()
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                proc.wait(10)
            except Exception:  # noqa: BLE001
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
        res["rc"] = proc.poll()
        res["bin_sha256_pristine_after"] = sha256(pristine)
        res["bin_sha256_copy_after"] = sha256(cfg / tg["bin"])
        txt = emu_log.read_text(errors="replace") if emu_log.exists() else ""
        res["emu_log_bytes"] = len(txt)
        res["faults"] = len(re.findall(FAULT_RE, txt))
        res["reset_lines"] = len(re.findall(RESET_RE, txt))
        res["fault_lines"] = [ln[:220] for ln in txt.splitlines()
                              if re.search(FAULT_RE + "|" + RESET_RE, ln)][:6]
        m = re.findall(r"BOOT-COUNT: commands_process_packet[^\n]*n=(\d+)", txt)
        res["packets_accepted_guest_count"] = int(m[-1]) if m else 0
        _trim(emu_log, txt)
        shutil.rmtree(cfg / "tmp", ignore_errors=True)
        try:
            (cfg / tg["bin"]).unlink()
        except OSError:
            pass
        res["load_at_end"] = os.getloadavg()[0]
        res["wall_s"] = round(time.time() - t_spawn, 1)
        _score(tg, res)


def _trim(p: Path, txt: str) -> None:
    if len(txt) < (2 << 20):
        return
    lines = txt.splitlines()
    keep = lines[:3000] + ["... [%d lines trimmed by fuzz_entry; %d total] ..."
                           % (len(lines) - 3200, len(lines))] + lines[-200:]
    p.write_text("\n".join(keep) + "\n")


def _a0(h: dict):
    return (h.get("argv") or [None])[0]


def _hit_for(hits: List[dict], e: dict, tg: dict) -> bool:
    """REACHED: the FIRST handler-class hook (any entry's handler, or the
    default) that fires with argv[0] == e's name is e's OWN handler, it is in
    thread mode, and the default never fired with that name. For the empty
    case (`decision`) the own-handler hit must also carry r0 == 0."""
    name, pc = e["name"], int(e["handler"], 16)
    handler_pcs = {int(x["handler"], 16) for x in tg["entries"]}
    default_pc = int(tg["default"], 16)
    if any(h.get("pc") == default_pc and h.get("k") == "default" and _a0(h) == name
           for h in hits):
        return False
    for h in hits:
        if _a0(h) != name:
            continue
        k = h.get("k")
        if k == "decision" and h.get("r0") != 0:
            continue                  # a compare that did NOT match: not a dispatch
        if k in HANDLER_KINDS and h.get("pc") in handler_pcs:
            return h.get("pc") == pc and _thread(h)
    return False


def _spin(res: dict) -> dict:
    pr = res.get("pcring") or {}
    ring = pr.get("ring") or []
    tail = ring[-16:]
    pcs = [r[0] for r in tail if r and r[0] is not None]
    ipsrs = sorted({r[1] for r in tail if r and r[1] is not None})
    from collections import Counter
    c = Counter(pcs)
    return {"samples": len(ring), "tail_distinct_pcs": len(c),
            "tail_span": (max(pcs) - min(pcs)) if pcs else None,
            "tail_top": [("0x%x" % a, n) for a, n in c.most_common(4)],
            "tail_ipsr": ipsrs, "ticks": pr.get("ticks"),
            "async_samples": pr.get("async_samples"),
            "exc_by_ipsr": pr.get("exc_by_ipsr"),
            "log_dropped": dict(list((pr.get("log_dropped") or {}).items())[:6])}


def _score(tg: dict, res: dict) -> None:
    e = res.get("entry_meta") or {}
    hits = res.get("entry_hits") or []
    res["handlers_fired"] = sorted({(h.get("k"), "0x%x" % h["pc"], _a0(h), h.get("r0")
                                     if h.get("k") == "decision" else None, h.get("ipsr"))
                                    for h in hits if h.get("k") in HANDLER_KINDS + ("default",)
                                    and h.get("pc") is not None}, key=str)
    res["spin"] = _spin(res)
    isr = res.get("boot_isr") or []
    res["isr_control"] = {"records": len(isr),
                          "thread_mode_true": sum(1 for h in isr if _thread(h)),
                          "ipsrs": sorted({h.get("ipsr") for h in isr}, key=str)}
    exit_pcs = {int(x, 16) for x in tg.get("function_exit", [])}
    if e.get("id") in ("raw", "term"):
        res["handler_hit"] = any(h.get("k") in HANDLER_KINDS for h in hits)
        return
    if "handler" not in e:            # a control
        name = e.get("input")
        res["control_scores"] = {
            "declared_entries_scored_reached": [x["id"] for x in tg["entries"]
                                                if _hit_for(hits, x, tg)],
            "default_hit_with_this_input": any(h.get("k") == "default" and _a0(h) == (name or "").lower()
                                               for h in hits) if name else False,
            # the WEAK rule: "any hit on a declared handler's label with
            # argv[0] == the input" at the SHARED function exit, which an empty
            # case's equal edge also targets.
            "weak_rule_shared_exit_hit": bool(name) and any(
                h.get("k") == "exit" and h.get("pc") in exit_pcs and _a0(h) == name.lower()
                for h in hits)}
        return
    res["handler_hit"] = _hit_for(hits, e, tg)
    nxt = e.get("next_entry")
    if nxt:
        ne = next(x for x in tg["entries"] if x["id"] == nxt)
        res["control_next_identity"] = {"next": nxt, "next_handler": ne["handler"],
                                        "scored_true": _hit_for(hits, ne, tg)}


# ---- sweep -----------------------------------------------------------------
def _safe(e: str) -> str:
    # macOS file systems are case-INSENSITIVE: name files by the hex of the id.
    return e.encode().hex()


def _child(entry: str, slot: int, outdir: Path, python: Optional[str]) -> dict:
    out = outdir / ("%s.json" % _safe(entry))
    wd = outdir / ("run-%s" % _safe(entry))
    argv = [python or sys.executable, "-m", PKG + ".fuzz_entry", "--entry", entry,
            "--slot", str(slot), "--out", str(out), "--workdir", str(wd)]
    t0 = time.time()
    p = subprocess.Popen(argv, stdout=open(outdir / ("%s.child.txt" % _safe(entry)), "w"),
                         stderr=subprocess.STDOUT)
    try:
        p.wait(BOOT_TIMEOUT + ENTRY_MAX + LIVE_TIMEOUT + 120)
    except subprocess.TimeoutExpired:
        p.kill()
    try:
        return json.loads(out.read_text())
    except (OSError, ValueError):
        return {"entry": entry, "harness_error": "child produced no result (rc=%s, %.0fs)"
                % (p.returncode, time.time() - t0)}


def sweep(outdir: Path, workers: int, python: Optional[str],
          only: Optional[List[str]] = None, controls: bool = True) -> dict:
    tg = targets()
    ids = [e["id"] for e in tg["entries"]]
    if controls:
        ids += [c["id"] for c in tg["controls"]]
    if only:
        ids = [i for i in ids if i in only]
    outdir.mkdir(parents=True, exist_ok=True)
    _ports(workers - 1)
    free = list(range(workers))
    lk = threading.Lock()

    def job(i):
        with lk:
            s = free.pop(0)
        try:
            return _child(i, s, outdir, python)
        finally:
            with lk:
                free.append(s)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(job, ids))
    return {r.get("entry"): r for r in results}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--entry")
    ap.add_argument("--term")
    ap.add_argument("--raw-hex")
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--out")
    ap.add_argument("--workdir")
    ap.add_argument("--no-liveness", action="store_true")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--no-controls", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--outdir")
    a = ap.parse_args(argv)
    if a.sweep:
        r = sweep(Path(a.outdir), a.workers, None, a.only, not a.no_controls)
        Path(a.outdir, "sweep.json").write_text(json.dumps(r, indent=1, default=str))
        print(json.dumps({k: {"hit": v.get("handler_hit"), "live": v.get("live_after"),
                              "err": v.get("boot_error") or v.get("harness_error")}
                          for k, v in r.items()}, indent=1))
        return 0
    raw = bytes.fromhex(a.raw_hex) if a.raw_hex else None
    term = a.term.encode() if a.term is not None else None
    r = reach_one(entry=a.entry, term=term, raw=raw, slot=a.slot, workdir=a.workdir,
                  liveness=not a.no_liveness)
    js = json.dumps(r, indent=1, default=str)
    if a.out:
        Path(a.out).write_text(js)
    else:
        print(js)
    sys.stdout.flush()
    os._exit(0)          # forced exit: no socket or thread survives this input


if __name__ == "__main__":
    main()
