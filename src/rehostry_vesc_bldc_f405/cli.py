# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""`rehostry-vesc-bldc-f405` CLI: boot the re-host standalone.

`run` boots the VESC firmware under HALucinator (unicorn) and streams the
emulator log to stdout for `--seconds`, then reaps the whole process tree. The
host seam -- USART3, carrying VESC's own COMM packet protocol -- is served by the
USART peripheral model itself and is always listening on tcp/21201, so a real
VESC client (or the web panel, `rehostry-vesc-bldc-f405-panel`) can drive the
firmware's own protocol engine with nothing extra to enable.

Reaching the COMM stack takes a couple of minutes of wall clock; watch for
`USART3: enabled by the firmware`, which is the firmware's own driver arriving
at the port.

`attack` runs the fleet-standard attack (`python -m rehostry_vesc_bldc_f405.attack`).
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

from . import paths, spawn


def _descendants(pid: int) -> list[int]:
    out: list[int] = []
    try:
        kids = subprocess.run(["pgrep", "-P", str(pid)],
                              capture_output=True, text=True).stdout.split()
    except (OSError, ValueError):
        kids = []
    for k in kids:
        out.extend(_descendants(int(k)))
        out.append(int(k))
    return out


def _kill_tree(proc: subprocess.Popen) -> None:
    # Kill ONLY the PIDs we started (via the Popen handle). NEVER `pkill -f
    # halucinator` -- a global pattern kill takes out other sessions' emulators
    # and the victim sees rc=-15 with no fault in the log (playbook trap 10).
    for sig in (signal.SIGTERM, signal.SIGKILL):
        # Signal the whole SESSION we created (the spawn passes setsid /
        # start_new_session, so the child IS the group leader and the group id
        # is proc.pid). The halucinator emulator is a GRANDCHILD: killing only
        # the direct child leaves it alive, reparented to init, still holding
        # the guest's port and burning a core.
        #
        # proc.pid is used directly rather than os.getpgid(proc.pid): getpgid
        # raises ProcessLookupError as soon as the direct child is reaped, and
        # that is exactly the case where the grandchild is still running and
        # most needs the signal. The descendant walk below races the same
        # reparenting -- once the grandchild's parent is gone, `pgrep -P` no
        # longer lists it under our pid -- so it is kept only as a fallback for
        # a child that never got its own session.
        # Still only PIDs WE started. NEVER a pattern kill.
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        pids = _descendants(proc.pid) + [proc.pid]
        for p in pids:
            try:
                os.kill(p, sig)
            except (ProcessLookupError, OSError):
                pass
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            continue


def cmd_run(args: argparse.Namespace) -> int:
    if not paths.firmware_present():
        print(f"firmware not found at {paths.firmware_bin()}", file=sys.stderr)
        print("  (regenerate it with tools/extract_firmware.py -- see PROVENANCE.md)",
              file=sys.stderr)
        return 1

    argv = spawn.spawn_argv(emulator=args.emulator)
    env = spawn.spawn_env(uart_port=args.port)

    print(f"[rehostry-vesc-bldc-f405] booting: {' '.join(argv)}")
    print(f"[rehostry-vesc-bldc-f405] cwd={spawn.spawn_cwd()}  (configs from the installed package)")
    print(f"[rehostry-vesc-bldc-f405] USART3 <-> VESC COMM protocol on "
          f"tcp/{args.port} (drive it with `rehostry-vesc-bldc-f405-panel`)")

    proc = subprocess.Popen(argv, cwd=spawn.spawn_cwd(), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, preexec_fn=os.setsid)
    deadline = time.monotonic() + args.seconds
    try:
        assert proc.stdout is not None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                for line in proc.stdout:      # drain whatever is left
                    sys.stdout.write(line)
                print("[rehostry-vesc-bldc-f405] HALucinator exited early.", file=sys.stderr)
                return proc.returncode or 1
            line = proc.stdout.readline()
            if line:
                sys.stdout.write(line)
            else:
                time.sleep(0.05)
        print(f"[rehostry-vesc-bldc-f405] ran for {args.seconds:.0f}s; tearing down.")
        return 0
    finally:
        _kill_tree(proc)


def cmd_attack(args: argparse.Namespace) -> int:
    from . import attack
    return attack.main()


def cmd_panel(args: argparse.Namespace) -> int:
    from . import vesc_panel
    return vesc_panel.main(["--port", str(args.http_port)])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="rehostry-vesc-bldc-f405",
        description="VESC (vedderb/bldc 7.01) on a rehosted STM32F405 / ChibiOS "
                    "motor controller, with its COMM protocol on tcp/21201.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="boot the firmware and stream its log")
    r.add_argument("--seconds", type=float, default=180.0,
                   help="how long to run (default 180; the COMM stack comes up "
                        "after roughly 60-90s of wall clock)")
    r.add_argument("--emulator", default="unicorn")
    r.add_argument("--bridge", action="store_true",
                   help="accepted for fleet compatibility; the USART3 seam is "
                        "always served")
    r.add_argument("--port", type=int, default=spawn.BRIDGE_PORT,
                   help="USART3 bridge TCP port (default %d)" % spawn.BRIDGE_PORT)
    r.set_defaults(func=cmd_run)

    a = sub.add_parser("attack", help="run the unauthenticated COMM_SET_MCCONF "
                                      "attack (prints one RESULT-tagged JSON verdict)")
    a.set_defaults(func=cmd_attack)

    pan = sub.add_parser("panel", help="serve the live web panel")
    pan.add_argument("--http-port", type=int, default=9011)
    pan.set_defaults(func=cmd_panel)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
