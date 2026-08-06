# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The single source of truth for *how to run this device* under HALucinator.

The CLI (`rehostry-vesc-bldc-f405 run`), the attack and the web panel all build
their invocation from here, so there is exactly one spawn recipe: HALucinator on
the **unicorn** backend with this device's config + symbol table.

HALucinator is a *runtime* dependency reached as a separate process; it is not
imported here. It must be importable by the spawned interpreter, which is the
*installed* ``halucinator`` in the running interpreter's environment
(``sys.executable``, overridable via ``HAL_PY``). We deliberately do NOT splice
any source tree onto PYTHONPATH: a polluted ``HALUCINATOR_SRC``/``PYTHONPATH``
must never resurrect an out-of-tree core, so both are stripped from the child
env (see :func:`spawn_env`).
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional

from . import paths

# The host-facing seam: USART3, where ChibiOS' SD3 serial driver runs VESC's own
# COMM packet protocol (hw_100_250.h sets HW_UART_DEV = SD3, and appconf's
# default app_to_use is APP_UART). Point VESC Tool -- or the attack -- at this
# TCP port exactly as you would at the ESC's UART header. The protocol carries
# no authentication whatsoever, which is what the attack exploits.
BRIDGE_PORT = int(os.environ.get("VESC_UART_PORT", "21201"))
# Symbolic seam id, for the orchestrator binding.
UART_SEAM = "STM32F405 USART3 DR (0x40004804) <-> VESC COMM packet protocol"

# ZMQ peripheral-bus ports. HALucinator's peripheral_server.start() BINDS
# machine-global endpoints and its own defaults are 5555/5556, so two devices
# left on the default silently share one bus and inject each other's messages
# into the wrong guest. This device owns 6102/6103.
DEFAULT_RX_PORT = int(os.environ.get("VESC_RX_PORT", "6102"))
DEFAULT_TX_PORT = int(os.environ.get("VESC_TX_PORT", "6103"))


def spawn_argv(python: Optional[str] = None, emulator: str = "unicorn",
               bridge: bool = True,
               rx_port: Optional[int] = None,
               tx_port: Optional[int] = None) -> List[str]:
    """argv for ``python -m halucinator.main`` with this device's configs.

    Config basenames are resolved against :func:`spawn_cwd`. ``bridge`` is
    accepted for fleet-interface compatibility and has no effect: this device's
    host seam is the USART3 model itself, which always listens (there is no
    separate overlay config to layer on).
    """
    argv = [python or os.environ.get("HAL_PY") or sys.executable,
            "-m", "halucinator.main"]
    for f in paths.CONFIG_FILES:
        argv += ["-c", f]
    argv += ["--emulator", emulator]
    argv += ["--rx_port", str(DEFAULT_RX_PORT if rx_port is None else rx_port)]
    argv += ["--tx_port", str(DEFAULT_TX_PORT if tx_port is None else tx_port)]
    return argv


def spawn_cwd() -> str:
    """Run from the packaged configs dir so config basenames, the relative
    ``file: vesc.bin`` in the memory map, and the packaged ``logging.cfg``
    (which is what makes the backend's own diagnostics visible) resolve."""
    return str(paths.configs_dir())


def spawn_env(halucinator_src: Optional[str] = None,
              extra: Optional[dict] = None,
              uart_port: Optional[int] = None) -> dict:
    """Environment for the spawned HALucinator process.

    The child runs the *installed* ``halucinator@dev``, so ``HALUCINATOR_SRC``
    and ``PYTHONPATH`` are stripped from the inherited environment: a polluted
    value must not resurrect an out-of-tree core. The ``halucinator_src``
    argument is accepted for API compatibility and ignored.
    """
    env = dict(os.environ)
    env.pop("HALUCINATOR_SRC", None)
    env.pop("PYTHONPATH", None)
    env["PYTHONUNBUFFERED"] = "1"

    # The STM32F405 is a Cortex-M4F and this firmware uses the FPU from its very
    # first instructions (ChibiOS' crt0 enables CP10/CP11 in CPACR and then
    # writes FPSCR). unicorn's default M-profile model is an M3, which has no
    # VFP, so that instruction is UNDEFINED and the boot dies six instructions
    # in -- which reads like a decode failure and is not one (playbook §2.38,
    # §2.120: the YAML `cpu_model:` key does NOT select this).
    env.setdefault("HAL_CORTEXM_CPU_MODEL", "UC_CPU_ARM_CORTEX_M4")

    # A single breakpoint otherwise installs ONE global per-instruction Python
    # hook, which costs ~3 orders of magnitude on a 460 KiB image. HAL_FAST_BP
    # installs one range-bounded hook per breakpoint address instead
    # (playbook §2.51).
    env.setdefault("HAL_FAST_BP", "1")

    # Bound each emu_start chunk. On cortex-m the core's irq_chunk defaults to
    # 0 = unbounded, so a queued interrupt is only delivered when emulation
    # stops for some other reason (playbook §2.50/§2.99).
    env.setdefault("HAL_IRQ_CHUNK", "200000")

    env["VESC_UART_PORT"] = str(BRIDGE_PORT if uart_port is None else uart_port)
    if extra:
        env.update(extra)
    return env
