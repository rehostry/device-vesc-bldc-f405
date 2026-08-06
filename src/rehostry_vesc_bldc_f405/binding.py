# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Orchestrator binding: expose this device to rehostry/orchestrator.

This is the adapter a co-simulation scenario imports. It depends on the
orchestrator package (`rehostry`), so it's an OPTIONAL extra -- the device runs
fine standalone (via the CLI) without it. The import is lazy so merely importing
`rehostry_vesc_bldc_f405` never requires the orchestrator to be installed.

"""
from __future__ import annotations

from typing import Optional

from . import paths, spawn

# Static description of the device (also what a future halucinator entry-point
# plugin hook would advertise).
VESC_BLDC_F405 = {
    "name": "vesc-bldc-f405",
    "uart_seam": spawn.UART_SEAM,
    "config_files": paths.CONFIG_FILES,
    "bridge_config": paths.BRIDGE_CONFIG,
    "bridge_port": spawn.BRIDGE_PORT,        # host TCP server, if any
    "telemetry": "the VESC COMM packet protocol over USART3 -- VESC Tool's own\n"
                 "binary protocol, unauthenticated in both directions",
}


def make_device(name: str = "vesc-bldc-f405",
                halucinator_src: Optional[str] = None,
                bridge: bool = True,
                python: Optional[str] = None, log_path: Optional[str] = None):
    """Build a rehostry.Device for this device, wired with the spawn recipe.

    Requires the `rehostry` orchestrator package
    (install `rehostry-vesc-bldc-f405[orchestrator]`).
    """
    try:
        from rehostry import Device, SpawnSpec
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "make_device needs the orchestrator: pip install 'rehostry-vesc-bldc-f405[orchestrator]'"
        ) from e

    spec = SpawnSpec(
        argv=spawn.spawn_argv(python=python, bridge=bridge),
        cwd=spawn.spawn_cwd(),
        env=spawn.spawn_env(halucinator_src=halucinator_src),
        log_path=log_path,
        readiness_marker=None,
        join_delay=6.0,
    )
    return Device(name, None, uart_id=spawn.BRIDGE_PORT, spawn=spec)
