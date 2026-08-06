# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""rehostry-vesc-bldc-f405 -- a VESC 100/250 brushless motor controller
(vedderb/bldc 7.01, ChibiOS on an STM32F405RG) as a standalone, pip-installable
HALucinator device, with its real COMM packet protocol on a TCP socket.

The device is self-contained: its configs and symbol table ship as package data
and are referenced by the installed module path (`rehostry_vesc_bldc_f405.*`),
with no `project.` symlink and no `HALUCINATOR_SRC` source-tree injection. The
firmware image is NOT shipped -- build it per FIRMWARE.md and regenerate it with
tools/extract_firmware.py.

This package spawns HALucinator as a CHILD process (see spawn.py) and never
imports `halucinator` itself, so it needs no sys.path guard; spawn_env() strips
HALUCINATOR_SRC/PYTHONPATH from the child environment instead.
"""
from . import paths, spawn
from .binding import VESC_BLDC_F405

__version__ = "0.0.1"

__all__ = ["paths", "spawn", "VESC_BLDC_F405", "__version__"]
