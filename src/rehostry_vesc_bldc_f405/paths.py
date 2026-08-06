# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Resource paths for the packaged HALucinator configs and the flash image.

Everything the device needs to run ships inside the installed package. These
helpers resolve those paths from the *installed* location via
``importlib.resources``, so the device runs from anywhere -- no cwd assumptions,
no `project.` PYTHONPATH hack.

The firmware is NOT committed (.gitignore excludes *.bin/*.elf): build it per
FIRMWARE.md and regenerate it into configs/ with tools/extract_firmware.py.
"""
from __future__ import annotations

import importlib.resources as _ir
from pathlib import Path

PACKAGE = "rehostry_vesc_bldc_f405"

# The config files handed to `halucinator.main -c ...`, in load order: the
# machine/memory/peripheral description, then the symbol table
# tools/extract_firmware.py derived from the build ELF.
CONFIG_FILES = [
    "vesc_config.yaml",
    "vesc_addrs.yaml",
]

# There is no separate host-bridge overlay: this device's seam is the USART3
# peripheral model itself (peripheral_models/stm32_usart.py), which binds its
# TCP listener whenever the device runs.
BRIDGE_CONFIG = None  # this device has no separate bridge overlay: the USART3
                      # peripheral model is the host seam and always listens.

# The flash image. NOT committed -- the VESC firmware is GPL-3.0 and this
# package is AGPL-3.0-or-later, and the fleet never commits firmware bytes.
# Build it (FIRMWARE.md) and regenerate with tools/extract_firmware.py.
FIRMWARE_BIN = "vesc.bin"
FIRMWARE_ELF = "vesc.elf"   # not shipped; the build ELF lives in your build dir


def configs_dir() -> Path:
    """Absolute path to the packaged configs/ dir (also where firmware lives)."""
    return Path(str(_ir.files(PACKAGE))) / "configs"


def config_paths(bridge: bool = False) -> list[Path]:
    return [configs_dir() / f for f in CONFIG_FILES]


def firmware_bin() -> Path:
    return configs_dir() / FIRMWARE_BIN


def firmware_elf() -> Path:
    return configs_dir() / FIRMWARE_ELF


def firmware_present() -> bool:
    return firmware_bin().is_file()
