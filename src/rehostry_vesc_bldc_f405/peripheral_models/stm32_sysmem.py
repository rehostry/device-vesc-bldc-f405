# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The STM32F4 system-memory page that holds the die's unique ID.

Playbook §2.80: an STM32's 96-bit unique device ID and its flash-size register
live in the OTP/system area, which is neither flash nor SRAM and which nothing
thinks to put in ``peripherals:``. VESC reads it directly --
``conf_general.h:145`` defines ``STM32_UUID_8 ((uint8_t*)0x1FFF7A10)`` -- and
``COMM_FW_VERSION`` puts those twelve bytes straight into its reply. Left
unmapped it is a ``UC_ERR_READ_UNMAPPED`` and a dead run.

There is no honest way to recover a real die's serial number from a firmware
image, so this device answers a **fixed, documented, obviously synthetic** one:
the ASCII ``REHOSTRYVESC``. Zeroes were rejected deliberately -- they read like a
failed access rather than a chosen constant, and they would make the
``COMM_FW_VERSION`` prediction in PROVENANCE.md weaker (twelve zero bytes are
what a broken model produces by accident; twelve specific ASCII bytes are not).

The page also carries ``FLASH_SIZE`` at ``0x1FFF7A22`` (KiB, u16) -- 1024 for the
STM32F405RG this hardware target is built for.
"""
from __future__ import annotations

from typing import Any, Dict

from halucinator import hal_log
from halucinator.peripheral_models.auto_model import AutoPeripheral

log = hal_log.getHalLogger()

# Peripheral regions must be 4 KiB-aligned multiples of 4 KiB (playbook §2.61),
# so the model covers 0x1FFF7000-0x1FFF8000 and dispatches by offset.
PAGE_BASE = 0x1FFF7000
UID_ADDR = 0x1FFF7A10
UID_OFF = UID_ADDR - PAGE_BASE          # 0xA10
FLASH_SIZE_ADDR = 0x1FFF7A22
FLASH_SIZE_OFF = FLASH_SIZE_ADDR - PAGE_BASE

# The synthetic serial. Twelve bytes, printable, and impossible to arrive at by
# accident -- which is exactly what makes it usable as evidence that the
# firmware read THIS region when those bytes turn up in its COMM_FW_VERSION
# reply. tests/test_structure.py pins it against PROVENANCE.md's prediction.
UID_BYTES = b"REHOSTRYVESC"
FLASH_SIZE_KB = 1024                    # STM32F405RG


class Stm32SystemMemory(AutoPeripheral):
    """0x1FFF7000: the die UID + flash-size registers, read-only."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self._reported = False

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        if UID_OFF <= offset < UID_OFF + len(UID_BYTES):
            i = offset - UID_OFF
            chunk = (UID_BYTES + b"\x00" * 4)[i:i + size]
            if not self._reported:
                self._reported = True
                log.info("stm32_sysmem: firmware read the die UID at 0x%08x "
                         "(pc=0x%08x); answering the synthetic serial %r",
                         self.address + offset, pc, UID_BYTES.decode())
            return int.from_bytes(chunk, "little")
        if offset == FLASH_SIZE_OFF:
            return FLASH_SIZE_KB & ((1 << (8 * size)) - 1)
        # Everything else in the system-memory page is the factory ROM
        # bootloader, which this image never enters. Reads of it are not a
        # busy-wait, so do NOT let the breaker escalate them.
        return 0
