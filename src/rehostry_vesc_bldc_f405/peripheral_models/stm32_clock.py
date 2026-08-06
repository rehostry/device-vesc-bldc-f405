# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The 0x40023000 page: the CRC unit, the clock tree (RCC), and the flash
interface. Three peripherals share one 4 KiB page, which is the granularity
HALucinator maps at (playbook §2.61), so one model dispatches by offset.

Why each of them has to be real, rather than left to the catch-all:

* **RCC.** ChibiOS' ``stm32_clock_init()`` drives RCC as raw registers and then
  *waits for what it wrote to read back*. The catch-all's busy-wait breaker
  answers a spun read with all-ones, and the firmware is looking for one specific
  value, so it can never be satisfied (playbook §2.40, and §2.100 for the
  write-then-read-back-until-equal shape). Ready bits are mirrored from their own
  enable bits so both "spin until ready" and "spin until off" work (§2.72).
  ``RCC_CR`` starts at its silicon reset value ``0x00000083`` -- HSI running --
  because firmware reads clock registers before writing them (§2.84).

* **The flash interface.** ``FLASH_ACR`` must read back the latency ChibiOS
  wrote; ``FLASH_SR`` must report BSY clear (a status register that echoed the
  firmware's clear-mask made ST's wait-idle loop immortal, §2.67); and
  ``FLASH_CR``'s sector erase has to *physically blank* the sector, because
  VESC's ``flash_helper.c`` reads erased flash back and checks it for ``0xFF``.
  Programming is left to the firmware's own stores -- the flash region is mapped
  writable for exactly that, which is what the hardware does too.

* **The CRC unit.** ``util/crc.c``'s ``crc32()`` is the *hardware* CRC
  (``CRC->DR`` at 0x40023000). A plausible-but-different CRC fails statistically
  rather than obviously (playbook §2.82), so this is the real STM32 unit:
  polynomial ``0x04C11DB7``, MSB-first, init ``0xFFFFFFFF``, unreflected, fed a
  32-bit word per write, and reset by ``CR`` bit 0.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from halucinator import hal_log
from halucinator.peripheral_models.auto_model import AutoPeripheral

log = hal_log.getHalLogger()

PAGE_BASE = 0x40023000
CRC_OFF = 0x000
RCC_OFF = 0x800
FLASH_OFF = 0xC00

# --- CRC (0x40023000) -------------------------------------------------------
CRC_DR = 0x00
CRC_IDR = 0x04
CRC_CR = 0x08

# --- RCC (0x40023800) -------------------------------------------------------
RCC_CR = 0x00
RCC_CFGR = 0x08
RCC_BDCR = 0x70
RCC_CSR = 0x74

# Reset values the silicon provides before the firmware writes anything.
# RCC_CR = 0x83: HSION + HSIRDY set (the 16 MHz internal oscillator runs from
# power-on and is the chip's fallback), HSITRIM = 16.
RESET_VALUES = {RCC_CR: 0x00000083}

# "enable bit -> ready bit", per register. Mirroring the ready bit from its own
# enable bit makes both directions of the wait work, and is simply what the
# silicon does (playbook §2.72).
READY_BITS = {
    RCC_CR: {0: 1, 16: 17, 24: 25, 26: 27, 28: 29},   # HSI, HSE, PLL, PLLI2S, PLLSAI
    RCC_BDCR: {0: 1},                                  # LSE
    RCC_CSR: {0: 1},                                   # LSI
}

# --- embedded flash interface (0x40023c00) ----------------------------------
FLASH_ACR = 0x00
FLASH_KEYR = 0x04
FLASH_OPTKEYR = 0x08
FLASH_SR = 0x0C
FLASH_CR = 0x10
FLASH_OPTCR = 0x14

KEY1 = 0x45670123
KEY2 = 0xCDEF89AB

CR_PG = 1 << 0
CR_SER = 1 << 1
CR_SNB_SHIFT = 3
CR_SNB_MASK = 0xF << CR_SNB_SHIFT
CR_STRT = 1 << 16
CR_LOCK = 1 << 31

SR_EOP = 1 << 0

# STM32F405RG, 1 MiB: 4 x 16K, 1 x 64K, 7 x 128K.
SECTORS: List[Tuple[int, int, int]] = (
    [(i, 0x08000000 + i * 0x4000, 0x4000) for i in range(4)]
    + [(4, 0x08010000, 0x10000)]
    + [(5 + i, 0x08020000 + i * 0x20000, 0x20000) for i in range(7)]
)

# VESC's own layout (flash_helper.c:54-75): sector 0 holds the vector table and
# the start of the application, sectors 2-3 are the emulated EEPROM the motor
# and app configurations live in, and the application runs on from sector 3.
# Erasing sector 0 or 1 would blank the running image, which is not something
# this firmware ever asks for -- so it is refused loudly rather than performed,
# because a silently self-erasing rehost is impossible to debug.
PROTECTED_SECTORS = (0, 1)

def _build_crc32_table() -> list:
    """The MSB-first byte table for polynomial 0x04C11DB7 (the STM32 unit's)."""
    tab = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 \
                else (c << 1) & 0xFFFFFFFF
        tab.append(c)
    return tab


_CRC32_TAB = _build_crc32_table()

_BACKEND: Any = None


def set_backend(backend: Any) -> None:
    """Hand the model the live backend (a bp_handler's register_handler is the
    only place a device is given one). Needed so an erase can blank real guest
    memory."""
    global _BACKEND
    _BACKEND = backend


class Stm32ClockBlock(AutoPeripheral):
    """CRC at +0x000, RCC at +0x800, embedded-flash interface at +0xc00."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self._rcc: Dict[int, int] = {}
        self._flash: Dict[int, int] = {FLASH_CR: CR_LOCK}
        self._key_state = 0
        self._crc = 0xFFFFFFFF
        self._crc_idr = 0
        self.erases = 0
        self.refused = 0
        self._switch_logged = False

    # -- CRC ---------------------------------------------------------------
    @staticmethod
    def _crc32_word(crc: int, word: int) -> int:
        """One 32-bit word through the STM32's CRC unit: poly 0x04C11DB7,
        MSB-first, no reflection, no final XOR.

        Table-driven, and that is not premature optimisation: VESC's
        ``flash_helper_verify_flash_memory()`` feeds **122 878 words** through
        this register on the first boot (the whole vector table plus the whole
        application), and a 32-iteration Python bit loop per word puts four
        million interpreter steps between reset and the COMM stack.
        """
        crc = (crc ^ (word & 0xFFFFFFFF)) & 0xFFFFFFFF
        tab = _CRC32_TAB
        for _ in range(4):
            crc = ((crc << 8) & 0xFFFFFFFF) ^ tab[(crc >> 24) & 0xFF]
        return crc

    # -- flash -------------------------------------------------------------
    def _flash_write(self, reg: int, value: int) -> None:
        if reg == FLASH_KEYR:
            if self._key_state == 0 and value == KEY1:
                self._key_state = 1
            elif self._key_state == 1 and value == KEY2:
                self._key_state = 0
                self._flash[FLASH_CR] = self._flash.get(FLASH_CR, 0) & ~CR_LOCK
                log.info("stm32_flash: unlocked")
            else:
                self._key_state = 0
            return
        if reg == FLASH_SR:
            # rc_w1: the firmware clears sticky flags by writing 1 to them.
            # Never echo the write back -- a status register that stores its own
            # clear-mask makes a wait-idle loop immortal (playbook §2.67).
            self._flash[FLASH_SR] = self._flash.get(FLASH_SR, 0) & ~value
            return
        if reg == FLASH_CR:
            self._flash[FLASH_CR] = value & 0xFFFFFFFF
            if value & CR_STRT and value & CR_SER:
                self._erase(( value & CR_SNB_MASK) >> CR_SNB_SHIFT)
                # STRT is cleared by the hardware when the operation ends.
                self._flash[FLASH_CR] = value & ~CR_STRT & 0xFFFFFFFF
                self._flash[FLASH_SR] = self._flash.get(FLASH_SR, 0) | SR_EOP
            return
        self._flash[reg] = value & 0xFFFFFFFF

    def _erase(self, snb: int) -> None:
        entry = next((s for s in SECTORS if s[0] == snb), None)
        if entry is None:
            log.warning("stm32_flash: erase of unknown sector %d ignored", snb)
            return
        _, base, size = entry
        if snb in PROTECTED_SECTORS:
            self.refused += 1
            log.error("stm32_flash: REFUSED an erase of sector %d "
                      "(0x%08x+0x%x) -- that is the running image", snb,
                      base, size)
            return
        if _BACKEND is None:
            log.error("stm32_flash: erase of sector %d requested but no backend "
                      "is attached; the sector still reads its old contents and "
                      "the firmware's read-back verify will fail", snb)
            return
        try:
            _BACKEND.write_memory(base, 1, b"\xff" * size, size, raw=True)
        except Exception as exc:  # noqa: BLE001
            log.error("stm32_flash: erase of sector %d failed: %s", snb, exc)
            return
        self.erases += 1
        log.info("stm32_flash: erased sector %d (0x%08x + 0x%x) -- blanked to "
                 "0xFF in guest memory", snb, base, size)

    # -- MMIO --------------------------------------------------------------
    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        value &= 0xFFFFFFFF
        if offset >= FLASH_OFF:
            self._flash_write(offset - FLASH_OFF, value)
            return True
        if offset >= RCC_OFF:
            reg = offset - RCC_OFF
            self._rcc[reg] = value
            if reg == RCC_CFGR and not self._switch_logged:
                self._switch_logged = True
                log.info("stm32_clock: system clock switch requested "
                         "(RCC_CFGR=0x%08x)", value)
            return True
        reg = offset - CRC_OFF
        if reg == CRC_DR:
            self._crc = self._crc32_word(self._crc, value)
        elif reg == CRC_IDR:
            self._crc_idr = value & 0xFF
        elif reg == CRC_CR and value & 1:
            self._crc = 0xFFFFFFFF
        return True

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        if offset >= FLASH_OFF:
            reg = offset - FLASH_OFF
            if reg == FLASH_SR:
                # BSY is never set: every operation this model performs is
                # instantaneous, so it is already finished by the time the
                # firmware can look.
                return self._flash.get(FLASH_SR, 0)
            return self._flash.get(reg, 0)
        if offset >= RCC_OFF:
            reg = offset - RCC_OFF
            val = self._rcc.get(reg, RESET_VALUES.get(reg, 0))
            ready = READY_BITS.get(reg)
            if ready:
                for enable, ready_bit in ready.items():
                    if val & (1 << enable):
                        val |= 1 << ready_bit
            elif reg == RCC_CFGR:
                # SWS (bits 3:2) reports the clock actually in use; mirror SW
                # (bits 1:0), i.e. the switch has already completed.
                val = (val & ~0xC) | ((val & 0x3) << 2)
            return val
        reg = offset - CRC_OFF
        if reg == CRC_DR:
            return self._crc
        if reg == CRC_IDR:
            return self._crc_idr
        return 0
