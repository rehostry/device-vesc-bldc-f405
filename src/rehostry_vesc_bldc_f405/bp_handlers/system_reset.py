# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Perform the warm reset that ``NVIC_SystemReset()`` asks for.

unicorn implements no ``SCB->AIRCR.SYSRESETREQ``, so CMSIS'
``NVIC_SystemReset()`` — write AIRCR, ``dsb``, ``for(;;);`` — becomes a
permanent hang that from outside is indistinguishable from any other
(playbook §2.54).

VESC reaches one on its **first** boot, and it is not an error path:
``flash_helper_verify_flash_memory()`` finds the app-CRC slot erased, programs
the CRC of the image into it, and then reboots so the value is used. Without
this handler the rehost sits on `b .` at that site forever, having said nothing
at all — measured before it existed: 3 000 000 PC samples at one address, dump
after dump, and no further boot progress.

There are three such sites in this build, all found by scanning
(``tools/extract_firmware.py``, symbols ``sysresetreq_spin_N``):
``stop_motor_and_reset()``, ``flash_helper_verify_flash_memory()``, and the
**``COMM_REBOOT``** case inside ``commands_process_packet()`` — i.e. one of them
is reachable by anyone who can send a packet on the UART.

What a warm reset must actually do, and what this does:

* take the CPU back to **MSP, privileged, interrupts unmasked** (``CONTROL = 0``,
  ``PRIMASK = FAULTMASK = 0``); the firmware is on the process stack in thread
  mode when it asks;
* load ``SP`` and ``PC`` from the vector table, exactly as the hardware does;
* **keep the flash contents.** A real SYSRESETREQ resets the core, not the flash
  array — which is precisely why the firmware bothers to reboot here. The CRC it
  just programmed has to survive, so nothing is reloaded.
* reset the *peripherals*, because the silicon does: the USART queues and
  register file are cleared, so the firmware re-initialises them from scratch.

``.data``/``.bss`` are not touched by hand: ChibiOS' own ``crt0`` re-initialises
them from the flash image on the way through the reset vector, which is the
firmware doing its own work.
"""
from __future__ import annotations

import struct
from typing import TYPE_CHECKING, cast

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import (BPHandler, HandlerFunction,
                                                HandlerReturn, bp_handler)

from ..peripheral_models.stm32_usart import get_uart_bus

if TYPE_CHECKING:  # pragma: no cover
    from halucinator.backends.hal_backend import HalBackend

log = hal_log.getHalLogger()

VECTOR_BASE = 0x08000000
MAX_RESETS = 8


class SystemReset(BPHandler):
    """Reload SP/PC from the vector table when the firmware requests a reset.

    Halucinator configuration usage::

        - class: rehostry_vesc_bldc_f405.bp_handlers.system_reset.SystemReset
          function: sysresetreq_spin_1
    """

    def __init__(self) -> None:
        self.resets = 0

    def register_handler(self, qemu: "HalBackend", addr: int,
                         func_name: str) -> HandlerFunction:
        return cast(HandlerFunction, SystemReset.reset)

    @bp_handler(["sysresetreq_spin_0", "sysresetreq_spin_1",
                 "sysresetreq_spin_2"])
    def reset(self, qemu: "HalBackend", addr: int) -> HandlerReturn:
        self.resets += 1
        if self.resets > MAX_RESETS:
            log.error("system_reset: %d resets requested -- refusing to loop. "
                      "The firmware is rebooting on every boot, which means "
                      "something it checks after the reset still is not "
                      "satisfied.", self.resets)
            raise SystemExit(0)

        try:
            raw = bytes(qemu.read_memory(VECTOR_BASE, 1, 8, raw=True))
            sp, pc = struct.unpack("<II", raw)
        except Exception as exc:  # noqa: BLE001
            log.error("system_reset: cannot read the vector table: %s", exc)
            return False, None

        uc = getattr(qemu, "_uc", None)
        if uc is not None:
            try:
                import unicorn
                from unicorn import arm_const
                # Back to the main stack, privileged, nothing masked -- the
                # architectural reset state. CONTROL must be cleared BEFORE `sp`
                # is written, or the write lands on the process stack pointer
                # that is about to stop being the active one.
                uc.reg_write(arm_const.UC_ARM_REG_CONTROL, 0)
                uc.reg_write(arm_const.UC_ARM_REG_PRIMASK, 0)
                uc.reg_write(arm_const.UC_ARM_REG_FAULTMASK, 0)
                del unicorn
            except Exception as exc:  # noqa: BLE001
                log.warning("system_reset: could not clear CONTROL/PRIMASK "
                            "(%s); the reset may resume on the wrong stack", exc)

        qemu.write_register("sp", sp)
        qemu.write_register("pc", pc & ~1)

        # Peripherals reset too. Clearing the USART state means the firmware
        # re-runs sdStart() and re-enables the port, which is what the next boot
        # would see on real silicon.
        bus = get_uart_bus()
        for port in bus.ports.values():
            port.regs.clear()
            port.rx.clear()
            port.tx = bytearray()
            port.started = False

        log.warning("system_reset: firmware requested SYSRESETREQ at 0x%08x "
                    "(reset #%d) -- performing a warm reset to SP=0x%08x "
                    "PC=0x%08x. Flash contents are KEPT, which is the whole "
                    "point of this reboot.", addr, self.resets, sp, pc)

        # This handler moved PC deliberately, so nothing should be skipped when
        # execution resumes; continue_past_breakpoint() would otherwise leave a
        # one-shot skip armed at this address (playbook §2.62).
        try:
            qemu._bp_hit_addr = None  # noqa: SLF001
        except Exception:  # noqa: BLE001
            pass
        return False, None
