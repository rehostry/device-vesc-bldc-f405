# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The bxCAN page at 0x40006000 — CAN1 (+0x400) and CAN2 (+0x800).

VESC's ``comm_can_init()`` calls ChibiOS' ``canStart()``, whose ``can_lld_start``
does the standard bxCAN entry/exit dance::

    CAN->MCR = CAN_MCR_INRQ;                     /* request init mode  */
    while ((CAN->MSR & CAN_MSR_INAK) == 0) ;     /* wait: INAK SET     */
    ... program BTR / filters ...
    CAN->MCR &= ~CAN_MCR_INRQ;
    while ((CAN->MSR & CAN_MSR_INAK) != 0) ;     /* wait: INAK CLEAR   */

That is playbook §2.72 in its purest form: **a "ready" model that is always
ready breaks the opposite wait.** The catch-all's busy-wait breaker answers a
spun read with all-ones, which satisfies the first loop and makes the second one
unsatisfiable — measured as a hard spin at ``pc=0x0800fc46`` on ``0x40006404``
with no fault and nothing in the log. Mirroring each acknowledge bit from the
request bit that causes it makes both directions work, and is simply what the
silicon does.

Scope, stated plainly: this models the controller's **handshake and status**, not
a bus. Nothing is attached to CAN, so ``RF0R.FMP``/``RF1R.FMP`` read 0 (no
frames) and the three transmit mailboxes always read empty. VESC's CAN COMM
channel therefore exists but has no peer on this rehost; the protocol seam this
device exposes is USART3 (see peripheral_models/stm32_usart.py).
"""
from __future__ import annotations

from typing import Any, Dict

from halucinator import hal_log
from halucinator.peripheral_models.auto_model import AutoPeripheral

log = hal_log.getHalLogger()

PAGE_BASE = 0x40006000
CONTROLLERS = {0x400: "CAN1", 0x800: "CAN2"}

MCR = 0x00
MSR = 0x04
TSR = 0x08
RF0R = 0x0C
RF1R = 0x10
IER = 0x14
ESR = 0x18
BTR = 0x1C
FMR = 0x200

MCR_INRQ = 1 << 0
MCR_SLEEP = 1 << 1
MCR_RESET = 1 << 15

MSR_INAK = 1 << 0
MSR_SLAK = 1 << 1

# TME0..TME2: all three transmit mailboxes empty. A driver that waits for a free
# mailbox before queueing must be able to find one.
TSR_TME_ALL = (1 << 26) | (1 << 27) | (1 << 28)

# MCR out of reset on the STM32F4: SLEEP is set (the peripheral powers up in
# sleep mode) -- which is why every driver clears it, and why SLAK has to track
# it rather than being nailed either way (playbook §2.84: populate reset values
# for any register the firmware reads before writing).
MCR_RESET_VALUE = MCR_SLEEP


class Stm32BxCan(AutoPeripheral):
    """0x40006000: CAN1 at +0x400, CAN2 at +0x800."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self._regs: Dict[int, int] = {}
        self._started: set = set()

    @staticmethod
    def _split(offset: int):
        return offset & ~0x3FF, offset & 0x3FF

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        base, reg = self._split(offset)
        if base not in CONTROLLERS:
            return 0
        mcr = self._regs.get(base + MCR, MCR_RESET_VALUE)
        if reg == MSR:
            msr = 0
            if mcr & MCR_INRQ:
                msr |= MSR_INAK          # init acknowledged
            if mcr & MCR_SLEEP:
                msr |= MSR_SLAK          # sleep acknowledged
            return msr
        if reg == TSR:
            return TSR_TME_ALL
        if reg in (RF0R, RF1R):
            return 0                     # FMP = 0: no frames waiting
        if reg == ESR:
            return 0                     # no bus errors, error-active
        return self._regs.get(base + reg, MCR_RESET_VALUE if reg == MCR else 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        base, reg = self._split(offset)
        if base not in CONTROLLERS:
            return True
        value &= 0xFFFFFFFF
        if reg == MCR:
            # RESET is a software reset that the hardware self-clears; storing it
            # would leave the peripheral permanently in reset (playbook §2.73).
            if value & MCR_RESET:
                self._regs[base + MCR] = MCR_RESET_VALUE
                return True
            self._regs[base + MCR] = value
            if not value & MCR_INRQ and base not in self._started:
                self._started.add(base)
                log.info("%s: left initialisation mode (MCR=0x%08x, BTR=0x%08x) "
                         "-- the controller is up, but nothing is attached to "
                         "the bus on this rehost", CONTROLLERS[base], value,
                         self._regs.get(base + BTR, 0))
            return True
        self._regs[base + reg] = value
        return True
