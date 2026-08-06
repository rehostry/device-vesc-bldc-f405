# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Answer ChibiOS' cycle-counter busy delay, and keep DWT->CYCCNT monotonic.

``chSysPolledDelayX(cycles)`` is six instructions::

    ldr r2, =0xE0001000      ; DWT
    ldr r1, [r2, #4]         ; start = DWT->CYCCNT
  1:ldr r3, [r2, #4]         ; now   = DWT->CYCCNT
    subs r3, r3, r1
    cmp  r0, r3
    bhi  1b

The unicorn backend maps the ARMv7-M private peripheral bus as plain RW memory,
so ``DWT->CYCCNT`` stores whatever the firmware wrote and **never advances**.
The loop is therefore unsatisfiable: measured 12 500 000 samples at those four
addresses per window, forever, with no fault, no MMIO and nothing in the log.
It is the same silent shape as the SysTick trap (playbook §2.6), one peripheral
along, and it is reached the first time anything wants a sub-microsecond
hardware delay — here ChibiOS' USB OTG bring-up inside ``comm_usb_init()``.

Modelling the register properly is not available: the PPB is owned by the
backend, and taking it over means owning the whole 1 MiB including ``SCB->ICSR``,
which the core maintains and which ChibiOS' exception epilogue depends on
(playbook §2.56, §2.68). So this answers at the *function* seam instead:

* the requested cycles are **added to DWT->CYCCNT in guest memory**, so anything
  else that reads the cycle counter still sees it move forward monotonically;
* the delay itself returns immediately.

Stated plainly, because it is a real limitation: **this device does not honour
sub-microsecond hardware delays.** Guest time is monotonic but not calibrated.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, cast

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import (BPHandler, HandlerFunction,
                                                HandlerReturn, bp_handler)

if TYPE_CHECKING:  # pragma: no cover
    from halucinator.backends.hal_backend import HalBackend

log = hal_log.getHalLogger()

DWT_CYCCNT = 0xE0001004


class PolledDelay(BPHandler):
    """Complete ``chSysPolledDelayX()`` at once, advancing the cycle counter.

    Halucinator configuration usage::

        - class: rehostry_vesc_bldc_f405.bp_handlers.dwt_delay.PolledDelay
          function: chSysPolledDelayX
    """

    def __init__(self) -> None:
        self.calls = 0
        self.cycles = 0

    def register_handler(self, qemu: "HalBackend", addr: int,
                         func_name: str) -> HandlerFunction:
        return cast(HandlerFunction, PolledDelay.delay)

    @bp_handler(["chSysPolledDelayX"])
    def delay(self, qemu: "HalBackend", addr: int) -> HandlerReturn:
        try:
            want = qemu.read_register("r0") & 0xFFFFFFFF
        except Exception:  # noqa: BLE001
            want = 0
        self.calls += 1
        self.cycles += want
        try:
            cur = int.from_bytes(
                bytes(qemu.read_memory(DWT_CYCCNT, 1, 4, raw=True)), "little")
            qemu.write_memory(DWT_CYCCNT, 1,
                              ((cur + want + 1) & 0xFFFFFFFF).to_bytes(4, "little"),
                              4, raw=True)
        except Exception as exc:  # noqa: BLE001
            if self.calls == 1:
                log.warning("dwt_delay: could not advance DWT->CYCCNT (%s)", exc)
        if self.calls == 1:
            log.info("dwt_delay: chSysPolledDelayX(%u cycles) answered at the "
                     "function seam -- DWT->CYCCNT does not advance under "
                     "unicorn, so this loop is otherwise unsatisfiable", want)
        # Void function: returning "handled" makes the framework do pc = lr,
        # which is exactly a return from it.
        return True, None
