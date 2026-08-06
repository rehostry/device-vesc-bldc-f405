# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Catch-all for the rest of the STM32F4 peripheral space, with real timer
register files.

``AutoPeripheral`` absorbs unmodelled MMIO and breaks status-poll spin-waits,
which is most of what an unmodelled STM32F4 needs. Two adjustments:

1. **The class must not be called ``AutoPeripheral``.** The core sets a GLOBAL
   ``skip_svc`` flag for any peripheral class *named* that, which suppresses the
   ``svc`` an RTOS uses to switch context. ChibiOS' ``_port_switch`` does not use
   ``svc``, but ``chSysHalt``/the scheduler paths do reach ``SVCall`` on
   ARMv7-M, and the flag is global — so the catch-all is subclassed under a
   different name (playbook §2.11).

2. **Timers keep a real register file.** "Reads return 0" is not a safe default
   for a timer: ChibiOS' and VESC's drivers write ``ARR``/``CCRn`` and read them
   back, and on the STM32F405 only TIM2 and TIM5 are 32-bit while every other
   timer is 16-bit. A width probe that reads back 0 sends drivers down the wrong
   branch (playbook §2.67 saw this panic a ChibiOS kernel). Status registers are
   ``rc_w0`` — cleared by writing zeros, never echoed — because a status
   register that stores its own clear-mask makes a wait-idle loop immortal.

The GPIO pages are also given a register file, and ``IDR`` is fed from ``ODR``
for the pins the firmware drives: a push-pull pad reflects on the *input*
register the level it is driving, and firmware leans on that to answer "is this
output already on?" (playbook §2.72). VESC reads back several of its own enable
pins.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from halucinator import hal_log
from halucinator.peripheral_models.auto_model import AutoPeripheral

log = hal_log.getHalLogger()

# --- timer pages ------------------------------------------------------------
TIM_SR = 0x10
TIM_CNT = 0x24
TIM_ARR = 0x2C
TIM_CCR1 = 0x34
_WIDTH_REGS = (TIM_CNT, TIM_ARR, TIM_CCR1, TIM_CCR1 + 4, TIM_CCR1 + 8,
               TIM_CCR1 + 12)

# STM32F405 timer page -> (name, counter mask). TIM2 and TIM5 are 32-bit.
TIMERS: Dict[int, Tuple[str, int]] = {
    0x40000000: ("TIM2", 0xFFFFFFFF),
    0x40000400: ("TIM3", 0x0000FFFF),
    0x40000800: ("TIM4", 0x0000FFFF),
    0x40000C00: ("TIM5", 0xFFFFFFFF),
    0x40001000: ("TIM6", 0x0000FFFF),
    0x40001400: ("TIM7", 0x0000FFFF),
    0x40001800: ("TIM12", 0x0000FFFF),
    0x40001C00: ("TIM13", 0x0000FFFF),
    0x40002000: ("TIM14", 0x0000FFFF),
    0x40010000: ("TIM1", 0x0000FFFF),
    0x40010400: ("TIM8", 0x0000FFFF),
    0x40014000: ("TIM9", 0x0000FFFF),
    0x40014400: ("TIM10", 0x0000FFFF),
    0x40014800: ("TIM11", 0x0000FFFF),
}

# --- GPIO pages -------------------------------------------------------------
GPIO_LO = 0x40020000
GPIO_HI = 0x40023000
GPIO_IDR = 0x10
GPIO_ODR = 0x14
GPIO_BSRR = 0x18


class SocCatchAll(AutoPeripheral):
    """AutoPeripheral, minus the skip_svc flag, plus timer + GPIO registers."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._regs: Dict[int, int] = {}
        self._probed: set = set()
        self._counting: set = set()

    @staticmethod
    def _timer_for(addr: int) -> Optional[Tuple[str, int, int]]:
        page = addr & ~0x3FF
        entry = TIMERS.get(page)
        return (entry[0], entry[1], page) if entry else None

    def _tick_counter(self, name: str, base: int, cmask: int) -> int:
        """A timer's CNT is a FREE-RUNNING COUNTER: advance it on every read.

        VESC's ``driver/timer.c`` runs TIM5 as its microsecond-grade time base
        (``TIMER_HZ = 1.4e7``, prescaler from the 84 MHz APB1 timer clock) and
        blocks on it directly::

            void timer_sleep(float seconds) {
                uint32_t start_t = TIM5->CNT;
                for (;;) if (timer_seconds_elapsed_since(start_t) >= seconds) return;
            }

        With CNT stored-but-static that loop is unsatisfiable: measured
        1 838 354 samples across its eight instructions per sampling window, no
        fault, no diagnostic (playbook §2.52's shape, one peripheral along).

        Advancing by one count per read is not an arbitrary rate -- it is very
        close to the real one. The loop is eight instructions, i.e. ~48 ns at
        168 MHz, and one TIM5 count is 71 ns. So a *polled* delay takes roughly
        the number of iterations the silicon would take. Time still only moves
        when the guest executes (playbook §2.77), and it is monotonic; it is
        explicitly **not calibrated** against wall clock.

        The counter wraps at ARR, as the hardware does, so the PWM timers
        (TIM1/TIM8, ARR = 0x15e0 here) stay inside their period instead of
        running away -- firmware reads those to find its position in the PWM
        cycle.
        """
        cnt = self._regs.get(base + TIM_CNT, 0) + 1
        arr = self._regs.get(base + TIM_ARR, 0) & cmask
        limit = arr + 1 if arr else cmask + 1
        cnt %= limit
        self._regs[base + TIM_CNT] = cnt
        if name not in self._counting:
            self._counting.add(name)
            log.info("%s: CNT is free-running (wraps at ARR=0x%08x)", name, arr)
        return cnt

    @staticmethod
    def _gpio_page(addr: int) -> Optional[int]:
        if GPIO_LO <= addr < GPIO_HI:
            return addr & ~0x3FF
        return None

    # -- reads -------------------------------------------------------------
    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        addr = self.address + offset
        mask = (1 << (8 * size)) - 1
        tim = self._timer_for(addr)
        if tim is not None:
            name, cmask, base = tim
            if addr - base == TIM_CNT:
                return self._tick_counter(name, base, cmask) & mask
            return self._regs.get(addr, 0) & mask
        page = self._gpio_page(addr)
        if page is not None:
            reg = addr - page
            if reg == GPIO_IDR:
                # A push-pull output reads back on IDR what it is driving.
                return self._regs.get(page + GPIO_ODR, 0) & mask
            return self._regs.get(addr, 0) & mask
        return super().hw_read(offset, size, pc=pc, **kwargs)

    # -- writes ------------------------------------------------------------
    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        addr = self.address + offset
        val = value & 0xFFFFFFFF
        tim = self._timer_for(addr)
        if tim is not None:
            name, cmask, base = tim
            reg = addr - base
            if reg in _WIDTH_REGS:
                val &= cmask
            if reg == TIM_SR:
                self._regs[addr] = self._regs.get(addr, 0) & val
                return True
            self._regs[addr] = val
            if reg == TIM_ARR and name not in self._probed:
                self._probed.add(name)
                log.info("%s: ARR reads back 0x%08x (a %d-bit counter)", name,
                         val, 32 if cmask > 0xFFFF else 16)
            return True
        page = self._gpio_page(addr)
        if page is not None:
            reg = addr - page
            if reg == GPIO_BSRR:
                odr = self._regs.get(page + GPIO_ODR, 0)
                odr |= val & 0xFFFF          # BS[15:0] set
                odr &= ~((val >> 16) & 0xFFFF)   # BR[15:0] reset
                self._regs[page + GPIO_ODR] = odr & 0xFFFF
                return True
            self._regs[addr] = val
            return True
        return super().hw_write(offset, size, value, pc=pc, **kwargs)
