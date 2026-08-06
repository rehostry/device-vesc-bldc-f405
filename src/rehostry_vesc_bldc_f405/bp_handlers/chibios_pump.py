# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Give ChibiOS a clock and a serial interrupt, from its own idle thread.

**Why the idle thread.** VESC's ``chconf.h`` sets ``CH_CFG_ST_TIMEDELTA 0``, so
ChibiOS runs in *periodic* mode, where the system tick is **SysTick** and not a
GP timer (``ChibiOS_3.0.5/os/hal/ports/STM32/LLD/TIMv1/st_lld.c``). This build's
vector 15 points at a real ``SysTick_Handler`` at ``0x0800f8c0``, and
``st_lld_init`` is linked in — so this is the §2.41 check coming out the other
way from ``device-ardupilot-matekf405``, whose ChibiOS used TIM5.

The unicorn backend maps the ARMv7-M private peripheral bus as plain RW memory,
so SysTick stores its LOAD/CTRL and then never counts and never fires (playbook
§2.6). Periodic mode never reads ``SYST_CVR``, so the whole of the missing
behaviour is the *exception*: deliver 15 and the firmware's own
``SysTick_Handler`` → ``osalOsTimerHandlerI`` → ``chSysTimerHandlerI`` runs, with
the firmware computing every consequence.

``_idle_thread`` is the kernel stating that nothing is runnable until an
interrupt arrives — the honest place to supply one, and the safe context to take
it in: a bp_handler runs on the dispatch thread with a precise PC, whereas an
injection from a model's own thread frames whatever block boundary unicorn last
synced (playbook §2.48).

**One interrupt per visit.** Delivering a batch is wrong (§2.98: the second
entry synthesises an exception on top of a handler that has not run an
instruction), and always preferring one line starves the other (§2.127). So each
visit takes exactly one: the USART if it has a line asserted, otherwise the tick
— with a floor that forces a tick every ``CLOCK_FLOOR`` visits so a long
transmit can never stop the guest clock.

**Serial transmit is interrupt-driven too** (§2.70). ChibiOS' ``sdWrite`` only
fills an output queue and sets ``CR1.TXEIE``; the bytes reach ``DR`` from
``sd_lld_serve_interrupt``. Without a USART interrupt the firmware would compose
a perfectly correct, correctly-CRC'd reply and sit on it forever, which reads
exactly like a broken protocol engine.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import (BPHandler, HandlerFunction,
                                                HandlerReturn, bp_handler)

from ..peripheral_models import stm32_clock
from ..peripheral_models.stm32_usart import get_uart_bus

if TYPE_CHECKING:  # pragma: no cover
    from halucinator.backends.hal_backend import HalBackend

log = hal_log.getHalLogger()

# SysTick is exception 15. inject_irq(-1) reaches it because the backend
# computes the handler slot as vtor + (16 + num) * 4.
SYSTICK_IRQ = -1

# One SysTick per this many passes through the idle thread.
#
# The rate is a CORRECTNESS parameter, not a performance one (playbook §2.124),
# and this firmware pushed it in both directions. Too fast and periodic work runs
# before the code that initialises what it operates on. Too slow and the guest
# simply cannot reach its own deadlines: VESC's `conf_general_store_mc_configuration`
# opens with `mc_interface_wait_for_motor_release_both(3.0)`, which polls
# `mcpwm_foc_get_state()` every `chThdSleepMilliseconds(1)` against the ChibiOS
# system time. With CH_CFG_ST_FREQUENCY = 10000 that is **30 000 ticks** of guest
# time before the wait can end, and at one tick per eight idle visits the whole
# COMM_SET_MCCONF took over seven minutes with the profile pinned on
# `_port_switch` -- i.e. the machine was healthy and busy context-switching, not
# stuck. A tick per idle visit is the honest maximum: the idle thread is the
# kernel stating that nothing is runnable, so time may as well move.
IDLE_DIVISOR = int(os.environ.get("VESC_IDLE_DIVISOR", "1"))

# Force a SysTick every this many idle visits even while the UART has a line
# asserted, so a long transmit can never stop the guest clock.
CLOCK_FLOOR = int(os.environ.get("VESC_CLOCK_FLOOR", "4"))


class ChibiosIdlePump(BPHandler):
    """Deliver one interrupt per pass through ChibiOS' idle thread.

    Halucinator configuration usage::

        - class: rehostry_vesc_bldc_f405.bp_handlers.chibios_pump.ChibiosIdlePump
          function: _idle_thread
    """

    def __init__(self) -> None:
        self.ticks = 0
        self.uart_irqs = 0
        self._spins = 0
        self._stall_spins = 0
        self._last_rx_read = -1
        self._stall_reported = False

    def register_handler(self, qemu: "HalBackend", addr: int,
                         func_name: str) -> HandlerFunction:
        # register_handler is the ONE place a device is handed the live backend.
        # The flash model needs it so a sector erase can really blank guest
        # memory; the UART bus needs this moment to bind its listener
        # synchronously, before emu_start holds the GIL (playbook §2.3/§2.12).
        stm32_clock.set_backend(qemu)
        get_uart_bus().start_bridge()
        return cast(HandlerFunction, ChibiosIdlePump.idle)

    @bp_handler(["_idle_thread"])
    def idle(self, qemu: "HalBackend", addr: int) -> HandlerReturn:
        self._spins += 1
        bus = get_uart_bus()
        uart_irq = bus.pending_irq()

        # Stall detector: host bytes queued that the firmware is not consuming.
        # Without this, "the device is thinking" and "the receive path has
        # stopped" look identical from outside.
        port = bus.ports[0x800]
        if port.rx:
            if port.rx_read == self._last_rx_read:
                self._stall_spins += 1
            else:
                self._last_rx_read = port.rx_read
                self._stall_spins = 0
                self._stall_reported = False
            if self._stall_spins > 200000 and not self._stall_reported:
                self._stall_reported = True
                log.error("chibios_pump: RECEIVE STALLED -- %d bytes still "
                          "queued for %s after it read %d of %d; CR1=0x%04x "
                          "pending=%s (ticks=%d uart_irqs=%d)",
                          len(port.rx), port.name, port.rx_read,
                          port.rx_total, port.regs.get(0x0C, 0), uart_irq,
                          self.ticks, self.uart_irqs)

        # The UART line wins whenever it is asserted -- ChibiOS' ISR moves ONE
        # byte per interrupt, so a 470-byte COMM_GET_MCCONF reply needs 470 of
        # them, and sharing the seam evenly with the tick halves the throughput
        # of every reply. But the clock must never stop: threads (including the
        # one composing the reply) are waiting on it, so a tick is forced every
        # CLOCK_FLOOR visits regardless. Neither line can starve the other.
        take_uart = uart_irq is not None and self._spins % CLOCK_FLOOR

        if take_uart:
            self.uart_irqs += 1
            try:
                qemu.inject_irq(uart_irq)
            except Exception as exc:  # noqa: BLE001
                log.error("chibios_pump: inject_irq(%d) failed: %s",
                          uart_irq, exc)
            return False, None

        if IDLE_DIVISOR > 1 and self._spins % IDLE_DIVISOR:
            return False, None
        self.ticks += 1
        if self.ticks in (1, 1000, 100000, 1000000):
            log.info("chibios_pump: delivered SysTick #%d (uart irqs so far: %d)",
                     self.ticks, self.uart_irqs)
        try:
            qemu.inject_irq(SYSTICK_IRQ)
        except Exception as exc:  # noqa: BLE001
            log.error("chibios_pump: inject_irq(SysTick) failed: %s", exc)
        return False, None
