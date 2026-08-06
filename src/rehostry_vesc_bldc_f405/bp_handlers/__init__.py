# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Device breakpoint handlers.

Handlers for the four things this firmware needs that the hardware would
otherwise do. Each is referenced from the config's ``intercepts:`` block by its
installed dotted path (``rehostry_vesc_bldc_f405.bp_handlers.<mod>.<Class>``):

* ``chibios_pump``  SysTick and the USART interrupt, delivered from ChibiOS' idle
  thread -- the kernel stating that nothing is runnable until one arrives
* ``system_reset``  the warm reset ``NVIC_SystemReset()`` asks for, which unicorn
  cannot perform (VESC reaches one on its FIRST boot)
* ``dwt_delay``     ``chSysPolledDelayX()``, which spins on a cycle counter the
  backend cannot make advance
* ``boot_trace``    named boot milestones, and ``chSysHalt`` so a kernel panic is
  not an anonymous spin

Gotchas (playbook):
  * The ``function:`` in an intercept must match a name in ``@bp_handler([...])``,
    NOT the Python method name. Convention: make them identical to the symbol
    (trap 2).
  * Use ``from halucinator import hal_log; log = hal_log.getHalLogger()`` for any
    log visibility (trap 1).
  * If a handler starts a TCP server, bind SYNCHRONOUSLY at ``register_handler``
    time (before unicorn's emu_start holds the GIL), and only ONCE via a class
    flag -- see ModbusUartBridge.register_handler (trap 3, 12).
"""
