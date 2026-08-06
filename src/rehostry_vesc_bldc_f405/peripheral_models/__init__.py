# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Device peripheral models.

MMIO register models for the peripherals this firmware polls whose default-0
read would flip a branch that matters. Each model subclasses
``halucinator.peripheral_models.auto_model.AutoPeripheral`` and is referenced
from the config's ``peripherals:`` block by its installed dotted path
(``rehostry_vesc_bldc_f405.peripheral_models.<mod>.<Class>``):

* ``stm32_usart``   USART2/3 + UART4, and the host TCP bridge on USART3 (the seam)
* ``stm32_clock``   the 0x40023000 page: CRC unit, RCC, embedded-flash controller
* ``stm32_bxcan``   CAN1/CAN2, enough for ChibiOS' can_lld_start handshake
* ``stm32_sysmem``  the die UID at 0x1FFF7A10, which COMM_FW_VERSION reports
* ``soc_catchall``  everything else, with real timer + GPIO register files

Gotchas (playbook):
  * Use ``from halucinator import hal_log; log = hal_log.getHalLogger()`` -- a
    plain ``logging.getLogger(__name__)`` is silent (trap 1/2).
  * Models are constructed MORE THAN ONCE while a config resolves. Never bind a
    socket or start a thread naively in ``__init__``: use a module-level
    singleton + a ``get_bus()``-style accessor (trap 3, 12).
  * Prefer register-level capture over intercepting a driver's send function --
    the register file is the real bus boundary (see device-zephyr-can's bxcan.py).
  * NAMING the class ``AutoPeripheral`` sets a GLOBAL ``skip_svc`` flag that
    breaks FreeRTOS/NuttX/Zephyr's task-starting ``svc``. If you need the
    catch-all's behaviour but also need SVC, subclass it under a DIFFERENT name
    (e.g. ``AbsorbingPeripheral`` -- see device-nuttx-fs/soc_catchall.py) (trap 11).
"""
