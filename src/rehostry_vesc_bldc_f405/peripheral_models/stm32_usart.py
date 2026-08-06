# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The STM32F4 USART page at 0x40004000 — USART2, **USART3**, UART4, UART5 —
modelled at register level, with a host TCP bridge on USART3.

USART3 is where this device's protocol lives. ``hw_100_250.h:138`` sets
``HW_UART_DEV = SD3``, and ``appconf_default.h:82`` defaults ``app_to_use`` to
``APP_UART``, so ``app_set_configuration()`` starts ChibiOS' serial driver on
USART3 and hands every byte it receives to VESC's own ``packet_process_byte()``.
That is the seam: the whole VESC COMM protocol — the one VESC Tool speaks, and
the one an attacker on the ESC's UART header speaks — arrives here.

**Register level, deliberately.** Nothing intercepts ``packet_process_byte()``
or ``sdWrite()``. Bytes go in through ``USART3->DR`` and come out of
``USART3->DR``, which is the real bus boundary: the framing, the length byte and
the CCITT CRC in the reply are produced by the firmware's own ``packet.c`` and
its own ``crc16_tab``, not by anything on this side (playbook §3).

What the ChibiOS driver actually does, and therefore what has to be right
(``ChibiOS_3.0.5/os/hal/ports/STM32/LLD/USARTv1/serial_lld.c``):

* ``usart_init()`` writes BRR/CR2/CR3, then ``CR1 = UE|PEIE|RXNEIE|TE|RE``,
  clears ``SR`` and does the two dummy reads (``SR`` then ``DR``) that retire the
  status bits. So ``DR`` is read once at startup with nothing to receive — it
  must not consume a byte that has not arrived, and it must not underflow.
* ``sd_lld_serve_interrupt()`` reads ``SR`` once, then ``DR`` if ``RXNE``, then
  — if ``CR1.TXEIE`` and ``SR.TXE`` — pops one byte from the output queue and
  writes it to ``DR``, clearing ``TXEIE`` itself when the queue runs dry.
* ``sd_lld_notify()`` sets ``CR1.TXEIE`` when the firmware writes to the queue.

So **transmit is interrupt-driven** (playbook §2.70): the firmware composes the
whole reply, buffers it, and it only reaches the wire because the USART's
interrupt keeps being taken. This model therefore reports a line as pending
while ``RXNE & RXNEIE`` *or* ``TXE & TXEIE`` holds, and a bp_handler injects it
(models raise flags, handlers inject — playbook §2.95).

Trap 3/12 apply: peripheral models are constructed more than once while a config
resolves, so the TCP listener lives on a module-level singleton reached through
:func:`get_uart_bus`, is bound exactly once, and a failed bind is logged loudly —
a device whose bridge never bound looks exactly like a firmware wall.
"""
from __future__ import annotations

import os
import socket
import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from halucinator import hal_log
from halucinator.peripheral_models.auto_model import AutoPeripheral

log = hal_log.getHalLogger()

PAGE_BASE = 0x40004000
# offset within the page -> (name, NVIC IRQ number on the STM32F405)
PORTS: Dict[int, tuple] = {
    0x400: ("USART2", 38),
    0x800: ("USART3", 39),
    0xC00: ("UART4", 52),
}
# The port this device bridges to a host TCP socket.
BRIDGE_PORT_NAME = "USART3"
BRIDGE_OFFSET = 0x800

# Register offsets within a USART.
SR = 0x00
DR = 0x04
BRR = 0x08
CR1 = 0x0C
CR2 = 0x10
CR3 = 0x14

SR_RXNE = 1 << 5
SR_TC = 1 << 6
SR_TXE = 1 << 7

CR1_RE = 1 << 2
CR1_TE = 1 << 3
CR1_RXNEIE = 1 << 5
CR1_TXEIE = 1 << 7
CR1_UE = 1 << 13

TCP_PORT = int(os.environ.get("VESC_UART_PORT", "21201"))

# Log a transmit-progress line every N bytes (0 = off). Cheap, and it is the
# difference between "the UART is busy" and "the UART is sending your reply".
TX_TRACE = int(os.environ.get("VESC_UART_TX_TRACE", "256"))


class _Port:
    """One USART's register file + queues."""

    def __init__(self, name: str, irq: int) -> None:
        self.name = name
        self.irq = irq
        self.regs: Dict[int, int] = {}
        self.rx: Deque[int] = deque()
        self.tx: bytearray = bytearray()
        self.started = False
        self.tx_total = 0
        self.rx_total = 0
        self.rx_read = 0

    # -- what the firmware sees ------------------------------------------
    def status(self) -> int:
        # TXE and TC are permanently set: the shift register of a model with no
        # baud rate is always empty. RXNE follows the receive queue.
        sr = SR_TXE | SR_TC
        if self.rx:
            sr |= SR_RXNE
        return sr

    def irq_pending(self) -> bool:
        cr1 = self.regs.get(CR1, 0)
        if not cr1 & CR1_UE:
            return False
        sr = self.status()
        if (cr1 & CR1_RXNEIE) and (sr & SR_RXNE):
            return True
        if (cr1 & CR1_TXEIE) and (sr & SR_TXE):
            return True
        return False


class UartBus:
    """Module-level singleton: the ports, and the host bridge on USART3."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.ports: Dict[int, _Port] = {
            off: _Port(name, irq) for off, (name, irq) in PORTS.items()}
        self._srv: Optional[socket.socket] = None
        self._clients: List[socket.socket] = []
        self._bound = False
        self.bridge_port = TCP_PORT

    # -- host bridge -----------------------------------------------------
    def start_bridge(self) -> None:
        if self._bound:
            return
        self._bound = True
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", self.bridge_port))
            srv.listen(4)
        except OSError as exc:
            # Playbook §2.12: a failed bind looks EXACTLY like a firmware wall --
            # the device boots, looks healthy and simply never answers.
            log.error("vesc uart: could NOT bind tcp/%d (%s) -- nothing can be "
                      "injected on this run", self.bridge_port, exc)
            return
        self._srv = srv
        log.info("vesc uart: LISTENing on tcp/%d  <->  %s (VESC COMM protocol)",
                 self.bridge_port, BRIDGE_PORT_NAME)
        threading.Thread(target=self._accept_loop, daemon=True,
                         name="vesc-uart-accept").start()

    def _accept_loop(self) -> None:
        while self._srv is not None:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self._lock:
                self._clients.append(conn)
            log.info("vesc uart: host connected on tcp/%d", self.bridge_port)
            threading.Thread(target=self._client_loop, args=(conn,), daemon=True,
                             name="vesc-uart-rx").start()

    def _client_loop(self, conn: socket.socket) -> None:
        port = self.ports[BRIDGE_OFFSET]
        while True:
            try:
                data = conn.recv(4096)
            except OSError:
                data = b""
            if not data:
                break
            with self._lock:
                port.rx.extend(data)
                port.rx_total += len(data)
        with self._lock:
            if conn in self._clients:
                self._clients.remove(conn)
        try:
            conn.close()
        except OSError:
            pass
        log.info("vesc uart: host disconnected")

    def _publish(self, data: bytes) -> None:
        with self._lock:
            clients = list(self._clients)
        for c in clients:
            try:
                c.sendall(data)
            except OSError:
                pass

    # -- test/attack helpers ---------------------------------------------
    def inject(self, data: bytes, offset: int = BRIDGE_OFFSET) -> None:
        with self._lock:
            self.ports[offset].rx.extend(data)
            self.ports[offset].rx_total += len(data)

    def pending_irq(self) -> Optional[int]:
        """The IRQ number of the first port with a line asserted, else None."""
        for off in sorted(self.ports):
            p = self.ports[off]
            if p.irq_pending():
                return p.irq
        return None


_BUS: Optional[UartBus] = None


def get_uart_bus() -> UartBus:
    """The one live bus. Models are constructed more than once while a config
    resolves (playbook §2.3); this is the instance everyone must reach."""
    global _BUS
    if _BUS is None:
        _BUS = UartBus()
    return _BUS


class Stm32UsartBlock(AutoPeripheral):
    """0x40004000: USART2 (+0x400), USART3 (+0x800), UART4 (+0xc00)."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.bus = get_uart_bus()

    @staticmethod
    def _split(offset: int):
        base = offset & ~0x3FF
        return base, offset & 0x3FF

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        base, reg = self._split(offset)
        port = self.bus.ports.get(base)
        if port is None:
            return 0
        if reg == SR:
            return port.status()
        if reg == DR:
            with self.bus._lock:
                if port.rx:
                    port.rx_read += 1
                    if TX_TRACE and port.rx_read % TX_TRACE == 0:
                        log.info("%s: firmware has read %d of %d received bytes",
                                 port.name, port.rx_read, port.rx_total)
                    return port.rx.popleft()
            # ChibiOS reads DR once at startup with nothing received, to retire
            # the status bits. Answering 0 is correct and must not underflow.
            return 0
        return port.regs.get(reg, 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        base, reg = self._split(offset)
        port = self.bus.ports.get(base)
        if port is None:
            return True
        value &= 0xFFFFFFFF
        if reg == DR:
            byte = value & 0xFF
            port.tx.append(byte)
            port.tx_total += 1
            if base == BRIDGE_OFFSET:
                self.bus._publish(bytes([byte]))
            # A running total, with a preview of what the firmware is actually
            # emitting. Without it, "the device is transmitting" and "the device
            # is transmitting the reply you asked for" are indistinguishable
            # from outside -- and they are not the same thing: the first run of
            # this device pushed 985 852 bytes out of USART3 while the attack
            # waited for one 489-byte frame.
            if TX_TRACE and port.tx_total % TX_TRACE == 0:
                tail = bytes(port.tx[-48:])
                log.info("%s: %d bytes transmitted; last 48: %s | %s",
                         port.name, port.tx_total, tail.hex(),
                         "".join(chr(b) if 32 <= b < 127 else "." for b in tail))
            return True
        if reg == SR:
            # rc_w0 on this part: the firmware clears flags by writing zeros.
            # Never store it -- a status register that echoes its own write
            # makes the driver's wait immortal (playbook §2.67).
            return True
        port.regs[reg] = value
        if reg == CR1 and (value & CR1_UE) and not port.started:
            port.started = True
            log.info("%s: enabled by the firmware (CR1=0x%04x: %s%s%s%s) -- "
                     "ChibiOS' serial driver is up on this port",
                     port.name, value,
                     "UE " if value & CR1_UE else "",
                     "TE " if value & CR1_TE else "",
                     "RE " if value & CR1_RE else "",
                     "RXNEIE" if value & CR1_RXNEIE else "")
        return True
