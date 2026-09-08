# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The VESC COMM packet protocol, host side.

This is an **independent** re-implementation of ``comm/packet.c`` and
``util/crc.c`` from the pinned upstream tree, written from the source rather
than copied out of the firmware. That independence is the point: when the
rehosted firmware's reply matches what this module expects, the framing and the
CRC were produced by the firmware's own code and its own ``crc16_tab``, and the
match cannot be circular (playbook §3).

Framing (``packet_send_packet`` / ``try_decode_packet``)::

    len <= 255      0x02  len            <payload…>  crc_hi crc_lo  0x03
    len <= 65535    0x03  len_hi len_lo  <payload…>  crc_hi crc_lo  0x03

The CRC is CCITT over the **payload only**: polynomial 0x1021, MSB-first,
initial value 0, no reflection, no final XOR. ``PACKET_MAX_PL_LEN`` is 512 in
this build, and the decoder rejects a 16-bit-length frame shorter than 255
bytes ("a shorter packet should use less length bytes").

There is **no authentication, no session and no sequence number** anywhere in
this protocol. Anyone who can put bytes on the ESC's UART header — or on its CAN
bus, or its USB port — can send any of these commands. That is what the attack
in ``attack.py`` exercises.
"""
from __future__ import annotations

import struct
from typing import Optional, Tuple

# --- packet ids (datatypes.h, COMM_PACKET_ID) -------------------------------
COMM_FW_VERSION = 0
COMM_GET_VALUES = 4
COMM_SET_MCCONF = 13
COMM_GET_MCCONF = 14
COMM_SET_MCCONF_TEMP = 48
COMM_TERMINAL_CMD = 20
COMM_PRINT = 21
COMM_REBOOT = 29

# confgenerator.h
MCCONF_SIGNATURE = 2466726157        # 0x9302FF8D

# Offsets INSIDE the serialized mc_configuration (confgenerator.c):
#   0  uint32  MCCONF_SIGNATURE
#   4  u8      pwm_mode
#   5  u8      comm_mode
#   6  u8      motor_type
#   7  u8      sensor_mode
#   8  f32     l_current_max      <- the motor-current limit
#   12 f32     l_current_min
MCCONF_OFF_SIGNATURE = 0
MCCONF_OFF_L_CURRENT_MAX = 8
MCCONF_OFF_L_CURRENT_MIN = 12
# The rest of the offsets the attack reads back, all derived from the order of
# the appends in confgenerator_serialize_mcconf() and pinned by tests/.
MCCONF_OFF_L_IN_CURRENT_MAX = 16     # float32_auto, battery current limit
MCCONF_OFF_L_IN_CURRENT_MIN = 20     # float32_auto
MCCONF_OFF_L_MIN_ERPM = 32           # float32_auto
MCCONF_OFF_L_MAX_ERPM = 36           # float32_auto
MCCONF_OFF_L_MIN_DUTY = 69           # float16 / 10000
MCCONF_OFF_L_MAX_DUTY = 71           # float16 / 10000
MCCONF_OFF_L_WATT_MAX = 73           # float32_auto
MCCONF_OFF_L_WATT_MIN = 77           # float32_auto
MCCONF_OFF_L_CURRENT_MAX_SCALE = 81  # float16 / 10000
MCCONF_OFF_L_CURRENT_MIN_SCALE = 83  # float16 / 10000


def _crc16_table() -> Tuple[int, ...]:
    tab = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
        tab.append(c)
    return tuple(tab)


CRC16_TAB = _crc16_table()


def crc16(buf: bytes) -> int:
    """``util/crc.c``'s ``crc16()``: CCITT, poly 0x1021, init 0, unreflected."""
    ck = 0
    for b in buf:
        ck = (CRC16_TAB[((ck >> 8) ^ b) & 0xFF] ^ ((ck << 8) & 0xFFFF)) & 0xFFFF
    return ck


def frame(payload: bytes) -> bytes:
    """Wrap a payload the way ``packet_send_packet()`` does."""
    if not 1 <= len(payload) <= 512:
        raise ValueError("payload must be 1..512 bytes (PACKET_MAX_PL_LEN)")
    c = crc16(payload)
    if len(payload) <= 255:
        head = bytes((2, len(payload)))
    else:
        head = bytes((3, (len(payload) >> 8) & 0xFF, len(payload) & 0xFF))
    return head + payload + bytes((c >> 8, c & 0xFF, 3))


def unframe(buf: bytes) -> Tuple[Optional[bytes], int]:
    """Decode the first complete frame in ``buf``.

    Returns ``(payload, consumed)``; ``(None, 0)`` when more data is needed.
    Mirrors ``try_decode_packet()``, including its CRC check — a frame whose CRC
    does not match is not a frame.
    """
    if not buf:
        return None, 0
    start = buf[0]
    if start == 2:
        hdr = 2
        if len(buf) < 2:
            return None, 0
        length = buf[1]
    elif start == 3:
        hdr = 3
        if len(buf) < 3:
            return None, 0
        length = (buf[1] << 8) | buf[2]
    else:
        return None, 0
    if len(buf) < hdr + length + 3:
        return None, 0
    payload = buf[hdr:hdr + length]
    got = (buf[hdr + length] << 8) | buf[hdr + length + 1]
    if buf[hdr + length + 2] != 3 or got != crc16(payload):
        return None, 0
    return payload, hdr + length + 3


def float32_auto(value: float) -> bytes:
    """``buffer_append_float32_auto()`` — big-endian IEEE-754 binary32.

    VESC builds the word by hand out of ``frexpf()`` rather than punning the
    float, but for every normal number the result is bit-identical to
    IEEE-754 single precision; subnormals are flushed to zero. Encoding it as
    ``>f`` is therefore exact, and ``tests/test_structure.py`` checks that
    against a transcription of VESC's own arithmetic rather than assuming it.
    """
    if abs(value) < 1.5e-38:
        value = 0.0
    return struct.pack(">f", value)


def parse_float32_auto(buf: bytes, off: int) -> float:
    return struct.unpack_from(">f", buf, off)[0]


def float32(value: float) -> float:
    """``value`` rounded to the nearest binary32, the way the guest holds it."""
    return struct.unpack(">f", struct.pack(">f", value))[0]


def float16(value: float, scale: float = 10000.0) -> bytes:
    """``buffer_append_float16()`` -- and it TRUNCATES, it does not round.

    ``util/buffer.c`` is::

        void buffer_append_float16(uint8_t* buffer, float number, float scale,
                                   int32_t *index) {
            buffer_append_int16(buffer, (int16_t)(number * scale), index);
        }

    ``(int16_t)`` is a C cast: it truncates toward zero. This function
    previously used ``round()``, and the docstring said so -- which is wrong
    for **537 of the 9000** values ``n/10000`` for n in 500..9500, because the
    binary32 nearest ``n/10000`` can sit just BELOW it and the product then
    truncates to ``n - 1``. Worked example, measured live on this device: the
    attacker writes ``l_current_max_scale = 0.5275``; binary32(0.5275) * 10000
    computed in binary32 is 5274.999512, and the firmware answers **5274**,
    not 5275.

    The arithmetic is done in binary32 at every step because that is what the
    Cortex-M4F's VFP does with two ``float`` operands.
    """
    prod = float32(float32(value) * float32(scale))
    return struct.pack(">h", int(prod))     # int() truncates toward zero


def parse_float16(buf: bytes, off: int, scale: float = 10000.0) -> float:
    return struct.unpack_from(">h", buf, off)[0] / scale


def set_mcconf_temp_payload(conf: bytes, *, store: bool = False,
                            ack: bool = True,
                            l_current_max_scale: Optional[float] = None,
                            l_in_current_max: Optional[float] = None) -> bytes:
    """Build a ``COMM_SET_MCCONF_TEMP`` payload from a live ``mc_configuration``.

    The handler (``commands.c``, case ``COMM_SET_MCCONF_TEMP``) reads a fixed
    field order and writes straight into ``mc_interface_get_configuration()``.
    With ``store`` false it does **not** touch the emulated EEPROM, so it is the
    fast path to the same live limits ``COMM_SET_MCCONF`` reaches.

    Every field the attacker does not intend to change is copied out of the
    device's own current configuration, so the packet is a genuine
    read-modify-write rather than a set of invented values.
    """
    def f32(off):
        return parse_float32_auto(conf, off)

    cur_scale_max = parse_float16(conf, MCCONF_OFF_L_CURRENT_MAX_SCALE)
    cur_scale_min = parse_float16(conf, MCCONF_OFF_L_CURRENT_MIN_SCALE)
    if l_current_max_scale is not None:
        cur_scale_max = l_current_max_scale
    in_max = f32(MCCONF_OFF_L_IN_CURRENT_MAX)
    if l_in_current_max is not None:
        in_max = l_in_current_max

    out = bytearray([COMM_SET_MCCONF_TEMP])
    out += bytes((1 if store else 0, 0, 1 if ack else 0, 0))
    out += float32_auto(cur_scale_min)
    out += float32_auto(cur_scale_max)
    out += float32_auto(f32(MCCONF_OFF_L_MIN_ERPM))
    out += float32_auto(f32(MCCONF_OFF_L_MAX_ERPM))
    out += float32_auto(parse_float16(conf, MCCONF_OFF_L_MIN_DUTY))
    out += float32_auto(parse_float16(conf, MCCONF_OFF_L_MAX_DUTY))
    out += float32_auto(f32(MCCONF_OFF_L_WATT_MIN))
    out += float32_auto(f32(MCCONF_OFF_L_WATT_MAX))
    out += float32_auto(f32(MCCONF_OFF_L_IN_CURRENT_MIN))
    out += float32_auto(in_max)
    return bytes(out)


def parse_fw_version(payload: bytes) -> dict:
    """Decode a ``COMM_FW_VERSION`` reply (``commands.c`` case COMM_FW_VERSION)."""
    if not payload or payload[0] != COMM_FW_VERSION:
        raise ValueError("not a COMM_FW_VERSION reply")
    major, minor = payload[1], payload[2]
    end = payload.index(b"\x00", 3)
    hw_name = payload[3:end].decode("latin-1")
    i = end + 1
    uuid = payload[i:i + 12]
    i += 12
    return {
        "fw_major": major,
        "fw_minor": minor,
        "fw_version": "%d.%02d" % (major, minor),
        "hw_name": hw_name,
        "uuid": uuid.hex(),
        "uuid_ascii": uuid.decode("latin-1"),
        "pairing_done": payload[i],
        "test_version": payload[i + 1],
        "hw_type": payload[i + 2],
    }
