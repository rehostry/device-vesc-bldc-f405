<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Provenance — vesc-bldc-f405 firmware

## The binary

- **Upstream:** <https://github.com/vedderb/bldc> — the VESC project's own
  BLDC/FOC motor-controller firmware (Benjamin Vedder). **GPL-3.0-only.**
- **Pinned commit:** `e4db57a8d90747091a4ea98c381fe3efc83a8722`
  (2026-08-04T12:27:08Z, `master`).
- **Firmware version reported by that tree:** `FW_VERSION_MAJOR 7`,
  `FW_VERSION_MINOR 01`, `FW_TEST_VERSION_NUMBER 1` (`conf_general.h:24-27`).
- **Hardware target built:** `100_250` — the Trampa VESC 100/250, an
  STM32F405RG (Cortex-M4F, 168 MHz, 1 MiB flash, 128 KiB SRAM + 64 KiB CCM),
  ChibiOS 3.0.5. Header `hwconf/trampa/100_250/hw_100_250.h`, `HW_NAME "100_250"`.
- **Build:** from source; **no prebuilt `.bin` is published upstream** (VESC Tool
  bundles release images, the firmware repo does not). See `FIRMWARE.md` for the
  exact, reproducible recipe and the sha256 of the resulting artifacts.
- **Nothing in the image was written for the re-host.** It is a stock upstream
  `make 100_250`.

### Not committed here

`.gitignore` excludes `*.bin`/`*.elf`/`*.hex`. The firmware is **GPL-3.0** and
this package is AGPL-3.0-or-later; the image is also 400 KiB of build output, and
the fleet rule is that firmware bytes are never committed. Regenerate it with
`FIRMWARE.md`'s recipe and then `tools/extract_firmware.py`.

## How the target was identified

The build produces an **unstripped ELF** (`builds/100_250/100_250.elf`) with full
symbols, so nothing about this device is inferred:

- `tools/extract_firmware.py` flattens the ELF's PT_LOAD segments from
  `0x08000000`, pads the remainder of the 1 MiB flash with `0xFF` (erased flash —
  the firmware *scans* the un-programmed QML/LISP sectors for `0xFF`, see below),
  and emits `vesc.bin` + `vesc_addrs.yaml` (decimal address → symbol).
- It **hard-fails** if the recovered vector table (`initial SP`, `Reset_Handler`)
  disagrees with what `vesc_config.yaml` hardcodes, so a different upstream
  revision fails at extraction rather than mid-boot.
- The VESC application is linked at the **flash base** `0x08000000` (VESC's own
  bootloader lives in sector 11 at `0x080E0000`, i.e. *above* the app, not below
  it), which is why this device — unlike `device-ardupilot-matekf405` — has no
  bootloader hole under its image.

## The falsifiable prediction

**Derived statically from the pinned source tree and recorded here BEFORE the
first boot of this device.** (Committed in this repository's first commit; the
run logs that test it come later.)

### 1. The protocol seam

The `100_250` hardware header sets `HW_UART_DEV = SD3`, i.e. ChibiOS' serial
driver on **USART3** (`0x40004800`), pins PB10/PB11, 115200 8N1
(`hw_100_250.h:138-143`; `app_uartcomm.c:31` `BAUDRATE 115200`).

`applications/appconf_default.h:82` sets `APPCONF_APP_TO_USE = APP_UART`, so
`app_set_configuration()` (`applications/app.c:112-114`) calls
`app_uartcomm_start(UART_PORT_COMM_HEADER)`, which `sdStart()`s SD3 and creates
the `uartcomm proc` thread. That thread feeds every received byte to
`packet_process_byte()` and hands complete packets to `commands_process_packet()`.

### 2. Framing (comm/packet.c)

`packet_send_packet()` emits, for a payload of `len <= 255`:

    0x02  len  <payload…>  crc>>8  crc&0xFF  0x03

`crc16()` (`util/crc.c:56-65`) is CCITT: polynomial `0x1021`, MSB-first, **init
0**, no reflection, no final XOR, computed over the payload only. The 256-entry
`crc16_tab` is a `const unsigned short []` in `.rodata`; `tests/test_structure.py`
regenerates it independently and asserts it appears **verbatim in the image
bytes** (playbook §2.19: GCC can rewrite a CRC loop, so the table in the artifact
is the thing to check, and §2.118: the check must be able to fail — the test also
asserts a plausible-wrong polynomial does *not* match).

### 3. The exact `COMM_FW_VERSION` reply

`comm/commands.c:231-296`, `case COMM_FW_VERSION`, builds the payload field by
field. Every field is resolvable statically for this build:

| off | bytes | source | value |
|---|---|---|---|
| 0 | 1 | `COMM_FW_VERSION` (first enum member) | `00` |
| 1 | 1 | `FW_VERSION_MAJOR` | `07` |
| 2 | 1 | `FW_VERSION_MINOR` (`01`, C octal → 1) | `01` |
| 3 | 8 | `HW_NAME` + NUL | `31 30 30 5F 32 35 30 00` (`"100_250"`) |
| 11 | 12 | `STM32_UUID_8` = `(uint8_t*)0x1FFF7A10` | see below |
| 23 | 1 | `app_get_configuration()->pairing_done`, default `APPCONF_PAIRING_DONE false` | `00` |
| 24 | 1 | `FW_TEST_VERSION_NUMBER` | `01` |
| 25 | 1 | `HW_TYPE_VESC` (= 0) | `00` |
| 26 | 1 | `conf_custom_cfg_num()` — no custom config in this build | `00` |
| 27 | 1 | `HW_HAS_PHASE_FILTERS` **is** defined (`hw_100_250.h:28`) | `01` |
| 28 | 1 | `QMLUI_SOURCE_HW` not defined | `00` |
| 29 | 1 | `flash_helper_code_flags(CODE_IND_QML)` — QML sector is erased, its CRC check fails, so `code_data()` returns 0 | `00` |
| 30 | 1 | `nrf_flags` (static, initialised 0) | `00` |
| 31 | 1 | `FW_NAME` = `""` (`hwconf/hw.h:46-50`, limits **not** disabled) + NUL | `00` |
| 32 | 4 | `main_calc_hw_crc()` big-endian — no QMLUI source, no custom cfg, no QML in flash, so it stays `0` | `00 00 00 00` |

Payload length is therefore **36 = 0x24** bytes.

**The die UID is not in the firmware image and is not a peripheral.** Playbook
§2.80: `0x1FFF7A10` is STM32 system/OTP space that nothing maps, and reading it
aborts the run. This device maps it and answers a **fixed, documented, obviously
synthetic** 12-byte serial — the ASCII `REHOSTRYVESC` — rather than zeroes
(zeroes read like a failed access rather than a chosen constant). The value is
served by `peripheral_models/stm32_sysmem.py` and asserted in `tests/`.

**Predicted framed reply on USART3's data register, byte for byte:**

```
02 24 00 07 01 31 30 30 5F 32 35 30 00
52 45 48 4F 53 54 52 59 56 45 53 43
00 01 00 00 01 00 00 00 00 00 00 00 00
0E AA 03
```

41 bytes. The CRC `0x0EAA` is computed here from an **independent** Python
implementation of `crc16_tab`; the firmware computes its own with the table in
its own `.rodata`. If the emulated firmware emits these bytes, the match cannot
be circular: the host has no code that could have synthesised the frame.

The request that must produce it is the same framing around a one-byte payload
`00`:

```
02 01 00 00 00 03      # start, len=1, COMM_FW_VERSION, crc16(00)=0x0000, stop
```

### 4. Predicted rejections (negative controls, derived from the same source)

- **Bad CRC.** `try_decode_packet()` (`packet.c:237-245`) only calls
  `process_func` when `crc_calc == crc_rx`; otherwise it returns `-1` and the
  byte stream is re-scanned one byte forward. Prediction: a well-formed frame
  with a corrupted CRC produces **no reply at all**.
- **Bad `mcconf` signature.** `COMM_SET_MCCONF` calls
  `confgenerator_deserialize_mcconf()`, which returns false unless the first four
  payload bytes equal `MCCONF_SIGNATURE`. Prediction: the firmware answers with
  its own `COMM_PRINT` carrying the string
  `Warning: Could not set mcconf due to wrong signature`, and the stored
  configuration is **unchanged**.

### 5. What is NOT predicted byte-exactly, and why

Per playbook §2.24, a prediction must not be a claim about when the host
sampled. Anything the running motor-control loop produces — `COMM_GET_VALUES`'
voltages, currents, temperatures, the ADC-derived numbers — depends on modelled
analogue inputs and on run timing, so it is **not** predicted byte-exactly here.
The predictions above are all values the *firmware itself* fixes at compile time
or reads back from its own storage.

## Licensing

- This re-host package: **AGPL-3.0-or-later**, `Copyright 2026 Christopher Wright`.
- The firmware: **GPL-3.0-only**, © Benjamin Vedder and the VESC contributors.
  It is **not** redistributed here — no firmware bytes are committed. Build it
  yourself with `FIRMWARE.md`.
- ChibiOS 3.0.5, vendored inside the VESC tree, is GPL-3.0 with the VESC
  project's usage; see `ChibiOS_3.0.5/` in the upstream repository.
