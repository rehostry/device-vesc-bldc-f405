<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# device-vesc-bldc-f405

A **VESC 100/250** brushless motor controller, rehosted: the VESC project's own
firmware (`vedderb/bldc` 7.01, ChibiOS 3.0.5 on an STM32F405RG) executed
instruction by instruction under HALucinator/unicorn, with its real **COMM
packet protocol** on a TCP socket.

VESC is the canonical open BLDC/FOC ESC — electric skateboards, e-bikes, robots,
small EVs, industrial drives. In the field it is configured and commanded over a
3-pin UART header, a CAN bus, or USB, using the same binary protocol VESC Tool
speaks. **That protocol has no authentication of any kind**, which is what the
attack here exercises.

```
                     tcp/21201
  VESC Tool / attacker  <-->  USART3 model  <-->  ChibiOS SD3 driver
                                                     |
                                          packet.c -> commands.c
                                                     |
                                     mc_interface / emulated EEPROM
```

## Quick start

```bash
# 1. Build the firmware from source (nothing is committed here) -- see FIRMWARE.md
python3 tools/extract_firmware.py /path/to/build/100_250/100_250.elf

# 2. Install this device into the HALucinator dev venv
"$HAL_PY" -m pip install -e .

# 3. Boot it and watch the firmware come up
rehostry-vesc-bldc-f405 run --seconds 180

# 4. The attack: one RESULT: {json} line, exit 0 iff it landed
rehostry-vesc-bldc-f405-attack

# 5. The live panel
rehostry-vesc-bldc-f405-panel          # http://127.0.0.1:9011
```

Boot takes roughly 40 s of wall clock to reach the COMM stack. The line to watch
for is the firmware's own driver arriving at the port:

```
USART3: enabled by the firmware (CR1=0x212c: UE TE RE RXNEIE)
```

## What works

| milestone | evidence |
|---|---|
| **M1** boots | no `UC_ERR` / `Traceback` / fault; ChibiOS `crt0` → `main()` → threads |
| **M2** drivers init | the firmware's own init sequence, traced by name: `conf_general_init` (emulated EEPROM) → `mc_interface_init` → `mcpwm_foc_init` → `commands_init` → `comm_usb_init` → `app_uartcomm_start` → `comm_can_init` → `timeout_init` → `shutdown_init`; CAN1 leaves initialisation mode; USART3 is enabled with `CR1=0x212c` |
| **M3** scheduler runs | SysTick delivered >100 000 times, ChibiOS `PendSV` context switches throughout, threads created and scheduled |
| **M4** protocol round-trip | `COMM_FW_VERSION` in, the firmware's own 41-byte framed and CRC-checked reply out — **byte-identical to the prediction written down before the first boot** (`PROVENANCE.md`); `COMM_GET_MCCONF` returns the firmware's own 489-byte serialized configuration |

## The seam

`hw_100_250.h` puts VESC's COMM UART on **SD3 = USART3** (PB10/PB11, 115200),
and `appconf_default.h` defaults `app_to_use` to `APP_UART`, so
`app_set_configuration()` starts the port and hands every received byte to
`packet_process_byte()`.

The bridge is **register-level**: bytes enter and leave through `USART3->DR`
(`0x40004804`). Nothing intercepts `packet_process_byte()` or `sdWrite()` — the
framing, the length byte and the CCITT CRC in every reply are produced by the
firmware's own `packet.c` and its own `crc16_tab` in flash.

## Layout

```
src/rehostry_vesc_bldc_f405/
  configs/     vesc_config.yaml  vesc_addrs.yaml  logging.cfg   (+ vesc.bin, not committed)
  peripheral_models/
    stm32_usart.py     USART2/3 + UART4, and the host TCP bridge on USART3
    stm32_clock.py     the 0x40023000 page: CRC unit + RCC + embedded-flash controller
    stm32_bxcan.py     CAN1/CAN2 handshake (MSR.INAK mirrors MCR.INRQ)
    stm32_sysmem.py    the die UID at 0x1FFF7A10
    soc_catchall.py    everything else, with real timer + GPIO register files
  bp_handlers/
    chibios_pump.py    SysTick + the USART interrupt, delivered from ChibiOS' idle thread
    system_reset.py    the warm reset NVIC_SystemReset() asks for and unicorn cannot do
    dwt_delay.py       chSysPolledDelayX(), whose cycle counter never advances
    boot_trace.py      named boot milestones + chSysHalt
  vesc_comm.py         the COMM protocol, host side (independent of the firmware)
  attack.py            the fleet-standard attack (playbook §2a)
  vesc_panel.py        the polling web panel
```

See `STATUS.md` for what is modelled, what is not, and the known limitations;
`PROVENANCE.md` for the pre-boot prediction and how it was tested;
`FIRMWARE.md` for the exact build.
