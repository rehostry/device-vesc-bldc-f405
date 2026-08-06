<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Status — device-vesc-bldc-f405

**Milestone: M4** — a real VESC COMM protocol round-trip over USART3, matching a
byte-exact prediction made before the first boot.

Firmware: `vedderb/bldc` @ `e4db57a8d90747091a4ea98c381fe3efc83a8722`, hardware
target `100_250` (Trampa VESC 100/250, STM32F405RG, ChibiOS 3.0.5), built from
source — see `FIRMWARE.md`. No firmware bytes are committed.

## Milestones, with the evidence and the alternative ruled out

### M1 — boots without faulting

ChibiOS' `crt0` runs, `main()` is reached, `chSysInit()` creates the idle thread
and the main thread. No `UC_ERR`, no `Traceback`, no `FETCH-DERAIL` for the whole
run.

*Alternative ruled out:* "it is executing, but not the firmware's code." The boot
is traced by **symbol name** (`bp_handlers/boot_trace.py`), not by address
counting, and the sequence it prints is exactly `main()`'s source order in
`main.c` — `conf_general_init` → `flash_helper_verify_flash_memory` →
`ledpwm_init` → `mc_interface_init` → `commands_init` → `comm_usb_init` →
`app_uartcomm_initialize` → `app_uartcomm_start` → `app_set_configuration` →
`comm_can_init` → `timeout_init` → `bm_init` → `shutdown_init`. Nothing but the
firmware's own control flow produces that order.

### M2 — drivers initialise

The firmware's own drivers reach their hardware and are answered:

```
stm32_clock: system clock switch requested (RCC_CFGR=0x00000000)
TIM5: ARR reads back 0xffffffff (a 32-bit counter)
TIM1: ARR reads back 0x000015e0 (a 16-bit counter)
stm32_flash: unlocked
stm32_sysmem: firmware read the die UID at 0x1fff7a10 (pc=0x080601c2)
CAN1: left initialisation mode (MCR=0x00000064, BTR=0x03290005)
UART4:  enabled by the firmware (CR1=0x212c: UE TE RE RXNEIE)
USART3: enabled by the firmware (CR1=0x212c: UE TE RE RXNEIE)
```

`CR1=0x212c` is `UE|TE|RE|RXNEIE|PEIE` — exactly what ChibiOS'
`usart_init()` writes, and `BTR=0x03290005` decodes to the 500 kbit/s bit timing
`appconf_default.h` asks for. These are the firmware's own register writes read
back out of the models, not host bookkeeping.

*Alternative ruled out:* "a catch-all is making anything look initialised."
A catch-all hides a wrong base address perfectly (playbook §2.137), so each of
these came from a **named model at a specific page**, and each one was added
only after the firmware demonstrably wedged without it (the CAN handshake at
`pc=0x0800fc46`, the clock read-back loop, the die UID abort).

### M3 — the scheduler runs

Over 100 000 SysTick exceptions delivered into the firmware's own
`SysTick_Handler` at `0x0800f8c0` (which is what vector 15 points at, i.e. the
real handler and not a weak stub), interleaved with ChibiOS' own `PendSV`
context switches (`inject_irq(-2): exc 14 @ 0x800e331`) requested by the kernel
itself through `SCB->ICSR`. Threads are created and scheduled: the `uartcomm
proc` thread wakes on the serial event, drains the port and answers.

*Alternative ruled out:* "ticking is not dispatching" (playbook §2.29) — a clock
can advance while every task stays blocked. Here the proof of dispatch is that a
**different thread's work product comes out of the UART**: `main()` is blocked in
its own loop, and the COMM replies are composed by the `uartcomm proc` thread.
No reply is possible without a real context switch.

### M4 — a real protocol round-trip

Request (host → USART3):

```
02 01 00 00 00 03            # COMM_FW_VERSION, framed + CRC'd by vesc_comm.py
```

Reply (firmware → USART3, read back out of `USART3->DR`):

```
02 24 00 07 01 31 30 30 5f 32 35 30 00
52 45 48 4f 53 54 52 59 56 45 53 43
00 01 00 00 01 00 00 00 00 00 00 00 00
0e aa 03
```

**All 41 bytes are identical to the prediction recorded in `PROVENANCE.md`
before this device had ever been booted** (that prediction is this repository's
first commit; the build and the models are the second — the two commits are kept
separate on purpose, because squashing them would destroy the evidence that the
prediction preceded the run).

The trailing `0e aa` is the CCITT CRC the firmware computed with its own
`crc16_tab` in flash; `tests/test_structure.py` asserts that table appears
verbatim in the image and matches an independently generated one.

`COMM_GET_MCCONF` likewise returns the firmware's own 489-byte serialized
`mc_configuration`, opening `0e 93 07 41 0d` — packet id, then
`MCCONF_SIGNATURE` (`confgenerator.h:11`, 2466726157) — followed by
`01 00 02 00` (`pwm_mode`, `comm_mode`, `motor_type = MOTOR_TYPE_FOC`,
`sensor_mode`) and `42 70 00 00` = 60.0 A, the live `l_current_max`.

*Alternative ruled out:* "the host synthesised it." The host sends six bytes; the
41 that come back carry a length byte, a hardware name, a firmware version, a
field layout and a CRC that this side never computed for the outbound direction.
The prediction was derived from the source before the run and matched exactly.

## The attack — verified live

`attack.py` sends **one unauthenticated `COMM_SET_MCCONF_TEMP` packet** that moves
two of the motor's protection limits, then proves it with a second, independent
`COMM_GET_MCCONF`. Verbatim from a live run (`RESULT: {"booted": true,
"landed": true}`, exit 0):

```
before        l_in_current_max = 250.0   l_current_max_scale = 1.0
attack frame  02 2d 30 00 00 01 00 3f800000 3dcccccd c7c35000 47c35000
                    3ba3d70a 3f733333 c9b71b00 49b71b00 c3480000 43960000 d6b2 03
set ack       02 01 30 36 53 03                     <- id 0x30 = COMM_SET_MCCONF_TEMP
after         l_in_current_max = 300.0   l_current_max_scale = 0.1
              read back as 43960000 (300.0f) and 03e8 (1000/10000 = 0.10)
```

* **`l_in_current_max` 250 A -> 300 A** — the battery-current ceiling. Raising it
  is how you push a pack past its safe discharge rate.
* **`l_current_max_scale` 1.00 -> 0.10** — a 90 % cut in available motor torque
  *and* regenerative braking. On a moving vehicle that is a remote, instant loss
  of drive and brake.

Both numbers come out of the firmware's own `confgenerator_serialize_mcconf()`
output, inside a frame the firmware's own `packet.c` length-prefixed and CRC'd.

### Negative controls (same harness, same connection, same run)

| control | expected (from the source) | observed |
|---|---|---|
| **the attack frame with one CRC byte flipped** | `try_decode_packet()` drops it: no reply, no change | no reply; `l_in_current_max` 250.0, scale 1.0 — unchanged |
| **the same command asking for 5000 A and scale 9.0** | `utils_truncate_number()` clamps to this board's `HW_LIM_CURRENT_IN` (300.0) and to the 0.0–1.0 scale range | acked (id 48); read back **300.0** and **1.0** — clamped, not stored |
| *(restore)* | the harness puts the device back to its own values before the attack | 250.0 / 1.0 |

The bad-CRC control is the important one: it is the attack frame **byte for
byte**, differing only in the checksum, so if it had "worked" the oracle would be
measuring this harness rather than the firmware. The clamp control is the
complement — it proves the firmware *discriminates* rather than storing whatever
it is handed, which is what makes the accepted 300.0/0.10 meaningful.

`landed` is true only if the read-back shows the attacker's values **and** both
controls behaved as the firmware's source says they must.

The run also opens a `COMM_TERMINAL_CMD` session first — unauthenticated in its
own right — and the firmware answers `"-> fault \n"` from its own
`terminal_process_string()`.

> **Why not `COMM_SET_MCCONF`?** It reaches the same limits, but it also calls
> `conf_general_store_mc_configuration()`, which writes the whole
> `mc_configuration` through ST's page-swapping EEPROM emulation — several
> hundred `EE_WriteVariable` calls, each linearly scanning a 16 KiB sector, plus
> `mc_interface_wait_for_motor_release_both(3.0)`, a 30 000-tick RTOS wait. Under
> emulation that is minutes per packet (profiled: the hot address was
> ChibiOS' `_port_switch`, i.e. the machine was healthy and context-switching,
> not stuck). `COMM_SET_MCCONF_TEMP` with its `store` flag clear reaches
> `mc_interface_get_configuration()` directly and is instantaneous. Both are
> unauthenticated; the fast one is the one the attack uses.

> **A `commands_printf` finding, worth knowing.** VESC composes its "Could not
> set mcconf due to wrong signature" warning unconditionally, but
> `commands_printf()` writes through `send_func_blocking`, and **nothing sets
> that except the blocking command group** (`commands.c:1687-1715`). Until a
> `COMM_TERMINAL_CMD` has been sent on that connection, every warning the
> firmware prints is built and then dropped with no error at all.

## Known limitations — stated plainly

* **Guest time is monotonic but not calibrated.** SysTick is delivered from
  ChibiOS' idle thread rather than by a real 10 kHz oscillator, TIM5's counter
  advances one count per read, and `chSysPolledDelayX()` (which spins on
  `DWT->CYCCNT`, a register the backend cannot make advance) returns
  immediately. Ordering and relative durations follow the firmware's own
  arithmetic; wall-clock rates do not. **This rehost cannot be used to measure
  real-time behaviour.**
* **There is no motor and no analogue front end.** The ADC, the current shunts,
  the input-voltage divider and the phase-voltage sensing are unmodelled, so
  `COMM_GET_VALUES` reports whatever the firmware computes from a silent front
  end, the FOC control loop is not driven by its ADC interrupt, and the device
  will not spin anything. The configuration surface — which is what the attack
  targets — is fully live; the control loop is not.
* **CAN has no peer.** The controller is modelled far enough to complete
  ChibiOS' `can_lld_start` handshake, and `comm_can_init()` runs, but nothing is
  attached to the bus, so VESC's CAN COMM channel and its multi-ESC forwarding
  are present and idle.
* **USB is not enumerated.** `comm_usb_init()` runs; nothing plugs in. The
  honest model of this board is one with an empty USB port.
* **The emulated EEPROM is real but slow.** VESC stores its configuration
  through ST's page-swapping EEPROM emulation over two 16 KiB flash sectors, and
  a full `mc_configuration` store is several hundred `EE_WriteVariable` calls,
  each of which linearly scans the page. It works — the boot's own
  `conf_general_store_backup_data()` completes — but a `COMM_SET_MCCONF` costs
  minutes of wall clock, and the attack's timeouts are sized for that.
* **The die serial is synthetic.** `0x1FFF7A10` answers the ASCII
  `REHOSTRYVESC`. There is no honest way to recover a real die's UID from an
  image; the value is fixed, documented and deliberately not zeroes.
* **`stop_pwm_hw()` dereferences NULL on a cold boot** — see the trap below.
  This rehost maps the STM32's boot-remap alias so the read succeeds, exactly as
  it does on silicon.

## Core changes

**None.** This device runs unmodified against the installed `halucinator@dev`
(`ee267d8`). Every model and seam lives in this package.

## Traps this device paid for

1. **VESC has a genuine NULL-pointer read on a cold first boot, and it survives
   only because the STM32 aliases flash at address 0.** With the emulated EEPROM
   erased, `conf_general_init()` ends in `conf_general_store_backup_data()`,
   which calls `mc_interface_release_motor_override_both()` *before*
   `mc_interface_init()` has run. `m_motor_1` is still zeroed `.bss`, so
   `motor_type` reads `MOTOR_TYPE_BLDC` (0) and the call reaches `mcpwm.c`'s
   `stop_pwm_hw()`, whose last statement is
   `set_switching_frequency(conf->m_bldc_f_sw_max)` with the file-static `conf`
   still NULL — a read of address `0x268`. On hardware the boot-remap region
   `0x00000000-0x000FFFFF` mirrors main flash, so it reads a garbage float and
   moves on. Map that alias or the rehost dies at `0x080550e8` with
   `UC_ERR_READ_UNMAPPED`, which reads like a rehost bug and is not one.

2. **`NVIC_SystemReset()` is on VESC's normal first-boot path.**
   `flash_helper_verify_flash_memory()` finds the app-CRC slot erased, programs
   the CRC, and reboots so it takes effect. unicorn implements no SYSRESETREQ, so
   that is a permanent silent `b .` (playbook §2.54). There are three such sites
   in this build — including the `COMM_REBOOT` case inside
   `commands_process_packet()`, i.e. one an attacker can reach — and
   `NVIC_SystemReset` is `__STATIC_INLINE` so there is no symbol to key on. The
   extractor **scans** for the `dsb sy ; b .` idiom with the `0x05FA0004` AIRCR
   literal nearby and emits synthetic `sysresetreq_spin_N` symbols; a test
   asserts every one is intercepted.

3. **`DWT->CYCCNT` is the other never-advancing clock.** ChibiOS'
   `chSysPolledDelayX()` spins on it, and the PPB is backend-owned plain memory,
   so the loop is unsatisfiable — 12 500 000 samples at four addresses per
   window, forever, entered from USB bring-up. It cannot be modelled as a
   peripheral without taking over the whole 1 MiB PPB including `SCB->ICSR`,
   which ChibiOS' exception epilogue needs; answer it at the function seam.

4. **A timer's `CNT` must free-run, and it must wrap at `ARR`.** VESC's
   `timer_sleep()` blocks directly on `TIM5->CNT`. Advancing the counter on every
   read costs nothing and is close to physically right (eight instructions per
   loop ≈ 48 ns at 168 MHz; one TIM5 count is 71 ns) — but the same model covers
   TIM1/TIM8, whose counters the firmware reads to find its position in the PWM
   cycle, so the counter must wrap at `ARR` rather than run away.

5. **A "ready" bit that is always ready breaks the opposite wait, again.**
   `can_lld_start` waits for `MSR.INAK` to SET and then to CLEAR; the catch-all's
   all-ones breaker can only ever satisfy one of them.

6. **The backend's per-exception INFO logging is a real cost on an
   interrupt-pumped device.** With `halucinator.backends.unicorn_backend` at
   INFO, this device wrote 463 KB/s and 3.5 million lines in eleven minutes. The
   record that actually matters (`vector table slot … is zero or unmapped`) is a
   WARNING, so the shipped `logging.cfg` sets that logger to WARNING and says how
   to raise it.
