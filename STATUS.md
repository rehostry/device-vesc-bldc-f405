<!-- rehostry-census: milestone=M7 landed=true verdict=M4-OK verified=2026-09-08 method=live-run -->
<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Status — device-vesc-bldc-f405

**Milestone: M7** (2026-09-08) — a real VESC COMM protocol round-trip over
USART3, matching a byte-exact prediction made before the first boot; the same
byte-identical `COMM_GET_MCCONF` answered differently at six attacker-installed
states; and ten classes of malformed input each answered as `comm/packet.c`
says they must, with the seam proven alive after every one.

**M5 and M8 are UNDEFINED**, not failed: this device drives one link (the
USART3 COMM seam) to one peer, so RULES §1a leaves both undefined and the
ladder deliberately has no branch for either.

Firmware: `vedderb/bldc` @ `e4db57a8d90747091a4ea98c381fe3efc83a8722`, hardware
target `100_250` (Trampa VESC 100/250, STM32F405RG, ChibiOS 3.0.5), built from
source — see `FIRMWARE.md`. No firmware bytes are committed.

## 2026-09-08 — M4 -> M7, and the corpse that had to be killed first

Seven arms, serial, each on its own bridge/rx/tx port triple.
`PREDICTIONS-M6-M7.md` was committed **before** the first graded arm
(`bee3100`), and every prediction in it held.

### The previous lane found the corpse, and both halves of its diagnosis are wrong

A lane on 2026-09-08 ran one probe session here and stopped, reporting that
**11 of 14 malformed frames left the next known-good `COMM_FW_VERSION` request
unanswered**, and that this was *"the decoder's `rx_timeout` versus its own
buffered reader, and not distinguishable from what it measured."* Stopping was
right. The diagnosis is refutable and is refuted:

* **There is no `rx_timeout` and no `packet_timerfunc`** anywhere in the pinned
  `comm/packet.c` or `comm/packet.h`. That mechanism does not exist in this
  firmware.
* **The known-good round trip costs 0.01–0.02 s** on this rehost (five
  consecutive, measured), so a 6 s `alive()` timeout was never the constraint
  either.

The real mechanism is `packet_process_byte`'s own arithmetic:

```c
if (state->bytes_left > 1) { state->bytes_left--; return; }        // swallow, no decode
if (data_len >= PACKET_BUFFER_LEN) { write = read = 0; bytes_left = 0; }  // the ONLY reset
```

A 16-bit-length header declaring 255 bytes sets `bytes_left` to 258, and the
decoder then **eats the next 255 bytes without attempting a decode at all** —
so every known-good request inside that window reads as "the firmware ignored
this", and no timer ever ends it. The only unconditional escape is the overflow
reset, at `PACKET_BUFFER_LEN` = 520 bytes. Measured, on the same class, in the
same run:

```
three plain known-good retries, 30 s each   ->  DEAD, 3 of 3
then 544 bytes of filler, then one retry    ->  ALIVE in 0.03 s
```

`VescScenario.resync()` is that sequence — one cheap retry, then the flush the
decoder's own overflow reset requires — it runs after **every** graded class,
and `m7_ok` is false unless every one came back alive. On the graded set it
never has to reach for the flush: **10 of 10 classes recover on the first plain
retry, in 0.51 s each**, which is the measurement that says these ten classes
are not corpses.

⚠ **What I refused to grade.** The 16-bit-length `254 refused / 255 accepted`
bracket the previous lane handed over is real on its refused side and costs
**minutes** on its accepted side, and its recovery time depends on our own
`HAL_IRQ_CHUNK` and on the USART3 model's byte-delivery rate rather than on the
firmware. A behaviour I cannot attribute to the guest is not adversarial
evidence, so it is recorded here and **nothing graded sits inside it**. The
same one-unit shape was available for six bytes and is graded instead:

```
02 00 …   8-bit form declaring length 0   ->  no reply, seam alive     (refused, 0.02 s)
02 01 …   8-bit form declaring length 1   ->  0007013130305f323530…    (answered, 0.02 s)
```

### A wrong model this row has been carrying, found by a twin

The M7 phase minted `l_current_max_scale = 0.5275`, predicted the firmware
would report **5275**, and it reported **5274**. `util/buffer.c` is

```c
buffer_append_int16(buffer, (int16_t)(number * scale), index);
```

— `(int16_t)` is a C cast, so it **truncates toward zero**. This package's
`vesc_comm.float16` used `round()` and its docstring said rounding. The two
disagree whenever the binary32 nearest `n/10000` sits just below it:
**537 of the 9000 values** `n/10000` for n in 500..9500, about six per cent.
`binary32(0.5275) * 10000` computed in binary32 is `5274.999512`.

That is what a near-miss twin is for. A class with no twin would have reported
ten of ten and the model would still be wrong — and it survived every previous
run of this device because the M4 attack's own `0.10` is one of the values
where truncation and rounding agree.

### M6 — the same request, six states, three witnesses

The request is byte-identical every round (`COMM_GET_MCCONF`). What changes is
the configuration the attacker installs, and the sides alternate so neither
direction can be absent by luck:

```
round over  minted scale  minted l_in_current  read back            guest counter
  0   no    0.6284        101.85 A             188c / 42cbb333      7 accepted of 7+1 sent
  1   YES   1.2796        316.00 A             2710 / 43960000      6 accepted of 6+2 sent
  2   no    0.8859        292.51 A             229b / 43924148      5 accepted of 5+1 sent
  3   YES   1.6646        444.00 A             2710 / 43960000      7 accepted of 7+2 sent
  4   no    0.4708         94.45 A             1264 / 42bce666      7 accepted of 7+0 sent
  5   YES   1.5236        661.00 A             2710 / 43960000      6 accepted of 6+0 sent
```

* **witness A** — the firmware's own serialized `mc_configuration`. On the
  accepting rounds both fields carry the mint; on the clamping rounds
  `l_in_current_max` predicts the **constant** `43960000` (300.0 A) whatever we
  mint, so it is only half a witness there — which is why it is paired with the
  scale, minted inside the accepted range on the same round and still moving.
* **witness B** — `COMM_GET_MCCONF_TEMP` (id 91), a *different* handler with a
  *different* serializer (`float32_auto`, not the int16 the full configuration
  uses), reporting the same state: 0.62840, 1.00000, 0.88590, 1.00000,
  0.47080, 1.00000. One wrong offset model cannot satisfy both.
* **witness C** — a **guest counter against a per-run mint, negative in some
  rounds**. `commands_process_packet` is reached exactly once per packet the
  firmware's own `try_decode_packet` accepted, and this device's boot-trace
  handler now logs every arrival. Each round mints `k` well-formed and `j`
  malformed frames; the guest's count rose by exactly `k` in **6 of 6** rounds,
  so the delta against what we put on the wire is `−j` — −1, −2, −1, −2, 0, 0.
  A host cannot produce that number without reimplementing `packet.c`.

### M7 — ten classes, three distinct answers, none of them graded on silence

Every framing class carries a real `COMM_SET_MCCONF_TEMP` write of a per-run
minted value, so the witness of the refusal is **the limit the firmware
declined to move**, not the silence:

```
class               frame                                    answer                    twin (must LAND)
hdr_len_zero        8-bit form declaring length 0            silent, no write          the same payload framed correctly
hdr_len_over        declared length = real + 1               silent, no write          "
hdr_len_under       declared length = real - 1               silent, no write          "
start_byte_24bit    start byte 4 (compiled out at 512)       silent, no write          "
stop_byte_wrong     stop byte 4                              silent, no write          "
crc_one_bit         ONE minted bit of the CRC-16 flipped     silent, no write          "
truncated           the last two bytes dropped               silent, no write          "
terminal_unknown    COMM_TERMINAL_CMD + a minted nonce       renders the nonce         `fault` -> FAULT_CODE_NONE
clamp_in_current    l_in_current_max = 43960001 (one ULP)    stored as 43960000        4395ffff stored unchanged
clamp_scale         l_current_max_scale minted above 1.0     stored as 2710            the minted value stored
```

**The rendered witness.** `terminal_process_string()` prints
`Invalid command: %s\ntype help to list all available commands\n`. That format
string is at image offset `0x726e1` and appears **once**; the *rendered* line,
carrying this run's `zz%08x` nonce, appears **zero** times in the image and
zero times in this package. Measured:

```
-> zz1c642e0c
Invalid command: zz1c642e0c
type help to list all available commands
```

**The twin is `fault`, and that choice was checked before it was used.** A twin
whose own answer is a refusal string would leave a witness standing in the
valid-only control arm. `fault` answers `FAULT_CODE_NONE` and contains none.
(The "one byte shorter" heuristic does not apply here: this console uses
`strcmp`, not a unique-abbreviation match, so `faul` is simply another unknown
command — which is a fact about this firmware, not a general rule.)

**The clamp bracket is ONE binary32 step wide**, and it is graded on the raw
bytes the firmware serialized rather than on the three-decimal rounding the
report uses — `round(299.99997, 3)` is `300.0`, so the rounded form cannot tell
the two sides apart at all:

```
l_in_current_max = 43960001 (300.00003)  ->  stored 43960000    CLAMPED
l_in_current_max = 4395ffff (299.99997)  ->  stored 4395ffff    UNCHANGED
```

⚠ `math.nextafter(300.0, 1e9)` steps a **double**; packed back to binary32 it
lands on 300.0 again, so a class built that way would have sent the limit
itself and passed while measuring nothing. Caught by this row's own tests
before the first arm ran.

**Three witness counters, deliberately in separate fields** — a rendered
string, a limit the firmware declined to move, and a limit it substituted are
different kinds of thing, and a control that has to drive a number to zero must
not be scored against a number we can pad.

### The arms, with both sides of every control

```
arm                        milestone  guard     m6                m7 classes  twins   rendered  state  clamp  reply_digest
default (seeded)           M7         M4-OK     6/6, ctr 6/6      10/10       10/10   1         7      2      0fe32b452605f752
default (unseeded)         M7         M4-OK     6/6, ctr 6/6      10/10       10/10   1         7      2      f1538f0122bd66b2
--falsify m7-valid-only    M6         M4-OK     6/6, ctr 6/6      0/10        10/10   0         0      0      c98fe2272b577b8c
--falsify m7-mispredict    M6         M4-OK     6/6, ctr 6/6      0/10        10/10   1         7      2      0fe32b452605f752
--falsify m6-freeze        M7         M4-OK     1/6, ok FALSE     10/10       10/10   1         7      2      96b70146f54af965
HAL_SEAM_CONTROL=1         M3         WALL-M3   unobservable      unobservable
VESC_BOOT_TIMEOUT=14       M2         WALL-M2   unobservable      unobservable
```

Read the three rows that decide it:

* **valid-only** replaces every malformed probe with its own valid twin. All
  **three** witness counters go to **zero** while the twins stay at **10/10**
  and the seam answers throughout. That is the arm the rung is worthless
  without, and it is a measurement, not an argument about the code.
* **mispredict** is the seeded partner of the seeded default, and its
  `reply_digest` is **byte-identical** — `0fe32b452605f752` on both. The
  firmware said exactly the same thing; only what the host expected changed.
  It rotates each class onto the next **distinct** answer, never onto the next
  class, because seven of the ten share `silent-nowrite` and a next-class
  rotation would leave those seven predicting what they already predict.
* **m6-freeze** collapses M6 to 1 of 6 while M4 and M7 are untouched, which is
  what shows the two new rungs are decided by separate terms.

Both control arms report `unobservable` rather than a scored zero.

### The ladder — three assignments and two early returns, and a false floor

The old grader was:

```python
result = {..., "milestone": "M0", ...}
if not sc.boot(stage):
    milestone = "ERROR" if gated else ("M0" if faulted else "M1")
    return result
result["milestone"] = "M3"          # boot() returned True
if result["landed"]: result["milestone"] = "M4"
```

Enumerated over the seven booleans the repaired ladder takes
(`tools/enumerate_ladder.py`):

```
attack.py BEFORE (transcription), 128 assignments
  ERROR 64  M0 16  M1 16  M3 16  M4 16     PRINTABLE {ERROR,M0,M1,M3,M4}
attack._ladder AFTER,             128 assignments
  ERROR 64  M0 32  M1 16  M2 8  M3 4  M4 1  M6 1  M7 2
  PRINTABLE {ERROR,M0,M1,M2,M3,M4,M6,M7}   WRITTEN == PRINTABLE by ast, no dead branch
  11 of 128 assignments move UP   (w91.1's DOWNWARD false floor)
  24 of 128 move DOWN             (the old grader printed M3/M4 for runs whose
                                   guest never cleared the work gate)
```

⚠ **The floor is proved to have moved by a CONTROL ARM, not by the happy
path.** `boot()` returns False when the firmware has not enabled USART3 inside
the timeout, and that path could only ever answer M0 or M1 — so a guest that
ran ChibiOS' `crt0`, reached `main()` and printed its own
`BOOT: conf_general_init` / `BOOT: mc_interface_init` trace (M2 by the fleet's
own definition) reported **M1**, with the evidence sitting in its own log. The
`VESC_BOOT_TIMEOUT=14` arm is exactly that run, and it now prints:

```
"own_init": true, "seam_up": false, "milestone": "M2",
"error": "the firmware never enabled USART3 within 14 s -- and the gates PASSED
          (marker=True, 13.89 CPU seconds burned by the child), so this is the
          device, not the install"
```

`_ladder` is pure, is called from **one** place, and that call is in
`run_attack`'s `finally` block, so every exit — the refusal, both gate
failures, an exception and the graded path — is graded by the same function on
the same facts. There is **no M5 and no M8 branch**, deliberately.

`tools/mutate_checks.py` plants **eighteen** defects — including a dead *and* a
live `M5` branch, the collapsed floor, a chained M7, a rounding `float16`, a
short flush and a valid-only arm that sends the malformed frame anyway — and
requires every one to make the suite fail: **18 of 18**. Three of those
mutations are refutations of my own code found before it ran, and one is a
refutation of my own *test*, which passed on a version that had dropped the
thing it was written for.

---

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

## Adversarial verification

Every claim above was re-tested against a deliberate attempt to break it.

| check | result |
|---|---|
| **Cold re-run, 3×**, each a fresh process from a fresh boot | `RESULT: {"booted": true, "landed": true}`, exit 0, **3/3**, with byte-identical evidence each time (`readback_in_current_max_bytes` `43960000`, `readback_current_max_scale_bytes` `03e8`, ack frame `020130365303`) |
| **Polluted environment** — `HALUCINATOR_SRC=/nonexistent/x PYTHONPATH=/nonexistent/x` | same result; `spawn_env()` strips both, and `tests/test_structure.py` asserts it |
| **Negative control 1** (attack frame, one CRC byte flipped) | no reply, configuration unchanged — the firmware dropped it |
| **Negative control 2** (5000 A / scale 9.0 through the same command) | acked but **clamped** to 300.0 / 1.0 — the firmware discriminates |
| **Static prediction** written before the first boot | matched, 41/41 bytes including the CRC |
| **Structural tests** (no emulator) | 20 passed — config/image agreement, every intercept symbol resolves, every scanned reset site is intercepted, no overlapping or misaligned regions, `crc16_tab` present verbatim in the image, and CRC/float encodings checked against independent implementations *and* against a plausible wrong constant that must disagree |

Reproduce:

```bash
rehostry-vesc-bldc-f405-attack                       # expect RESULT: {"booted": true, "landed": true}
HALUCINATOR_SRC=/nonexistent/x PYTHONPATH=/nonexistent/x rehostry-vesc-bldc-f405-attack
python3 -m pytest tests/test_structure.py -q
```


## Startup gates — telling a dead install from a dead device (2026-09-02)

`run_attack` pre-initialised its result with `"milestone": "M1"` and returned it
verbatim from `if not sc.boot(stage): return result`. Every failure inside
`boot()` — the emulator process exiting, USART3 never coming up, the bridge
refusing a connection — therefore reported **M1**, and `census_score.score()`
scored that `WALL-M1`: a *device* wall. A wrong interpreter, a missing
`halucinator`, an import error and a firmware that genuinely walls at M1 were
all recorded identically.

That mattered on this device specifically: two core-validation agents ran it
concurrently on 2026-09-01, on the same `--rx_port 6102` and the same fixed log
path. A harness that cannot separate a broken install from a dead device can
hand a core gate a false "safe to ship".

Two gates now run before anything is graded. **Both are computed, neither is an
opt-in, and neither can raise a milestone — only lower one.**

**Gate 1 — the core's own positive CPU-start marker.** `halucinator.main` logs
`Letting Unicorn Run` immediately before it enters the dispatch loop.

The marker was **not printable on this device**. `python -m halucinator.main`
runs `main.py` as `__main__`, so the marker goes to the logger `__main__`; this
device's `configs/logging.cfg` named `root`, `halucinator.main`, `HAL_LOG` and
the backend, but not `__main__`, so it inherited root's `ERROR` — and on the
cores whose CWD branch loads the file with `disable_existing_loggers=True` it is
disabled outright, where raising root's level would not help. Measured here
before the fix: a boot that reached the firmware's own USART3 driver contained
**zero** occurrences of the marker. `logging.cfg` now carries a
`[logger_mainmod]` stanza (`propagate=0` plus its own handler, so it works on
both branches); no other logger's output moved and no line prefix changed.

`logging_cfg_present()` therefore tests **printability** — the file exists *and*
names `__main__` — not mere existence. When it is false, Gate 1 reports `None`,
never `False`, so an absent marker is never read as a startup failure when the
real cause is that it could not have been printed.

**Gate 2 — a measured-work floor.** The metric is the emulator child's own CPU
seconds: model- and firmware-independent, and it measures *work*, so it does not
tighten when the box is loaded. Derived from **this device's own healthy boot**,
sampled the moment the firmware's USART3 driver enables the port:

| run | CPU s at the gate | wall s | box load |
|---|---:|---:|---:|
| A | 25.77 | 26.1 | 22.7 |
| B | 25.34 | 26.1 | 17.9 |

1.7 % apart across a 27 % swing in load — which is why the metric is CPU time
and not wall clock. **The floor is 2.0 CPU s, about 1/13 of that.** A floor is a
classifier: set it near the healthy figure and a slow-but-live boot is filed as
a dead device, which reads exactly like a device wall. The only safe direction
to be wrong in is down. The failure it must catch reads **0.00**.

Gate 2 does **not** fire when the log carries guest-fault evidence (`UC_ERR`,
`FETCH-DERAIL`, a unicorn `UcError`). Only the core's own guest-fault path can
emit those, so their presence proves the install works and the failure belongs
to the firmware — a firmware that faults after 1.5 CPU seconds would otherwise
be filed as a broken install, which is exactly the classifier failure a work
floor must not commit.

**The swallowed reason is now in the RESULT.** `note="... (see <path>)"` is
gone; failed runs carry `error`, `error_detail`, `child_returncode` and
`child_output_tail`, and `main()` prints the tail to stderr.

`run_attack` also now honours `HAL_PY`. It passed `sys.executable` explicitly,
which overrode the env var and made the one control arm that reproduces a broken
install unrunnable against this harness.

### The three arms, all run live on 2026-09-02

| arm | how | RESULT (verbatim) | `census_score.score()` |
|---|---|---|---|
| healthy | `VESC_UART_PORT=31430` | `{"booted": true, "landed": true, "milestone": "M4", "vesc_packet_round_trip": true, "seam_control": false, "gate1_cpu_started": true, "gate2_child_cpu_s": 52.32, "gate2_floor_cpu_s": 2.0, "logging_cfg_present": true}` | `M4-OK` |
| broken install | `HAL_PY=<a venv with no halucinator>` | `{"booted": false, "landed": false, "milestone": "ERROR", ..., "gate1_cpu_started": false, "gate2_child_cpu_s": 0.0, "child_returncode": 1, "error_detail": "... ModuleNotFoundError: No module named 'halucinator'"}` | `WALL` |
| seam control | `HAL_SEAM_CONTROL=1` | unchanged — the knob still flips `landed` | `WALL-*` |

The healthy arm reported `gate1 marker=True … gate2 child cpu=27.73s (floor
2.00)` at the gate and 52.32 CPU s by the end. **The milestone did not move:
M4 before, M4 after.** The broken-install arm moved from `WALL-M1` (a device
wall) to `WALL` on `milestone: "ERROR"` — no rung at all, which is correct,
because nothing was measured.

## Log path (2026-09-02)

`self.log` was `<log_dir>/vesc_bldc_f405_attack.log` — a constant. Two
concurrent runs open it `"w"`, interleave and truncate, and every log-derived
field in *both* results then describes two guests. It is now
`vesc_bldc_f405_attack.<pid>.log`: unique per run, still findable by name, and
the stem is unchanged so `vesc_bldc_f405_attack.*.log` still globs.
