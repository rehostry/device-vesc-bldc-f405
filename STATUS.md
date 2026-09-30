<!-- rehostry-census: milestone=M7 landed=true verdict=M4-OK verified=2026-09-30 method=live-run n=none core=hal-b0818-on-9bde2c0@60619b7e faults=0 fault_before_round_trip=false fault_after_round_trip=false note=NO-ENTRY-WAS-REMOVED-this-row-had-NO-M8-denominator-at-all-and-this-session-CREATES-one-so-the-reported-coverage-is-WORSE-than-the-row-s-previous-silence-implied-which-is-the-correct-direction;M8-WAS-RECORDED-UNDEFINED-ON-THE-WRONG-GROUND-the-old-reason-was-one-link-one-peer-which-answers-M5-not-M8-RULES-1b-separates-them-and-the-2026-09-29-ruling-makes-a-command-inside-one-framing-layer-an-ENTRY-naming-this-firmware-s-own-sibling-vesc-bms-16-COMM-packets-over-ONE-CAN-link-as-the-precedent;M5-STAYS-UNDEFINED-one-USART3-link-one-peer;M8-IS-DEFINED-AND-UNMET-denominator-52;WHAT-n-WOULD-COUNT-52-TERMINAL-COMMANDS-the-firmware-publishes-in-its-OWN-help-menu-NOT-interfaces-and-NOT-COMM-packet-ids;n-IS-none-BECAUSE-THE-NUMERATOR-IS-NOT-FULLY-MEASURED-49-driven-2-recognised-but-silent-1-UNDETERMINED-rebootwdt-so-the-bound-is-49-to-50-of-52-and-per-the-2026-09-30-ruling-a-bounded-numerator-publishes-n-none-never-a-fraction;INVENTORY-DERIVED-LIVE-FROM-THE-GUEST-S-OWN-BYTES-IN-EVERY-BOOT-one-COMM_TERMINAL_CMD-help-and-every-COMM_PRINT-frame-parsed-BY-SHAPE-52-command-shaped-lines-60-description-shaped-0-unclassifiable-summing-exactly-to-the-112-line-body-and-51-of-52-boots-re-derived-52-independently;COMPLETENESS-IS-STRUCTURAL-NOT-NUMERIC-help-ends-with-commands_printf-space-so-an-intact-menu-s-last-line-is-exactly-one-space-and-a-parse-without-that-sentinel-VOIDS-rather-than-reporting-a-smaller-denominator-because-a-count-cannot-detect-its-own-truncation-which-is-the-26-vs-34-lesson-the-sibling-paid-for;GUARD-IS-DIAGONAL-AND-PINNED-TO-RAW-BYTES-52-token-to-full-declaration-line-PAIRS-plus-help_sha256-625878ee-and-pairs_sha256-611e20fa-so-a-command-that-kept-its-name-and-changed-its-ARITY-breaks-it-and-a-mismatch-EITHER-WAY-voids;COULD-A-PASS-HAPPEN-WITH-THE-FIRMWARE-ASLEEP-NO-arm-B-is-the-answer-the-guest-must-RENDER-a-nonce-the-host-minted-seconds-earlier-inside-its-own-Invalid-command-line-and-both-strings-must-be-on-ONE-line-because-the-terminal-ECHOES-the-command-so-checking-them-separately-was-satisfied-by-the-echo-a-defect-caught-on-the-smoke-run;KNOB-BINDS-VESC_M8_TWIN_ONLY=1-gives-6-of-6-sampled-entries-driven-false-refused_by_firmware-with-the-inventory-STILL-52-and-the-guard-STILL-ok-which-is-pre-registered-PREDICTION-8-confirmed;HAL_SEAM_CONTROL-CANNOT-SERVE-AS-THE-NUMERATOR-KNOB-and-that-was-pre-registered-it-closes-the-seam-the-menu-is-read-over-so-it-voids-the-denominator-too;MY-PREDICTION-6-WAS-FALSIFIED-I-predicted-driven-in-15-to-40-and-measured-49-the-range-is-NOT-widened-the-error-was-conceptual-I-predicted-coverage-from-what-the-host-side-code-already-NAMES-when-the-sweep-drives-every-entry-DIRECTLY;ONE-FRESH-BOOT-PER-ENTRY-ENTRY-FIRST-52-of-52-because-stop-rebootwdt-and-foc_openloop-change-the-machine-a-later-entry-would-be-graded-against;MY-OWN-DEFECTS-a-late-async-print-from-measure_res_ind-was-consumed-by-arm-B-and-desynchronised-every-later-exchange-fixed-by-a-settle-and-re-run-with-4-driven-controls-unchanged-AND-my-aggregator-read-a-key-that-does-not-exist-and-printed-a-FALSE-VOID;THREE-CHECKS-ALL-0-check1-verdict-M4-OK-check2-0-check3-entitled-M7-credited-M7;firmware-UNCHANGED-sha256-ea6e96f9-before-and-after-all-59-chains-and-it-is-NOT-the-sibling-s-image-vesc-bms-is-f72bb1c4-and-85240-bytes-against-this-row-s-1048576 -->
<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Status — device-vesc-bldc-f405

**Milestone: M7** (2026-09-08) — a real VESC COMM protocol round-trip over
USART3, matching a byte-exact prediction made before the first boot; the same
byte-identical `COMM_GET_MCCONF` answered differently at six attacker-installed
states; and ten classes of malformed input each answered as `comm/packet.c`
says they must, with the seam proven alive after every one.

**M5 is UNDEFINED**, not failed: this device drives one link (the USART3 COMM
seam) to one peer, so RULES §1a leaves M5 undefined and the ladder deliberately
has no branch for it.

⚠ **This block used to say the same about M8, and that was WRONG — corrected
2026-09-30.** One link answers **M5**; RULES §1b makes **M8** a question about
*coverage of everything the image declares*, and the 2026-09-29 ruling makes a
command inside one framing layer an entry. **M8 is DEFINED here and UNMET against
a 52-command inventory the firmware publishes itself** — see the 2026-09-30
section below. The ladder still has no `M8` branch, and that is now a consequence
of parity being a fraction rather than of M8 being undefined.

Firmware: `vedderb/bldc` @ `e4db57a8d90747091a4ea98c381fe3efc83a8722`, hardware
target `100_250` (Trampa VESC 100/250, STM32F405RG, ChibiOS 3.0.5), built from
source — see `FIRMWARE.md`. No firmware bytes are committed.

## 2026-09-30 — M8 is DEFINED here, and UNMET: the 52 commands the firmware publishes itself

**No entry was removed. This row had no M8 denominator at all; this session
creates one, and the coverage it reports is worse than the row's previous silence
implied.** RULES §1a calls raising parity by shrinking a denominator the cardinal
sin, so that is the first thing stated.

### The old reason for "M8 UNDEFINED" answered the wrong question

This file used to say *"M5 and M8 are UNDEFINED, not failed: this device drives
one link (the USART3 COMM seam) to one peer."* **The M5 half is correct and
stands.** The M8 half is not: RULES §1b separates independence (M5) from coverage
(M8), and the 2026-09-29 ruling makes *a command inside one framing layer* an
entry when the firmware declares it — naming **this firmware's own sibling** as
the precedent, *"`vesc-bms` grades 16 COMM packets over ONE CAN link."*

⚠ **The sibling's image is NOT this image, and no constant was transferred.**

| row | image | sha256 | size |
|---|---|---|---|
| `device-vesc-bldc-f405` | `configs/vesc.bin` | `ea6e96f9c282f93f…` | 1 048 576 |
| `device-vesc-bms` | `configs/vesc_bms.bin` | `f72bb1c48eb90491…` | 85 240 |

Different builds, different silicon (STM32F405/ChibiOS against an STM32L4), and
different inventories — 52 here against 16 there. They are **two independent
observations**, so the byte-identical-images ruling does not apply and neither row
may be cited as corroboration for the other.

### The inventory: 52, from the guest's own bytes, in every boot

One `COMM_TERMINAL_CMD "help"` over USART3, and every `COMM_PRINT` frame the
firmware emits in reply — 115 lines. Parsed **by shape**, never grepped out of the
image (a string census is what pooled literals defeat):

| shape | count |
|---|---|
| preamble `Valid commands are:` | 1 |
| **command-shaped** (no leading space) | **52** |
| description-shaped (two leading spaces) | 60 |
| unclassifiable | **0** |
| sentinel (a single space) | 1 |

The three body classes sum **exactly** to the 112-line body, so no line is
unaccounted for, and **51 of the 52 graded boots re-derived 52 independently**.

⭐ **The completeness witness is structural, not numeric.** `help` ends with
`commands_printf(" ")`, so an intact menu's last line is **exactly one space**. A
count cannot detect its own truncation — that is the lesson the sibling paid for
when it relayed **26** CRC-valid packets against a **34**-entry menu and lost 7 of
16 names, *"true and incomplete"*, because the short path carries no CRC at all.
Here a parse whose last line is not `" "` **VOIDS** rather than reporting a
smaller denominator.

### What the denominator counts, and what it does not

It counts **52 terminal commands the firmware publishes in its own help menu** —
not interfaces, not COMM packet ids.

⚠ **The `COMM_PACKET_ID` switch in `commands_process_packet` is a second declared
surface on the same seam, and it is NOT counted here.** `COMM_TERMINAL_CMD` is
id 20, so all 52 arrive *inside* one member of that switch; counting both would
double-count. **A reader who counts it instead gets a larger denominator and a
worse fraction, and every number needed to re-derive that is printed here.**

### The guard: diagonal, and pinned to raw bytes

`tools/m8_inventory_guard.json` pins all **52 `(token -> full declaration line)`
pairs** (`pairs_sha256 = 611e20fa…`), the whole menu (`help_sha256 = 625878ee…`),
the preamble and the sentinel. ⚠ Pairs, not tokens: the declaration line carries
the command's **arity** (`param_detect [current] [min_rpm] [low_duty]`), so a
command that keeps its name and changes its arguments breaks the pairing. A
mismatch **either way** voids.

### Parity: `n=none`, and the bound is 49–50 of 52

| class | count | entries |
|---|---|---|
| **driven** | **49** | — |
| recognised but silent | 2 | `drv_reset_faults`, `update_pid_pos_offset` |
| **UNDETERMINED** | **1** | `rebootwdt` |

⚠ **`n=none`, not a fraction**, per the 2026-09-30 ruling: one entry is not
scoreable, so the numerator is bounded, not measured.

* **recognised but silent** is a limit of **my oracle**, not of the firmware:
  these two are accepted by `terminal_process_string` (no refusal) and print
  nothing. Counting them as driven would be an absence-witness pass.
* **`rebootwdt` is undetermined, and the reason is the honest one**: it produced
  **zero** output — no arm A, no arm B, no menu — and `seam_alive_after` was
  false. It reboots the board through the watchdog and this rehost does not
  re-establish the COMM seam afterwards, so ⭐ *the instrument dies with the
  phenomenon and correctly reports its absence.* A reader who treats an empty
  arm A as a determinate failure gets **49 of 52**; that number is printed here
  so the reading can be chosen explicitly rather than smuggled.

### Could a pass have happened with the firmware asleep? No — and arm B is why

Each entry is graded in **its own fresh boot, entry first** (52 of 52), because
`stop`, `rebootwdt` and `foc_openloop` change the machine a later entry would be
graded against, and a shared-boot sweep manufactures a false LOW parity.

* **Arm A** — a non-empty `COMM_PRINT` reply that is not the refusal. A sleeping
  guest emits nothing and arm A is false.
* **Arm B, the diagonal** — the guest must **render a nonce the host minted this
  run** inside its own `Invalid command:` line. A sleeping guest cannot; a
  recorded or replayed refusal carries a different nonce.

⚠ **Both strings must appear on ONE line, and that was a real defect.** The
terminal *echoes* the command it was given, so `-> <nonce>` already contains the
nonce, and a check that scanned the lines separately was satisfied by the echo.
Caught on this file's own smoke run and fixed before any graded arm.

### The falsification knob binds — and the obvious one could not

`VESC_M8_TWIN_ONLY=1` sends the minted nonce **in place of** the token, leaving
the inventory parse untouched: **6 of 6 sampled entries go to `driven=false`,
`refused_by_firmware`, with the inventory still 52 and the guard still `ok`.**
That is pre-registered PREDICTION 8, confirmed.

⚠ **`HAL_SEAM_CONTROL=1` cannot serve as the numerator knob, and PREDICTIONS-M8.md
said so before the run**: it closes the seam the menu is itself read over, so it
voids the denominator as well as the numerator. It can only show that nothing is
measurable without the seam. That is why a second knob exists.

### PREDICTION 6 was FALSIFIED, and the range is not widened

I predicted the driven count would land in **[15, 40]**. It is **49**. The
interval is not widened. The error was conceptual: I predicted coverage from what
the row's **host-side code already names**, when the sweep drives every entry
**directly** — so what it measures is what the *firmware* handles, not what
`vesc_comm.py` has constants for. The same mistake was made, in the same
direction, on both sibling rows in this lane.

### The three checks

| check | result | mechanism |
|---|---|---|
| 1 `DEFECT-landed-without-M4` | **0** | `census_score.score()` (imported, `sha256 56cd3ab3…`) returned verdict field 3 = `M4-OK` |
| 2 landed-vs-rung | **0** | rung `M7`, `landed` true, expected true |
| 3 `entitled()` over OBSERVATIONS | **0** | `entitled=M7`, credited `M7`; 52 per-entry records |

**Both directions of the by-construction argument**, because two zeros on their
own are not informative. `attack.py` closes with
`result["landed"] = bool(result.get("landed")) and result["milestone"] in
("M4","M6","M7")`:

* *landed true below M4* is impossible — the whitelist forces it false for
  `ERROR`/`M0`…`M3`;
* *a rung ≥ M4 with landed false* is impossible — `_ladder` is called with
  `m4=result["landed"]` and only returns `M4`/`M6`/`M7` when that is true.

⭐ **The teeth are kept**: this is a whitelist, **not** `landed = rung >= 4`, which
would make both checks tautologies. ⚠ **Latent defect, reported and deliberately
not patched:** if an `M8` branch is ever added to `_ladder` without adding `"M8"`
to that whitelist, a full-parity run scores `milestone=M8, landed=False` and the
guard returns **`WALL-M8`** — the row's best run reported as a wall. No `M8`
branch is added today: parity is a fraction, so the branch would be a dead one.

⚠⚠ **`tools/enumerate_ladder.py` cannot do check 3** and was not used for it: it
quantifies over the ladder's free booleans and never inspects how a term is
constructed. That is the fifth confirmation on this fleet.

### Defects in my own work, all found by me

1. **The async-print desync.** `measure_res_ind` prints seconds late; arm B
   consumed its line, every later exchange was one behind, and the nonce-bearing
   refusal surfaced in the help drain and broke the menu parse. Fixed with a
   settle that runs for **all** entries (not a template for the hard one), and
   re-run with **four already-driven entries as controls**, all unchanged.
2. **A false VOID from my aggregator**, which read `inventory_why.denominator` —
   a key this row never emits — and so reported "the inventory differed across
   boots" against 50 agreeing boots.
3. **`entitled_check3.py` asked for `guest_ran`**, a local in `_finalize` that
   never reaches the record, and **demanded the guard's sha unconditionally**, so
   one unscoreable entry raised `Undetermined` for the whole run. Both were caught
   *by the file raising rather than scoring a false floor*, which is the behaviour
   it exists to have.

### Not measured

* The `COMM_PACKET_ID` surface (above).
* Whether each driven command's **output is semantically correct**. M8 asks
  coverage; this measures that the firmware routed the command to its own handler
  and answered in its own bytes, discriminated against a minted twin.
* The CAN, USB and servo/ADC inputs this firmware also has: declared by the
  hardware, **not driven** by this rehost. A failure to cover, not a §1d absence.

### Environment

* venv `venvs-on-9bde2c0.noindex/vesc-bldc-f405-a69`; core
  `hal-b0818-on-9bde2c0` at **`60619b7e`**, clean, identical across all 59 boots.
  `origin/dev` **resolved at read time** was `9bde2c0c` and **is an ancestor** of
  that HEAD (+9 local commits). No SHA is quoted for a moving ref.
* Ports: lane `s0930-laneJ`, all binds inside **37750–37849** and verified from
  `lsof`; no device-default port (21201/6102/6103) was bound.
* ⚠ Box load was **14.1–19.9** throughout, largely self-inflicted. `BOOT_TIMEOUT`
  is 900 s against ~60 s observed, so no entry was decided by a budget; the one
  place a budget could have classified is named and tested on the sibling rows.
* Firmware `sha256 ea6e96f9…` **before and after every chain**, 59 of 59 unchanged.

## 2026-09-08 — M4 -> M7, and the corpse that had to be killed first

Seven arms, serial, each on its own bridge/rx/tx port triple.
`PREDICTIONS-M6-M7.md` was committed **before** the first graded arm
(`bee3100`), and every prediction in it held.

⚠ **A note on the source cross-references below.** The C quoted here is read
from a `vedderb/bldc` checkout at `b9d287b3`, which is **not** the pinned
`e4db57a8` this image was built from. Every load-bearing claim is therefore
also verified against **this image or a live run of it**: the `Invalid command`
template is at image offset `0x726e1` (once) and was rendered live with a
per-run nonce; the `bytes_left` behaviour was measured as a live A/B; the
`float16` truncation was measured as a firmware answer of 5274 against a
predicted 5275. Where a claim rests only on the cross-reference tree it is
marked as such.

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
(The "one byte shorter" heuristic does not apply here: this console dispatches
on `strcmp`, not on a unique abbreviation, so `faul` is simply another unknown
command. ⚠ That reading is from the cross-reference tree and was **not**
separately measured on this image — it is why the graded twin is `fault` rather
than a one-byte neighbour, not a claim the rung rests on.)

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
