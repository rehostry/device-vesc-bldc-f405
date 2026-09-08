<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Predictions for the M6 and M7 rungs — written and committed BEFORE the first graded arm

Everything below is derived from `comm/packet.c`, `comm/commands.c`,
`terminal.c` and `hwconf/hw_100_250.h` in the pinned tree
(`vedderb/bldc @ e4db57a8`), and from **exploratory** probe sessions on
2026-09-08 (`scratch-batch-s0907/laneT1D/probe_vesc_{a,c}.py`). No arm below has
been run against this harness. If a measurement contradicts a line here, the
line is wrong and stays, with the correction written beside it.

---

## 0. The reader defect this row had to fix first, and why it is FIRST

The previous lane ran one probe session against this device and reported that
**11 of 14 malformed frames left the next known-good `COMM_FW_VERSION` request
unanswered**, and that this was *"the decoder's `rx_timeout` versus its own
buffered reader, and not distinguishable from what it measured."*

**Both halves of that are refutable, and both are refuted.**

* There is **no `rx_timeout` and no `packet_timerfunc`** anywhere in the pinned
  `comm/packet.c` or `comm/packet.h`. That mechanism does not exist in this
  firmware.
* The known-good round trip costs **0.01–0.02 s** on this rehost (five
  consecutive, measured), so a 6 s `alive()` timeout was never the constraint
  either.

What actually happens is `packet_process_byte`'s own arithmetic:

```c
if (state->bytes_left > 1) { state->bytes_left--; return; }   // swallow, no decode
...
if (data_len >= PACKET_BUFFER_LEN) { write = read = 0; bytes_left = 0; }  // the ONLY reset
```

A 16-bit-length header that declares 255 bytes sets `bytes_left` to 258, and
the decoder then **swallows the next 255 bytes without attempting a decode at
all** — so every known-good request inside that window reads as "the firmware
ignored this". There is no timer that ends it. The only unconditional escape is
the overflow reset, which needs `PACKET_BUFFER_LEN` = 520 bytes.

**Prediction P0.** After a 255-byte-payload frame:

| arm | prediction |
|---|---|
| three plain known-good retries, 30 s each | **all three unanswered** |
| then `RESYNC_FLUSH` = 544 filler bytes, then one retry | **answered** |

*Measured in the probe, before this file: `[(False, 30.0), (False, 30.01),
(False, 30.0)]` then `alive=True in 0.03 s`.* `VescScenario.resync()` is that
sequence, it runs after **every** graded class, and `m7_ok` is false unless all
of them came back alive.

---

## 1. The M7 classes, their witnesses, and their twins

Nine graded classes over three **distinct answers**. Every class carries a real
`COMM_SET_MCCONF_TEMP` write of a **per-run minted** value, so the witness of a
refusal is *the limit the firmware declined to move*, never the silence.

| class | frame | predicted answer | witness |
|---|---|---|---|
| `hdr_len_zero` | 8-bit form, declared length 0 | `silent-nowrite` | `try_decode_packet`: `if (len < 1) return -1` |
| `hdr_len_over` | declared length = real + 1 | `silent-nowrite` | stop byte lands one late |
| `hdr_len_under` | declared length = real − 1 | `silent-nowrite` | CRC over the wrong span |
| `start_byte_24bit` | start byte 4 | `silent-nowrite` | the 24-bit form is compiled out at `PACKET_MAX_PL_LEN` 512 |
| `stop_byte_wrong` | stop byte 4 | `silent-nowrite` | `if (buffer[data_start+len+2] != 3) return -1` |
| `crc_one_bit` | ONE minted bit of the CRC-16 flipped | `silent-nowrite` | `crc_calc != crc_rx` |
| `truncated` | last two bytes dropped | `silent-nowrite` | `bytes_left` never reaches 0 |
| `terminal_unknown` | `COMM_TERMINAL_CMD` + a minted nonce | `rendered-invalid-command` | the firmware renders the nonce |
| `clamp_in_current` | `l_in_current_max` one **binary32** step above 300.0 | `clamped-to-limit` | `utils_truncate_number` |
| `clamp_scale` | `l_current_max_scale` a minted value above 1.0 | `clamped-to-limit` | the fixed 0.0–1.0 range |

**P1 — the rendered witness.** `terminal_process_string()` prints

```
Invalid command: %s
type help to list all available commands
```

That format string is at image offset **0x726e1** and appears **once**; the
*rendered* line, carrying a per-run `zz%08x` nonce, appears **zero** times in
the image and zero times in this package. Prediction: the firmware answers the
nonce with two `COMM_PRINT` packets — `-> <nonce> ` and
`Invalid command: <nonce>…` — and `refusal_witnesses_seen` is exactly 1 on a
default arm and **0** on the valid-only arm.

**P2 — the twin, and why it is `fault` and not a near-miss.** w100.2: a twin
whose answer is itself a refusal string would leave a witness standing in the
valid-only control arm. `fault` answers `FAULT_CODE_NONE` and contains no
refusal string, so it is safe. *(The one-byte-shorter idea does not apply here:
`terminal_process_string` uses `strcmp`, not a unique-abbreviation match, so
`faul` is simply another unknown command.)*

**P3 — the clamp bracket, ONE binary32 step wide.**

```
l_in_current_max = 0x43960001 (300.00003)  ->  stored as 0x43960000 (300.0)   CLAMPED
l_in_current_max = 0x4395ffff (299.99997)  ->  stored as 0x4395ffff           UNCHANGED
```

Both sides are graded on the **raw bytes** the firmware serialized, not on the
three-decimal rounding `_decode` applies — `round(299.99997, 3)` is `300.0`, so
the rounded form cannot tell the two apart at all.

⚠ `math.nextafter(300.0, 1e9)` steps a **double**; packed back to binary32 it
lands on 300.0 again, which would have made this class send the limit itself
and pass while measuring nothing. `_f32_neighbour()` steps the binary32 bit
pattern instead, and `tests/` pins the difference.

**P4 — a one-unit bracket that costs six bytes.** The 16-bit-length rule
(`len < 255` refused) needs a 261-byte frame on its accepted side, and on this
rehost that costs minutes; the 8-bit rule gives the same one-unit shape for
free, and **both sides were measured at 0.02 s**:

```
02 00 …  declared length 0  ->  no reply, seam alive           (refused)
02 01 …  declared length 1  ->  0007013130305f323530…          (answered)
```

**P5 — the controls.**

| arm | classes | twins | rendered | state | clamp | rung |
|---|---|---|---|---|---|---|
| default | 9/9 | 10/10 | 1 | 7 | 2 | M7 |
| `--falsify=m7-valid-only` | **0/9** | 10/10 | **0** | **0** | **0** | M6 |
| `--falsify=m7-mispredict` | **0/9** | 10/10 | 1 | 7 | 2 | M6 |
| `--falsify=m6-freeze` | 9/9 | 10/10 | 1 | 7 | 2 | M7 with M6 false |
| `HAL_SEAM_CONTROL=1` | unobservable | | | | | ≤ M3 |
| firmware absent | unobservable | | | | | ERROR or M0 |

`m7-mispredict` rotates each class's expectation onto the next **distinct
answer**, never onto the next class: six of the nine share `silent-nowrite`, so
a next-class rotation would leave those six predicting what they already
predict (w96.2/w100.4). With `VESC_MINT_SEED` set to the same value on both
arms, the firmware's own replies must be **byte-identical** across the pair —
`m7.reply_digest` equal — because the knob changes only what the host expects.

---

## 2. The M6 rungs

Six rounds. The request is **byte-identical every round**
(`02 01 0e <crc> 03`, `COMM_GET_MCCONF`); only the state differs.

**P6 — witness A, the firmware's own serialized configuration.** Round *r*
mints a scale `w` and a battery-current limit `v`, alternating sides so
neither direction can be absent by luck:

```
r even:  w in [0.05, 0.95]   -> read back as round(w*10000) in a BE int16
         v in [5.0, 295.0]   -> read back as binary32(v)
r odd :  w in [1.05, 1.95]   -> read back as 10000  (clamped to 1.0)
         v in [301, 800]     -> read back as binary32(300.0)
```

w99.4's rule is why the two are paired: on the clamping side `v` predicts the
**constant** 300.0 whatever we mint, so it is only half a witness there — and
`w` on that same round is minted inside a range that still moves.

**P7 — witness B, a GUEST counter against a per-run mint, negative in some
rounds.** `commands_process_packet` is reached exactly once per packet the
firmware's **own** `try_decode_packet` accepted. Each round mints `k` (1–4)
well-formed frames and `j` (0–2) malformed ones. Prediction: the guest's
arrival count rises by exactly the number of well-formed frames sent, so the
delta **against what we put on the wire** is `−j`. A host cannot produce that
number without reimplementing `packet.c`.

**P8 — witness C, a second INDEPENDENT handler.** `COMM_GET_MCCONF_TEMP`
(id **91**, verified live to answer with a 50-byte payload) reports
`l_current_max_scale` through a *different* serializer — `float32_auto`, not
the int16 the full `mc_configuration` uses. A single wrong offset model cannot
satisfy both. Predicted at payload offset 5 (after
`l_current_min_scale` at offset 1); if that offset is wrong the round reports
`id91_ok: false` rather than a wrong value.

**P9 — the knob.** `--falsify=m6-freeze` grades every round against round 0's
predicted state, so `rounds_ok` must collapse and `m6.ok` must be false while
M4 and M7 are untouched.

---

## 3. The ladder, before and after

`tools/enumerate_ladder.py`, over the seven booleans the repaired ladder takes:

```
attack.py BEFORE (transcription), 128 assignments
  ERROR 64  M0 16  M1 16  M3 16  M4 16     PRINTABLE {ERROR,M0,M1,M3,M4}
attack._ladder AFTER,             128 assignments
  ERROR 64  M0 32  M1 16  M2 8  M3 4  M4 1  M6 1  M7 2
  PRINTABLE {ERROR,M0,M1,M2,M3,M4,M6,M7}   WRITTEN == PRINTABLE, no dead branch
  11 of 128 assignments move UP   (w91.1's DOWNWARD false floor)
  24 of 128 move DOWN             (the old grader printed M3/M4 for runs whose
                                   guest never cleared the work gate)
```

**P10 — the control arm that proves the floor moved.** `VESC_BOOT_TIMEOUT` set
low enough that the firmware has not reached its USART3 driver when the wait
expires. The guest is alive and has printed its own `BOOT: conf_general_init`
/ `BOOT: mc_interface_init` trace. Prediction: the old grader printed **M1**;
the repaired ladder must print **M2**, and `own_init` must be `true` in the
RESULT.

There is **no M5 branch and no M8 branch**, deliberately: this device has one
interface (the USART3 COMM seam), so RULES §1a leaves both UNDEFINED, and a
branch with no term is w88.6's defect in a taller hat.

---

## 4. What I will refuse to grade, and why

* **The 16-bit-length `254 refused / 255 accepted` bracket the previous lane
  handed over.** Its refused side is cheap and reproducible; its **accepted**
  side costs minutes on this rehost and its recovery time depends on our own
  `HAL_IRQ_CHUNK` and on the USART3 model's byte-delivery rate. Per w96.5 a
  behaviour I cannot attribute to the guest is not adversarial evidence, so it
  is recorded as a measured seam fact and **nothing graded sits inside it**.
* **Any class whose only witness would be silence.** Every graded class here
  has either a rendered string, a limit the firmware declined to move, or a
  limit it substituted.
