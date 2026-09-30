<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# PREDICTIONS — M8 on device-vesc-bldc-f405 (written 2026-09-30, BEFORE any graded M8 arm)

Pre-registration, committed before the harness that grades against it. If a
graded arm contradicts anything below, **the contradiction is reported as a
falsification and the range is not widened.**

## 0. NO ENTRY IS REMOVED — the denominator is CREATED

This row's STATUS.md says *"M5 and M8 are UNDEFINED, not failed: this device
drives one link (the USART3 COMM seam) to one peer, so RULES §1a leaves both
undefined and the ladder deliberately has no branch for either."*

**The M5 half of that is right and stands. The M8 half is wrong**, and the
2026-09-29 ruling says so directly — it names this firmware's sibling as the
precedent: *"`vesc-bms` grades 16 COMM packets over ONE CAN link"*, and *"a
command within one framing layer is also an entry when the firmware declares
it."* One link does not make M8 undefined; **a one-entry inventory does**, and
this firmware's inventory is not one entry.

So this file **creates** a denominator. **Parity will be far worse than the row's
silence implied, and that is the correct direction.**

## 1. The image is NOT the sibling's image — no constant is transferred

`device-vesc-bms` is this lane's template and shares the upstream codebase, so
the byte-identical-images ruling was applied first, before anything was reused:

| row | image | sha256 | size |
|---|---|---|---|
| `device-vesc-bldc-f405` | `configs/vesc.bin` | `ea6e96f9c282f93fe0199db77991dcfd422cbf88f174a8043e987455b643bed9` | 1 048 576 |
| `device-vesc-bms` | `configs/vesc_bms.bin` | `f72bb1c48eb90491cd2232ec3b4c495928e8e96643e8d544eba095ca64596d43` | 85 240 |

**Different images, different sizes, different builds** — a BLDC ESC
(STM32F405, ChibiOS) against a BMS (STM32L4). They are **two independent
observations**, not one carried by two rows. ⚠ **Nothing numeric is transferred
from the sibling**: its inventory is 16, this one is derived here from this
guest's own bytes, and the two numbers have no reason to agree.

## 2. The inventory, and what the denominator COUNTS

**The denominator counts TERMINAL COMMANDS the firmware itself publishes in its
own `help` menu — not interfaces, and not COMM packet ids.**

It is parsed **from the guest's own bytes on every run**: one
`COMM_TERMINAL_CMD "help"` over the USART3 COMM seam, and every `COMM_PRINT`
frame the firmware emits in reply. The menu is **not** grepped out of the image:
a string census is exactly what over-counted and under-counted on other rows,
because the linker pools string literals.

**The shape rule, from the guest's own formatting:** between the preamble
`Valid commands are:` and the final sentinel line, a **command** line has no
leading space and a **description** line begins with two spaces. Measured on the
recon boot: 115 lines total, 112 body lines, **52 command-shaped**, 60
description-shaped, **0 lines of any other shape** — the three counts sum exactly
to the body, so no line is unclassified.

**PREDICTION 1 — the denominator is 52**, and the 52 tokens are unique.

### The completeness witness — this is the lesson the sibling paid for

⚠ The sibling row relayed **26** CRC-valid COMM packets when its menu had **34**
entries, because its reassembly never drained the short-buffer path and **7 of 16
names vanished**. *"26 CRC-valid" was true and incomplete* — the short path
carries **no CRC field at all**, so a CRC census could not detect the loss.

A count cannot detect its own truncation, so the completeness witness here is
**structural, not numeric**: the firmware's `help` handler emits a final
`commands_printf(" ")` after the last command, so **the menu ends in a
single-space line**. The recon boot observed `' '` as line 115.

**PREDICTION 2 — the sentinel is present, and a parse whose last line is not
`' '` VOIDS the measurement rather than reporting a smaller denominator.** A
truncated drain cannot masquerade as a shrunken inventory.

**PREDICTION 3 — zero callbacks are appended.** The 52 are all built-ins; this
build registers no `terminal_register_command_callback` commands, so the menu's
callback loop contributes nothing. If a graded run parses more than 52, the extra
entries are registered callbacks and **the denominator grows, not shrinks.**

## 3. What this denominator does NOT count

* **The `COMM_PACKET_ID` switch in `commands_process_packet`.** That is a
  **second declared surface on the same seam**, and `COMM_TERMINAL_CMD` (id 20)
  is one member of it. ⚠ **A reader who counts it instead of, or in addition to,
  the terminal menu gets a LARGER denominator and a WORSE fraction.** It is
  named here, unmeasured, precisely so that reader can re-derive their own
  number. **It is not counted here because it would double-count: the 52
  terminal commands all arrive inside packet id 20.**
* The CAN seam, the USB seam and the servo/ADC app inputs — declared by the
  hardware and **not driven** by this rehost.

## 4. The GUARD — diagonal, pinned to raw bytes

`tools/m8_inventory_guard.json`, committed with this file, pins:

* `help_sha256 = 625878ee5391caf7…` over the whole 115-line menu;
* `preamble = "Valid commands are:"` and `sentinel = " "`;
* all **52 `(token -> full declaration line)` PAIRS**, and their
  `pairs_sha256 = 611e20fa0eaf3315…`.

⚠ **Why pairs and not tokens.** A count-keyed guard is not a guard, and a
token-only guard is nearly as weak: the declaration line carries the command's
**argument specification** (`param_detect [current] [min_rpm] [low_duty]`), so a
firmware whose command kept its name but changed its arity breaks the pairing.
That is the diagonal.

**A mismatch in EITHER DIRECTION VOIDS parity.** Fewer than 52 voids; more than
52 voids and is re-derived.

## 5. The oracle for one entry, and the vacuity questions answered in advance

An entry is **driven** when both arms hold, in the entry's **own fresh boot**:

* **Arm A** — the token is sent as a terminal command and the firmware answers
  with **at least one non-empty `COMM_PRINT` line that is not its refusal**.
* **Arm B, the diagonal twin** — a **per-run minted nonce** token is sent in the
  same boot and the firmware renders **its own refusal containing that nonce**
  (`terminal_process_string()` prints `Invalid command: %s`). A nonce the host
  minted this run cannot be in the image, the models, the config or the handler,
  so the refusal is a deaf-console guard as well as a discriminator.

**Could a pass happen with the firmware asleep?** **No, and the two arms fail in
opposite directions if it were.** Arm A needs the guest to emit a `COMM_PRINT`
frame that our own decoder CRC-checks; a sleeping guest emits nothing and arm A
is false. Arm B needs the guest to *render a string the host minted seconds
earlier*; a sleeping guest cannot, and a recorded or replayed refusal carries the
wrong nonce. ⚠ **Arm B is the arm that would catch a VACUOUS PASS**, because an
absence-witness ("no refusal arrived") is true before the firmware acts, whereas
"the refusal arrived and contains this run's nonce" is not.

**PREDICTION 4 — three classes will appear, and all three are reported:**

1. **driven** — a non-refusal reply;
2. **refused** — the firmware's own `Invalid command:` for a token its own menu
   published (this would be a genuine firmware/menu disagreement and I predict
   **zero** of these);
3. ⚠ **recognised-but-silent** — the parser accepted the token (no refusal) and
   printed nothing. **These are NOT counted as passed**, and that is a limit of
   **my oracle**, not a property of the firmware: commands such as `stop` and
   `foc_dc_cal` act without printing. Saying so is required; a silent command
   scored as driven would be an absence-witness pass.

**PREDICTION 5 — ONE FRESH BOOT PER ENTRY, entry first.** A shared-boot sweep
manufactures a false LOW parity here for a concrete reason: several of these
commands (`stop`, `rebootwdt`, `foc_openloop`, `connect_virtual_motor`) change
motor-control state or reset the board, so an entry graded after them is graded
against a different machine. No entry is graded in a boot that already graded
another entry.

**PREDICTION 6 — parity will be well under 52.** Many entries drive motor,
encoder, IMU, NRF, UAVCAN or SWD hardware this rehost does not model. Those are
**FAILURES to cover, not §1d absences** — "we did not implement it" is not an
absence. I predict the driven count lands in **[15, 40]**; if it falls outside,
**I report the miss rather than widening the interval.**

## 6. Falsification arm

`HAL_SEAM_CONTROL=1`, this row's existing knob, withholds the outbound frames
while the rest of the arm runs unchanged. **PREDICTION 7: parity goes to 0 of 52,
and the denominator VOIDS rather than reading 0 of 0** — because the menu is
itself read over the seam the knob closes. ⚠ **That is the honest outcome and it
is worth stating plainly: this knob cannot show "inventory 52, parity 0", it can
only show that nothing is measurable without the seam.** A second knob is
therefore needed for the numerator alone, and it is:

`VESC_M8_TWIN_ONLY=1` — arm A sends the **minted nonce instead of the token**,
leaving the inventory parse untouched. **PREDICTION 8: the inventory still reads
52, and the driven count goes to 0**, because every entry then receives the
refusal its twin was supposed to receive.

## 7. What is NOT predicted, because it is not measured here

* The `COMM_PACKET_ID` surface (§3) — **unmeasured.**
* Whether any command's *output* is correct beyond being the firmware's own and
  not a refusal. This is a **coverage** measurement (M8 asks which entries are
  driven), not a per-command semantic check.
* M5 stays **UNDEFINED**: one link, one peer. ⚠ Full parity on 52 commands over
  one link with M5 undefined would not be a contradiction (RULES §1b, and
  `planck-rev6` at 3 of 3 with M5 undefined) — but parity is not full here
  anyway.
