#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The three required checks for device-vesc-bldc-f405, run against live runs.

1. `DEFECT-landed-without-M4` — via `census_score.score()`, **verdict field 3**.
   `scratch-census-guard-a48/census_score.py` is **IMPORTED, never forked**:
   three fleet scripts embed it verbatim and `tests/run-tests.sh` diffs them.
2. **landed-vs-rung** — `landed` must be true exactly when the rung is >= M4.
3. **check 3 at the OBSERVATION layer** — `tools/entitled_check3.py`, whose
   `entitled()` is evaluated over the run's raw observations, never over the
   ladder's terms. ⚠⚠ `tools/enumerate_ladder.py` CANNOT do this job: it
   quantifies `itertools.product` over free booleans and never inspects how a
   term is CONSTRUCTED. That is five independent confirmations on this fleet.

## Why checks 1 and 2 come out 0 here, stated in BOTH directions

`attack.py` closes with, verbatim:

    result["landed"] = bool(result.get("landed")) and \
        result["milestone"] in ("M4", "M6", "M7")

* **landed true with a rung below M4** cannot be produced: the whitelist forces
  `landed` false for `ERROR`/`M0`/`M1`/`M2`/`M3`. So check 1 is **0 by
  construction**, not 0 by luck.
* **a rung at or above M4 with landed false** cannot be produced either:
  `_ladder` is called with `m4=result["landed"]`, and it returns `M4`/`M6`/`M7`
  only on that argument being true. So check 2 is **0 by construction** too.

⭐ **And the teeth are kept**: this is a WHITELIST, not `landed = rung >= 4`. A
sibling row fixed the same class of bug by writing `landed = rung >= 4`, which
makes checks 1 and 2 tautologies that can never fire again. This one still fires
if the ladder gains a rung the whitelist does not name — see the latent defect
below.

⚠ **LATENT DEFECT FOUND AND REPORTED, NOT SILENTLY PATCHED.** If an `M8` branch
is ever added to `_ladder` without adding `"M8"` to that whitelist, a full-parity
run scores `milestone=M8, landed=False` and `census_score` returns **`WALL-M8`**
— the row's best possible run reported as a wall. M8 is **UNMET** on this row
today (parity is a fraction, so the branch is correctly absent and would be a
dead branch), so nothing is changed here; the coupling is recorded so whoever
adds the branch adds the whitelist entry in the same commit.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
CENSUS = "/Users/user/Development/rehostry/scratch-census-guard-a48/census_score.py"


def _census():
    """IMPORT census_score.py. Never fork it, never transcribe it."""
    spec = importlib.util.spec_from_file_location("census_score", CENSUS)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


RUNGS = ["M0", "M1", "M2", "M3", "M4", "M6", "M7", "M8"]


def main(argv):
    if len(argv) < 1:
        print("usage: three_checks.py <attack-result.json> [entry.json ...]")
        return 2
    cs = _census()
    print("census_score.py sha256 =",
          subprocess.run(["shasum", "-a", "256", CENSUS], capture_output=True,
                         text=True).stdout.split()[0])
    run = json.load(open(argv[0]))
    entries = [json.load(open(p)) for p in argv[1:]]

    # ---- CHECK 1 -------------------------------------------------------
    booted, landed, ms, verdict, why = cs.score(run)
    print("\nCHECK 1  census_score.score() -> verdict field 3 = %r" % verdict)
    print("         booted=%s landed=%s milestone=%s why=%s"
          % (booted, landed, ms, why))
    c1 = 1 if verdict == "DEFECT-landed-without-M4" else 0
    print("         DEFECT-landed-without-M4 hits: %d" % c1)

    # ---- CHECK 2 -------------------------------------------------------
    rung = run.get("milestone")
    ld = run.get("landed")
    if rung in RUNGS:
        expect = RUNGS.index(rung) >= RUNGS.index("M4")
        c2 = 0 if ld == expect else 1
        print("\nCHECK 2  landed-vs-rung: rung=%s landed=%s expected=%s -> %d "
              "disagreement(s)" % (rung, ld, expect, c2))
    else:
        c2 = 0
        print("\nCHECK 2  rung=%r is not a ladder rung; nothing to compare "
              "(Undetermined, not a hit)" % (rung,))

    # ---- CHECK 3 -------------------------------------------------------
    spec = importlib.util.spec_from_file_location(
        "entitled_check3", os.path.join(_HERE, "entitled_check3.py"))
    e3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(e3)
    print("\nCHECK 3  entitled() over OBSERVATIONS (%d per-entry records)"
          % len(entries))
    try:
        ent, w = e3.entitled(run, entries)
    except e3.Undetermined as exc:
        print("         UNDETERMINED: %s" % exc)
        print("         ⚠ reported as a TOOL DEFECT, not a finding. An absent "
              "input raises; it never scores a false floor.")
        c3 = "Undetermined"
    else:
        print("         entitled=%s credited=%s" % (ent, rung))
        print("         " + json.dumps({k: v for k, v in w.items()
                                        if k != "m8_not_driven"}))
        if w.get("m8_not_driven"):
            print("         NOT driven (%d): %s"
                  % (len(w["m8_not_driven"]), " ".join(w["m8_not_driven"])))
        c3 = 0
        if rung in RUNGS:
            if RUNGS.index(rung) > RUNGS.index(ent):
                print("         ** credited-but-not-entitled **"); c3 += 1
            elif RUNGS.index(rung) < RUNGS.index(ent):
                print("         ** FALSE FLOOR **"); c3 += 1
    print("\nSUMMARY  check1=%s check2=%s check3=%s" % (c1, c2, c3))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
