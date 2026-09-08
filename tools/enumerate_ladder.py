#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Enumerate this device's milestone ladder, BEFORE and AFTER.

Two questions, and they are different (playbook w100.1):

* **What can the ladder PRINT?** Drive every combination of the booleans it
  takes and collect the answers. That is what says whether a rung is reachable.
* **What does the ladder WRITE?** Read the function's own source with ``ast``
  and collect the `M<n>` constants it returns. A rung that is WRITTEN but never
  PRINTED is a **dead branch** -- a defect in the grader -- and enumeration
  alone reports it as "the firmware never got there", which reads like a fact
  about the device.

``ast`` and not ``grep``: a text scan flags the rung strings in the function's
own docstring, and this one names five of them (playbook w74).

The BEFORE ladder is a transcription of what `attack.run_attack` did before
2026-09-08, kept here so the comparison is reproducible rather than asserted.
"""
from __future__ import annotations

import ast
import inspect
import itertools
import re
import sys
import textwrap
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rehostry_vesc_bldc_f405 import attack as A  # noqa: E402


def _before(gates_ok, guest_ran, own_init, seam_up, m4, m6, m7):
    """TRANSCRIPTION of the pre-2026-09-08 grader. Do not 'fix' it.

        result = {..., "milestone": "M0", ...}
        if not sc.boot(stage):
            milestone = "ERROR" if gated else ("M0" if faulted else "M1")
            return result
        result["milestone"] = "M3"
        if result["landed"]: result["milestone"] = "M4"

    `boot()` returns True only when the firmware enabled USART3, so `seam_up`
    is what decided whether the early return was taken; `own_init`, `m6` and
    `m7` reached the old grader not at all.
    """
    if not gates_ok:
        return "ERROR"
    if not seam_up:
        return "M0" if not guest_ran else "M1"
    if m4:
        return "M4"
    return "M3"


def written(fn) -> set:
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant):
            v = str(n.value.value)
            if re.fullmatch(r"M\d|ERROR", v):
                out.add(v)
    return out


def enumerate_fn(fn, arity=7):
    counts = Counter()
    rows = []
    for combo in itertools.product((False, True), repeat=arity):
        v = fn(*combo)
        counts[v] += 1
        rows.append((combo, v))
    return counts, rows


def main() -> int:
    names = ("gates_ok", "guest_ran", "own_init", "seam_up", "m4", "m6", "m7")
    bc, brows = enumerate_fn(_before)
    ac, arows = enumerate_fn(A._ladder)
    bw, aw = written(_before), written(A._ladder)

    print("booleans: %s" % ", ".join(names))
    print()
    print("attack.py BEFORE (transcription), %d assignments" % sum(bc.values()))
    print("  " + "  ".join("%s %d" % kv for kv in sorted(bc.items())))
    print("  PRINTABLE %s" % sorted(bc))
    print("  WRITTEN   %s" % sorted(bw))
    print("  DEAD BRANCHES (written, never printed): %s"
          % (sorted(bw - set(bc)) or "none"))
    print()
    print("attack._ladder AFTER, %d assignments" % sum(ac.values()))
    print("  " + "  ".join("%s %d" % kv for kv in sorted(ac.items())))
    print("  PRINTABLE %s" % sorted(ac))
    print("  WRITTEN   %s" % sorted(aw))
    print("  DEAD BRANCHES (written, never printed): %s"
          % (sorted(aw - set(ac)) or "none"))
    print("  declared LADDER_PRINTABLE: %s" % sorted(A.LADDER_PRINTABLE))
    print("  M5 branch present: %s   (one interface -> RULES §1a leaves M5 "
          "UNDEFINED, so its absence is deliberate)"
          % ("M5" in aw or "M5" in set(ac)))
    print()

    # THE DOWNWARD FALSE FLOOR, counted rather than asserted (w91.1/w100.0).
    down = [(c, b, a) for (c, b), (_c2, a) in zip(brows, arows)
            if _rank(a) > _rank(b)]
    up = [(c, b, a) for (c, b), (_c2, a) in zip(brows, arows)
          if _rank(a) < _rank(b)]
    print("assignments the repair moves UP (the DOWNWARD false floor the old "
          "grader printed): %d of %d" % (len(down), len(brows)))
    for combo, b, a in down[:6]:
        print("   %s  %s -> %s"
              % (dict(zip(names, combo)), b, a))
    print("assignments the repair moves DOWN: %d" % len(up))
    for combo, b, a in up[:6]:
        print("   %s  %s -> %s" % (dict(zip(names, combo)), b, a))
    return 0


_ORDER = ["ERROR", "M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"]


def _rank(v: str) -> int:
    return _ORDER.index(v)


if __name__ == "__main__":
    raise SystemExit(main())
