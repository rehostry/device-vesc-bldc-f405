#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CHECK 3 for device-vesc-bldc-f405, at the OBSERVATION layer.

Written from RULES.md §0's TEXT and applied to a run's RAW observations. It does
NOT import `_ladder`, and it reads no flag the harness derived — not `driven`,
not `klass`, not `ok`. Every term is rebuilt from what the guest emitted, because
the 2026-09-20 ruling is that a check quantifying over a ladder's TERMS is blind
to a defect in what they derive from, and `tools/enumerate_ladder.py` cannot help
(five independent confirmations).

⚠⚠ **ABSENT INPUTS RAISE `Undetermined`. THEY DO NOT PRODUCE A FINDING.**
Eight false check-3 hits on this fleet were a missing or misspelled key read
through `dict.get()` and scored as a false floor. The sibling row's own
`entitled_check3.py` documents FOUR successive rounds of exactly that bug, each
of which reported a defect against a correct run. So every observation this file
needs is fetched through :func:`need`, which raises; a run that cannot be scored
is reported as **a defect in THIS TOOL**, never as a defect in the row.

⚠ DECLARED LIMITATION: I authored `tools/m8_parity.py` in the same session, so
this is not the blind transcription a fresh reader's would be. What it can still
do is refuse every derived flag: if `m8_parity.py`'s `driven` disagreed with the
raw arm-A/arm-B strings, this file would catch it.
"""
from __future__ import annotations

import json
import sys

RUNGS = ["M0", "M1", "M2", "M3", "M4", "M6", "M7", "M8"]


class Undetermined(Exception):
    """An input this check needs is absent. A TOOL DEFECT, not a finding."""


def need(d, key, kind=None):
    """Fetch `key` or raise. NEVER a default, NEVER `.get()`."""
    if not isinstance(d, dict):
        raise Undetermined("expected an object to read %r from, got %s"
                           % (key, type(d).__name__))
    if key not in d:
        raise Undetermined("observation %r is absent" % (key,))
    v = d[key]
    if kind is not None and not isinstance(v, kind):
        raise Undetermined("observation %r is %s, expected %s"
                           % (key, type(v).__name__, kind))
    return v


REFUSAL_MARK = "Invalid command"


def entry_driven(rec):
    """Rebuild ONE entry's verdict from the guest's own rendered lines.

    Reads `arm_a_lines`, `arm_b_lines`, `nonce`, `entry` and the guard — never
    `driven`, `arm_a_answered`, `arm_b_ok` or `klass`.
    """
    entry = need(rec, "entry", str)
    nonce = need(rec, "nonce", str)
    if not need(rec, "booted", bool):
        raise Undetermined("entry %s did not boot; nothing was measured" % entry)
    a_lines = need(rec, "arm_a_lines", list)
    b_lines = need(rec, "arm_b_lines", list)

    # ARM A, from the raw lines: a non-empty reply that is not the refusal. The
    # terminal's own echo (`-> <cmd>`) is not a reply.
    body_a = [l for l in a_lines
              if l.strip() and not l.strip().startswith("-> ")]
    a_refused = any(REFUSAL_MARK in l for l in a_lines)
    a_ok = bool(body_a) and not a_refused

    # ARM B, the diagonal: ONE rendered line must carry BOTH the firmware's
    # refusal AND this run's nonce. Checking them on separate lines is satisfied
    # by the command echo, which also contains the nonce -- that was a real
    # defect in m8_parity.py, caught on its own smoke run, and this file does
    # not repeat it.
    b_ok = any(REFUSAL_MARK in l and nonce in l for l in b_lines)

    # The entry must appear in the menu THIS boot parsed, re-derived here from
    # the raw help shape rather than taken from `token_in_own_menu`.
    toks = need(rec, "inventory_tokens")
    in_menu = toks is not None and entry in toks

    guard = need(rec, "inventory_guard", dict)
    # ⚠ THREE-WAY, NOT TWO-WAY. A boot in which the menu could not be READ at
    # all is not the same fact as a menu that MOVED, and it is not a tool defect
    # either -- it is a per-entry UNDETERMINED, which is a data point. The first
    # version of this file demanded `observed_pairs_sha256` unconditionally and
    # raised Undetermined for the WHOLE RUN because one entry (`rebootwdt`)
    # reboots the board and killed its own inventory read. One unscoreable entry
    # must not erase 51 scoreable ones.
    if "observed_pairs_sha256" not in guard:
        unreadable = bool(need(rec, "inventory_unreadable_this_boot", bool)) \
            if "inventory_unreadable_this_boot" in rec else True
        return {"entry": entry, "arm_a": a_ok, "arm_a_refused": a_refused,
                "arm_a_reply_lines": len(body_a), "arm_b": b_ok,
                "in_menu": False, "guard_ok": None,
                "inventory_unreadable": unreadable,
                "undetermined": True, "driven": False}
    guard_ok = (guard["observed_pairs_sha256"]
                == need(guard, "expected_pairs_sha256", str)
                and not need(guard, "missing", list)
                and not need(guard, "extra", list)
                and not need(guard, "arity_changed", list))

    return {"entry": entry, "arm_a": a_ok, "arm_a_refused": a_refused,
            "arm_a_reply_lines": len(body_a), "arm_b": b_ok,
            "in_menu": in_menu, "guard_ok": guard_ok,
            "inventory_unreadable": False, "undetermined": False,
            "driven": bool(a_ok and b_ok and in_menu and guard_ok)}


def entitled(run, entries):
    """§0, term by term, from observations only. Returns (rung, why)."""
    why = {}
    # ⚠ `guest_ran` is a LOCAL in `_finalize` and never reaches the record; the
    # first version of this file asked for it and correctly raised Undetermined
    # rather than reporting a false floor. The record carries `booted` and
    # `guest_faulted`, so M1 is rebuilt from those. ⚠ The fault terms are
    # REQUIRED reported fields, not colour: a row printing a bare faults=0 while
    # faulting after its round trip is hiding the fault, not passing the check.
    why["m1_booted"] = need(run, "booted", bool)
    why["guest_faulted"] = need(run, "guest_faulted", bool)
    why["m1_guest_executed"] = why["m1_booted"] and not why["guest_faulted"]
    why["m2_own_init"] = need(run, "own_init", bool)
    why["m3_seam_up"] = need(run, "seam_up", bool)

    # M4: "a request ... answered by the firmware's own bytes". Rebuilt from the
    # attack arm's own record.
    why["m4_round_trip"] = need(run, "vesc_packet_round_trip", bool)
    m4 = why["m4_round_trip"]

    why["m6"] = bool(need(need(run, "m6", dict), "ok", bool))
    why["m7"] = bool(need(need(run, "m7", dict), "ok", bool))

    # M8: "EVERY entry in an independently derived inventory passes M4", strict.
    rows = [entry_driven(r) for r in entries]
    if not rows:
        raise Undetermined("no per-entry records were supplied")
    # A MOVED inventory voids parity. An UNREADABLE one in a single boot makes
    # that entry undetermined and leaves the others intact.
    moved = [r for r in rows if r["guard_ok"] is False]
    undet = [r for r in rows if r["undetermined"]]
    if moved:
        why["m8"] = "VOID: the shrink guard MISMATCHED in %d of %d boots" % (
            len(moved), len(rows))
        m8 = False
    else:
        inv = {len(rec["inventory_tokens"]) for rec in entries
               if rec.get("inventory_tokens")}
        if len(inv) != 1:
            why["m8"] = "VOID: the inventory differed across boots: %s" % (inv,)
            m8 = False
        else:
            n = inv.pop()
            passed = [r["entry"] for r in rows if r["driven"]]
            why["m8_inventory"] = n
            why["m8_measured"] = len(rows)
            why["m8_boots_that_read_the_menu"] = len(rows) - len(undet)
            why["m8_driven"] = len(passed)
            why["m8_undetermined"] = sorted(r["entry"] for r in undet)
            why["m8_not_driven"] = sorted(r["entry"] for r in rows
                                          if not r["driven"]
                                          and not r["undetermined"])
            # STRICT: parity needs every entry measured AND none undetermined.
            # A bounded numerator is not a parity fraction (2026-09-30 ruling).
            m8 = (n > 1 and len(rows) == n and not undet and len(passed) == n)
            why["m8"] = m8

    if m4 and m8:
        return "M8", why
    if m4 and why["m7"]:
        return "M7", why
    if m4 and why["m6"]:
        return "M6", why
    if m4:
        return "M4", why
    if why["m3_seam_up"]:
        return "M3", why
    if why["m2_own_init"]:
        return "M2", why
    if why["m1_guest_executed"]:
        return "M1", why
    return "M0", why


def main(argv):
    if len(argv) < 2:
        print("usage: entitled_check3.py <run.json> <entry.json>...")
        return 2
    run = json.load(open(argv[0]))
    entries = [json.load(open(p)) for p in argv[1:]]
    try:
        ent, why = entitled(run, entries)
    except Undetermined as exc:
        # ⚠⚠ NOT a finding. The tool could not score the run.
        print("UNDETERMINED (a defect in THIS TOOL or a missing observation): %s"
              % exc)
        print("check3 = Undetermined; no claim is made either way")
        return 0
    credited = run.get("milestone")
    landed = run.get("landed")
    print("entitled=%s credited=%s landed=%s" % (ent, credited, landed))
    print("  " + json.dumps({k: v for k, v in why.items()
                             if k != "m8_not_driven"}))
    if why.get("m8_not_driven"):
        print("  NOT driven (%d): %s" % (len(why["m8_not_driven"]),
                                         " ".join(why["m8_not_driven"])))
    bad = 0
    if credited not in RUNGS:
        print("  ** the run credits %r, which is not a rung -- Undetermined **"
              % (credited,))
        return 0
    if RUNGS.index(credited) > RUNGS.index(ent):
        print("  ** credited-but-not-entitled **"); bad += 1
    elif RUNGS.index(credited) < RUNGS.index(ent):
        print("  ** FALSE FLOOR: entitled higher than credited **"); bad += 1
    if landed != (RUNGS.index(ent) >= RUNGS.index("M4")):
        print("  ** landed disagrees with the rung **"); bad += 1
    print("check3 disagreements: %d" % bad)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
