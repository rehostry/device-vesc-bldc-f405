#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M8 parity for device-vesc-bldc-f405, graded per entry in the entry's OWN boot.

Contract (pre-registered in ``PREDICTIONS-M8.md``, committed first):

* the **inventory** is the firmware's own ``COMM_TERMINAL_CMD help`` menu, parsed
  from the guest's bytes by shape, and re-parsed in **every** boot;
* the **denominator** is the 52 command-shaped lines between the preamble
  ``Valid commands are:`` and the final single-space sentinel;
* an entry is **driven** when arm A gets a non-empty, non-refusal reply AND
  arm B's minted-nonce twin gets the firmware's own refusal *containing this
  run's nonce*;
* **one fresh boot per entry, entry first** — a shared-boot sweep manufactures a
  false LOW parity here, because ``stop``/``rebootwdt``/``foc_openloop`` change
  the machine an entry graded after them would be graded against.

⚠ This file grades COVERAGE, which is what M8 asks. It does not check each
command's output semantically, and it does not count a **recognised-but-silent**
command as driven — that is a limit of this oracle and is reported as its own
class, not folded into either total.

Order inside one boot is deliberate: **entry, then twin, then ``fw_version``,
then ``help``**. The entry goes first so nothing precedes it; ``help`` goes last
so a state change the entry caused cannot alter the menu we grade against.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "src"))

from rehostry_vesc_bldc_f405 import attack as A          # noqa: E402
from rehostry_vesc_bldc_f405 import paths                # noqa: E402
from rehostry_vesc_bldc_f405 import vesc_comm as vc      # noqa: E402

GUARD = os.path.join(_HERE, "m8_inventory_guard.json")

#: The firmware's own refusal, `terminal_process_string()`:
#:     commands_printf("Invalid command: %s\n"
#:                     "type help to list all available commands\n", argv[0]);
#: ⚠ Matched by CONTAINMENT, never by `startswith`. A `startswith` matcher on the
#: sibling row missed the newline-less reassembled text and cost a 34-minute arm,
#: which then under-reported its own parity.
REFUSAL_MARK = "Invalid command"

#: Knob for the NUMERATOR only (see PREDICTIONS-M8.md §6). `HAL_SEAM_CONTROL`
#: closes the seam and therefore voids the inventory too, so it cannot show
#: "inventory 52, parity 0"; this one can.
TWIN_ONLY = os.environ.get("VESC_M8_TWIN_ONLY") == "1"


def parse_inventory(lines):
    """The menu -> (tokens, pairs, why). Shape only; no image, no strings.

    Returns ``tokens=None`` when the menu is not INTACT, so a truncated drain
    VOIDS the measurement instead of reporting a smaller denominator.
    """
    why = {"line_count": len(lines)}
    if len(lines) < 4:
        why["void"] = "fewer than 4 lines came back"
        return None, None, why
    if lines[1] != "Valid commands are:":
        why["void"] = "preamble absent; got %r" % (lines[1],)
        return None, None, why
    # THE COMPLETENESS WITNESS. `help` ends with commands_printf(" "), so an
    # intact menu's last line is exactly one space. A count cannot detect its
    # own truncation; this can.
    if lines[-1] != " ":
        why["void"] = "sentinel absent; last line is %r" % (lines[-1],)
        return None, None, why
    body = lines[2:-1]
    cmds = [l for l in body if l and not l.startswith(" ")]
    desc = [l for l in body if l.startswith("  ")]
    other = [l for l in body if (l.startswith(" ") and not l.startswith("  "))
             or not l]
    why.update(body=len(body), cmd_shaped=len(cmds), desc_shaped=len(desc),
               other_shaped=len(other))
    if len(cmds) + len(desc) + len(other) != len(body):
        why["void"] = "shape classes do not sum to the body"
        return None, None, why
    if other:
        why["void"] = "unclassifiable line(s): %r" % (other[:3],)
        return None, None, why
    pairs = {c.split()[0]: c for c in cmds}
    if len(pairs) != len(cmds):
        why["void"] = "duplicate command token in the menu"
        return None, None, why
    why["sentinel_present"] = True
    return sorted(pairs), pairs, why


def check_guard(pairs):
    """Diagonal shrink guard. A mismatch EITHER WAY voids; it never shrinks."""
    g = json.load(open(GUARD))
    exp = g["pairs"]
    res = {"expected_denominator": g["denominator"],
           "observed_denominator": None if pairs is None else len(pairs),
           "expected_pairs_sha256": g["pairs_sha256"]}
    if pairs is None:
        res.update(ok=False, why="the menu did not parse; nothing to compare")
        return res
    got_sha = hashlib.sha256(
        json.dumps(sorted(pairs.items())).encode()).hexdigest()
    res["observed_pairs_sha256"] = got_sha
    missing = sorted(set(exp) - set(pairs))
    extra = sorted(set(pairs) - set(exp))
    changed = sorted(k for k in set(exp) & set(pairs) if exp[k] != pairs[k])
    res.update(missing=missing, extra=extra, arity_changed=changed)
    res["ok"] = (got_sha == g["pairs_sha256"] and not missing
                 and not extra and not changed)
    if not res["ok"]:
        res["why"] = ("VOID: the inventory moved. missing=%d extra=%d "
                      "arity_changed=%d" % (len(missing), len(extra),
                                            len(changed)))
    return res


def grade_entry(token, port, log_dir, nonce):
    """ONE fresh boot. Entry first, then the twin, then fw_version, then help."""
    rec = {"entry": token, "port": port, "nonce": nonce,
           "boot_is_its_own": True}
    sc = A.VescScenario(bridge_port=port,
                        python=os.environ.get("HAL_PY") or sys.executable,
                        log_dir=log_dir)
    rec["log"] = sc.log
    try:
        if not sc.boot(lambda *a, **k: None):
            rec["booted"] = False
            rec["startup_failure"] = sc.startup_failure
            return rec
        rec["booted"] = True

        # ---- ARM A: the entry itself, FIRST -------------------------------
        sent_a = nonce if TWIN_ONLY else token
        rec["arm_a_sent"] = sent_a
        a_lines = sc.terminal_lines(sent_a.encode(), first=25.0, quiet=6.0)
        rec["arm_a_lines"] = a_lines
        body_a = [l for l in a_lines if l.strip()
                  and not l.strip().startswith("-> ")]
        refused_a = any(REFUSAL_MARK in l for l in a_lines)
        rec["arm_a_reply_lines"] = len(body_a)
        rec["arm_a_refused"] = refused_a
        # A non-empty reply that is NOT the refusal. An empty reply is NOT a
        # pass: an absence-witness is true before the firmware acts.
        rec["arm_a_answered"] = bool(body_a) and not refused_a

        # ---- ARM B: the diagonal twin, a nonce minted THIS run ------------
        b_lines = sc.terminal_lines(nonce.encode(), first=25.0, quiet=4.0)
        rec["arm_b_lines"] = b_lines
        # The refusal must be the firmware's own AND must carry this run's
        # nonce: a replayed or recorded refusal carries a different one, and a
        # sleeping guest emits none at all.
        #
        # ⚠ BOTH ON ONE LINE, and this was a real defect in the first version of
        # this file, caught on its own smoke run. The terminal ECHOES the command
        # it was given, so `-> <nonce>` already contains the nonce; a check that
        # scanned the lines SEPARATELY was satisfied by the echo and would have
        # passed even if the refusal had carried a stale nonce. The diagonal is
        # the CONJUNCTION on a single rendered line.
        rec["arm_b_refused"] = any(REFUSAL_MARK in l for l in b_lines)
        rec["arm_b_nonce_anywhere"] = any(nonce in l for l in b_lines)
        rec["arm_b_carries_nonce"] = any(
            REFUSAL_MARK in l and nonce in l for l in b_lines)
        rec["arm_b_ok"] = rec["arm_b_refused"] and rec["arm_b_carries_nonce"]

        # ---- the seam, after ---------------------------------------------
        fw = sc.fw_version()
        rec["seam_alive_after"] = fw is not None
        rec["fw_version_payload"] = None if fw is None else fw.hex()

        # ---- the inventory, LAST, in this entry's own boot ----------------
        h = sc.terminal_lines(b"help", first=30.0, quiet=20.0)
        toks, pairs, why = parse_inventory(h)
        rec["inventory_why"] = why
        rec["inventory_tokens"] = toks
        rec["inventory_guard"] = check_guard(pairs)
        rec["token_in_own_menu"] = (toks is not None and token in toks)
    finally:
        sc.shutdown()
        rec["log_tail"] = [l for l in sc.log_text().splitlines()
                           if l.strip()][-8:]
    # THE VERDICT for this entry. Both arms, in this boot, or it is not driven.
    rec["driven"] = bool(rec.get("arm_a_answered") and rec.get("arm_b_ok")
                         and rec.get("token_in_own_menu"))
    rec["klass"] = ("driven" if rec["driven"] else
                    "refused_by_firmware" if rec.get("arm_a_refused") else
                    "recognised_but_silent"
                    if rec.get("booted") and rec.get("arm_b_ok")
                    and not rec.get("arm_a_reply_lines") else
                    "not_measured")
    return rec


def main(argv):
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--entry", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--log-dir", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)

    fw = paths.firmware_bin()
    before = hashlib.sha256(open(fw, "rb").read()).hexdigest()
    # os.urandom per row, never a shared seed.
    nonce = "n" + os.urandom(6).hex()
    rec = grade_entry(a.entry, a.port, a.log_dir, nonce)
    rec["fw_sha256_before"] = before
    rec["fw_sha256_after"] = hashlib.sha256(open(fw, "rb").read()).hexdigest()
    rec["fw_unchanged"] = rec["fw_sha256_before"] == rec["fw_sha256_after"]
    rec["twin_only_knob"] = TWIN_ONLY
    rec["core"] = _core()
    rec["uptime"] = subprocess.run(["uptime"], capture_output=True,
                                   text=True).stdout.strip()
    with open(a.out, "w") as fh:
        json.dump(rec, fh, indent=1, default=str)
    print("ENTRY %-26s driven=%-5s klass=%-21s inv=%s guard=%s"
          % (a.entry, rec.get("driven"), rec.get("klass"),
             rec.get("inventory_why", {}).get("cmd_shaped"),
             rec.get("inventory_guard", {}).get("ok")))
    return 0


def _core():
    """The core THIS interpreter resolves, and its SHA at read time.

    ⚠ Never a SHA quoted for a moving ref: `origin/dev` is resolved here, now.
    """
    try:
        import halucinator
        src = os.path.dirname(os.path.dirname(
            os.path.abspath(halucinator.__file__)))
        top = os.path.dirname(src)

        def g(*args):
            return subprocess.run(["git", "-C", top] + list(args),
                                  capture_output=True, text=True).stdout.strip()
        od = g("rev-parse", "origin/dev")
        head = g("rev-parse", "HEAD")
        anc = subprocess.run(["git", "-C", top, "merge-base",
                              "--is-ancestor", od, head],
                             capture_output=True).returncode == 0
        return {"tree": top, "head": head, "origin_dev_at_read_time": od,
                "origin_dev_is_ancestor_of_head": anc,
                "dirty": bool(g("status", "--porcelain", "--untracked-files=no"))}
    except Exception as exc:                                   # noqa: BLE001
        return {"error": repr(exc)}


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
