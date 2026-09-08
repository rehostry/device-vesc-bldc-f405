#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Drive every new check to the WRONG SIDE on purpose, and require it to fire.

A test suite that has only ever been green is a suite nobody has measured. This
plants one defect at a time in ``attack.py`` (or the test file), runs the
suite, and requires it to FAIL. Anything that stays green is a check that
cannot see the thing it was written for -- which is how w100.1's thirteenth
mutation escaped: an ``M5`` branch planted *after* the M6/M7 returns, where it
was unreachable, so the enumeration never printed it and the dead-branch test
was the only thing that could have caught it. Both variants are here.

⚠ Two hygiene rules this tool obeys, both of which have cost real time on this
fleet:

* **Clear ``__pycache__`` between arms** (w93.4). CPython's ``.pyc`` validity
  check is (source mtime as an INTEGER SECOND, source size), so a same-second,
  size-preserving edit and its restore are indistinguishable to it and the
  stale bytecode is trusted -- a FALSE RESTORE that looks exactly like "my fix
  did nothing".
* **Restore from bytes held in memory**, not from a copy on disk, and verify
  the restore with a digest.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATTACK = ROOT / "src" / "rehostry_vesc_bldc_f405" / "attack.py"
TESTS = ROOT / "tests"

#: (name, file, old, new). Each must make the suite FAIL.
MUTATIONS = [
    ("floor: M2 collapses back to M1 (w91.1's downward false floor)",
     ATTACK, '    if not seam_up:\n        return "M2"',
     '    if not seam_up:\n        return "M1"'),
    ("floor: the ERROR path becomes a rung",
     ATTACK, '    if not gates_ok:\n', '    if False and not gates_ok:\n'),
    ("floor: M0 and M1 swap",
     ATTACK, '    if not guest_ran:\n        return "M0"',
     '    if not guest_ran:\n        return "M1"'),
    ("chain: M7 is made to require M6",
     ATTACK, '    if m7:\n        return "M7"',
     '    if m7 and m6:\n        return "M7"'),
    ("DEAD M5 branch, planted where it can never be reached",
     ATTACK, '    return "M4"\n', '    return "M4"\n    return "M5"\n'),
    ("LIVE M5 branch with no term",
     ATTACK, '    if m7:\n        return "M7"',
     '    if m4 and not m6:\n        return "M5"\n    if m7:\n        return "M7"'),
    ("rotation lands on the SAME answer (w96.2)",
     ATTACK, "    return ANSWER_IDS[(i + 1) % len(ANSWER_IDS)]",
     "    return ANSWER_IDS[i]"),
    ("the three witness counters are folded into one (w100.3)",
     ATTACK, '        and res["clamp_refusals_seen"] > 0)',
     '        and True)'),
    ("M6 accepts 1-of-N instead of N-of-N (Rule 2)",
     ATTACK, '                     and res["rounds_ok"] == rounds',
     '                     and res["rounds_ok"] >= 1'),
    ("the seam-alive flag is dropped from the M7 verdict (w78.5)",
     ATTACK, '        and res["seam_alive_after_every_class"]\n', '        \n'),
    ("the flush is made shorter than the decoder's own buffer",
     ATTACK, "RESYNC_FLUSH = PACKET_BUFFER_LEN + 24",
     "RESYNC_FLUSH = 64"),
    ("the clamp uses math.nextafter on a DOUBLE, so it clamps nothing",
     ATTACK, "    bits += 1 if up else -1", "    bits += 0"),
    ("the ladder is applied outside the finally block",
     ATTACK, "        _finalize(sc, result)\n        sc.shutdown()",
     "        sc.shutdown()"),
    ("`landed` is allowed below M4 (the fleet invariant)",
     ATTACK, '    result["landed"] = bool(result.get("landed")) and \\\n'
             '        result["milestone"] in ("M4", "M6", "M7")',
     '    result["landed"] = bool(result.get("landed"))'),
    ("the valid-only arm sends the malformed frame anyway (w91.2)",
     ATTACK, '        sc._send(good if mode == "m7-valid-only" else raw)',
     '        sc._send(raw)'),
]


def clear_pycache() -> None:
    for d in ROOT.rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)


def run_suite() -> bool:
    clear_pycache()
    r = subprocess.run(
        [sys.executable, "-m", "pytest", str(TESTS), "-q", "-p",
         "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
        env={**__import__("os").environ,
             "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"})
    return r.returncode == 0


def main() -> int:
    original = {p: p.read_bytes() for p in {m[1] for m in MUTATIONS}}
    digests = {p: hashlib.sha256(b).hexdigest() for p, b in original.items()}
    if not run_suite():
        print("BASELINE IS RED -- fix the suite before mutating it")
        return 2
    print("baseline: GREEN")
    caught = 0
    for name, path, old, new in MUTATIONS:
        text = original[path].decode()
        if text.count(old) != 1:
            print("  SKIPPED (anchor not unique: %d) %s"
                  % (text.count(old), name))
            continue
        path.write_text(text.replace(old, new, 1))
        red = not run_suite()
        path.write_bytes(original[path])
        clear_pycache()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digests[path], \
            "RESTORE FAILED -- do not trust anything after this line"
        print("  %-5s %s" % ("CAUGHT" if red else "MISSED", name))
        caught += int(red)
    print("%d of %d mutations caught" % (caught, len(MUTATIONS)))
    if not run_suite():
        print("POST-RESTORE SUITE IS RED -- the restore did not take")
        return 2
    return 0 if caught == len(MUTATIONS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
