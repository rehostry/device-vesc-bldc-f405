# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The ladder, the two new rungs, and the reader repairs they depend on.

Every floor the ladder can print is pinned here, so the floor and the ladder
cannot drift apart (playbook w96.4). Every check in this file was driven to the
WRONG SIDE on purpose before it was committed -- see
``tools/mutate_checks.py``, which plants thirteen defects and requires all
thirteen to be caught.
"""
from __future__ import annotations

import ast
import inspect
import itertools
import re
import struct
import textwrap

import pytest

from rehostry_vesc_bldc_f405 import attack as A


NAMES = ("gates_ok", "guest_ran", "own_init", "seam_up", "m4", "m6", "m7")


def _all():
    return {c: A._ladder(*c)
            for c in itertools.product((False, True), repeat=len(NAMES))}


# --------------------------------------------------------------- the floors
@pytest.mark.parametrize("combo,want", [
    # gates_ok guest own_init seam m4 m6 m7
    ((False, True, True, True, True, True, True), "ERROR"),
    ((True, False, True, True, True, True, True), "M0"),
    ((True, True, False, True, True, True, True), "M1"),
    # THE FLOOR w91.1 IS ABOUT. The old grader could only answer M0 or M1 here
    # -- `boot()` returned False and the early return never reached an
    # assignment -- for a guest that ran, reached main() and printed its own
    # initialisation trace. That is M2 by the fleet's own definition.
    ((True, True, True, False, False, False, False), "M2"),
    ((True, True, True, False, True, True, True), "M2"),
    ((True, True, True, True, False, False, False), "M3"),
    ((True, True, True, True, True, False, False), "M4"),
    ((True, True, True, True, True, True, False), "M6"),
    ((True, True, True, True, True, False, True), "M7"),
    ((True, True, True, True, True, True, True), "M7"),
])
def test_every_floor_is_pinned(combo, want):
    assert A._ladder(*combo) == want


def test_printable_matches_the_declared_set():
    assert set(_all().values()) == set(A.LADDER_PRINTABLE)


def test_no_dead_branch():
    """WRITTEN vs PRINTABLE, by ``ast``.

    Enumeration alone reports a dead branch as "that rung never printed", which
    reads like a fact about the firmware rather than a defect in the grader
    (w100.1). ``ast`` and not ``grep``: the docstring names five rungs.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(A._ladder)))
    written = {str(n.value.value) for n in ast.walk(tree)
               if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)
               and re.fullmatch(r"M\d|ERROR", str(n.value.value))}
    assert written - set(_all().values()) == set(), "dead branch in the ladder"
    assert set(_all().values()) - written == set()


def test_no_m5_branch():
    """One interface (the USART3 COMM seam) -> RULES §1a leaves M5 UNDEFINED.
    A branch with no term would be w88.6's defect in a taller hat."""
    src = textwrap.dedent(inspect.getsource(A._ladder))
    assert '"M5"' not in src and "'M5'" not in src
    assert "M5" not in A.LADDER_PRINTABLE


def test_m7_does_not_chain_on_m6():
    """RULES §1a (2026-09-02): a scorer that requires M6 before M7 is a defect
    in the scorer, not a property of the ladder."""
    assert A._ladder(True, True, True, True, True, False, True) == "M7"


def test_the_ladder_is_called_from_exactly_one_place_and_in_a_finally():
    mod = ast.parse(inspect.getsource(A))
    calls = [n for n in ast.walk(mod)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "_ladder"]
    assert len(calls) == 1, "the ladder must be applied from ONE place"
    run = next(n for n in ast.walk(mod)
               if isinstance(n, ast.FunctionDef) and n.name == "run_attack")
    finals = [t for n in ast.walk(run) if isinstance(n, ast.Try)
              for t in n.finalbody]
    assert any(isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
               and getattr(s.value.func, "id", "") == "_finalize"
               for s in finals), "_finalize must run in a finally block"


# ------------------------------------------------------ the fleet invariant
def test_landed_means_m4_and_only_m4():
    for combo in itertools.product((False, True), repeat=len(NAMES)):
        res = {"landed": combo[4], "gated_out": not combo[0],
               "gate1_cpu_started": combo[1] or None,
               "gate2_child_cpu_s": A.WORK_FLOOR_CPU_S + 1 if combo[1] else 0.0,
               "m6": {"ok": combo[5]}, "m7": {"ok": combo[6]}}

        class _S:
            log = "/nonexistent"

            @staticmethod
            def log_text():
                return ("BOOT: conf_general_init\n" if combo[2] else "") + \
                       (A.BOOT_MARKER if combo[3] else "")
        A._finalize(_S(), res)
        if res["landed"]:
            assert res["milestone"] in ("M4", "M6", "M7")


# ----------------------------------------------------- the mispredict knob
def test_rotation_lands_on_a_DIFFERENT_answer_for_every_class():
    """w96.2/w100.4: a knob that rotates onto the next CLASS is weak when
    classes share an answer, and six of this row's nine share one."""
    assert len(set(A.ANSWER_IDS)) == len(A.ANSWER_IDS)
    for a in A.ANSWER_IDS:
        assert A._rotate(a) != a
    assert sorted(A._rotate(a) for a in A.ANSWER_IDS) == sorted(A.ANSWER_IDS)


def test_falsify_modes_are_validated_not_swallowed():
    assert "" in A.FALSIFY_MODES
    for m in ("m6-freeze", "m7-valid-only", "m7-mispredict"):
        assert m in A.FALSIFY_MODES
    assert "m7-validonly" not in A.FALSIFY_MODES


def test_the_valid_only_arm_sends_the_twin_not_the_malformed_frame():
    """The one control the rung is worthless without (w91.2): every malformed
    send must be conditioned on the mode, structurally."""
    src = textwrap.dedent(inspect.getsource(A._m7_phase))
    tree = ast.parse(src)
    sends = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and getattr(n.func, "attr", "") == "_send"]
    assert sends, "the phase must send something"
    raw_sends = [n for n in sends
                 if any(isinstance(a, ast.Name) and a.id == "raw"
                        for a in n.args)]
    assert not raw_sends, ("the malformed frame must never be sent "
                           "unconditionally -- it has to go through the "
                           "mode-conditioned expression")


# ---------------------------------------------------- the firmware's limits
def test_clamp_predictions_are_the_firmwares_own_rules():
    assert A._predict_in_current_max(5000.0) == 300.0
    assert A._predict_in_current_max(-5000.0) == -300.0
    assert A._predict_in_current_max(299.5) == 299.5
    assert A._predict_scale(9.0) == 1.0
    assert A._predict_scale(-0.5) == 0.0
    assert A._predict_scale(0.5) == 0.5


def test_float_encodings_match_vesc_buffer_helpers():
    assert A._f16_bytes(0.5) == struct.pack(">h", 5000).hex()
    assert A._f32_bytes(300.0) == struct.pack(">f", 300.0).hex()
    # the ONE-ULP bracket the clamp class stands on: the two neighbours of the
    # limit encode differently, so "stored" and "clamped" are distinguishable.
    up = A._f32_neighbour(300.0, up=True)
    down = A._f32_neighbour(300.0, up=False)
    assert A._f32_bytes(A._predict_in_current_max(up)) == A._f32_bytes(300.0)
    assert A._f32_bytes(A._predict_in_current_max(down)) == A._f32_bytes(down)
    assert A._f32_bytes(down) != A._f32_bytes(300.0)
    assert A._f32_bytes(up) != A._f32_bytes(300.0)
    assert up > 300.0 > down


def test_each_clamp_field_is_predicted_with_its_OWN_encoder():
    """The refutation of my own second version, kept as a test.

    The observed-answer test was written as "the read-back equals the clamped
    prediction and is neither `_f32_bytes(bad)` nor `_f16_bytes(bad)`" -- an
    encoder chosen by `or`. `_f16_bytes(300.00003)` is 3_000_000 in an int16,
    so it RAISED mid-arm on the first live run, after the M6 phase had already
    passed 6/6. The phase now binds one encoder per field.
    """
    with pytest.raises(struct.error):
        A._f16_bytes(300.0)
    src = textwrap.dedent(inspect.getsource(A._m7_phase))
    assert "enc, predict = _f32_bytes, _predict_in_current_max" in src
    assert "enc, predict = _f16_bytes, _predict_scale" in src
    assert "predict_clamped = enc(predict(bad_v))" in src
    # and the class must send something the firmware has to CHANGE
    assert "assert predict_unclamped != predict_clamped" in src


def test_nextafter_on_a_double_would_have_made_the_clamp_class_test_nothing():
    """The refutation of my own first version, kept as a test.

    `math.nextafter(300.0, 1e9)` steps a DOUBLE; packed to binary32 it rounds
    back onto 300.0, so the 'one step above the limit' value the clamp class
    sends would have BEEN the limit -- the firmware would have had nothing to
    clamp and the class would have passed while measuring nothing."""
    import math
    naive = struct.unpack(">f", struct.pack(
        ">f", math.nextafter(300.0, 1e9)))[0]
    assert naive == 300.0
    assert A._f32_neighbour(300.0, up=True) != 300.0


# ------------------------------------------------- the seam re-establishment
def test_the_flush_is_at_least_the_decoders_own_buffer():
    """`packet_process_byte`'s only unconditional reset is
    `data_len >= PACKET_BUFFER_LEN`. A flush shorter than that cannot force it,
    and measured on this device three plain retries at 30 s each did not
    recover the seam while 544 bytes recovered it in 0.03 s."""
    assert A.PACKET_BUFFER_LEN == 520
    assert A.RESYNC_FLUSH >= A.PACKET_BUFFER_LEN


def test_every_malformed_class_is_followed_by_a_resync():
    """A class graded after a dead seam is w78.5's corpse. The phase must call
    `resync()` at least once per class and AND the result into a flag."""
    src = textwrap.dedent(inspect.getsource(A._m7_phase))
    assert src.count("sc.resync()") >= 3
    # The flag must be a CONJUNCT OF THE VERDICT, checked with `ast`.
    # A text scan for the name passes on a version that has dropped it from
    # `ok` and merely mentions it in a log line -- which is exactly what my
    # own first version of this test did, and the mutation harness caught it
    # (w74: a text scan cannot answer a structural question).
    tree = ast.parse(src)
    ok_expr = None
    for n in ast.walk(tree):
        if (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Subscript)
                and isinstance(n.targets[0].slice, ast.Constant)
                and n.targets[0].slice.value == "ok"):
            ok_expr = n.value
    assert ok_expr is not None, "the M7 phase must assign res['ok']"
    conjuncts = ast.dump(ok_expr)
    assert "seam_alive_after_every_class" in conjuncts, (
        "the seam-alive flag must be a conjunct of the M7 verdict, not just "
        "a line in the log")


def test_the_three_witness_counters_are_separate_fields():
    """w100.3: a control that has to drive a number to zero must not be scored
    against a number we can pad, so a rendered string, a limit the firmware
    declined to move and a limit it substituted are counted apart."""
    src = textwrap.dedent(inspect.getsource(A._m7_phase))
    for k in ("refusal_witnesses_seen", "state_refusals_seen",
              "clamp_refusals_seen"):
        assert k in src
        assert 'res["%s"] > 0' % k in src


def test_the_m6_phase_requires_n_of_n_not_at_least_one():
    src = textwrap.dedent(inspect.getsource(A._m6_phase))
    assert 'res["rounds_ok"] == rounds' in src
    assert 'res["counter_ok"] == res["counter_total"]' in src
    assert ">= 1" not in src


def test_a_phase_that_never_ran_reports_unobservable():
    src = textwrap.dedent(inspect.getsource(A.run_attack))
    assert '"unobservable": True' in src
    assert "if not SEAM_CONTROL:" in src
