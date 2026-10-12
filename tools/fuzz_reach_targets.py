#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Derive the VESC terminal's command set from the IMAGE'S OWN DISPATCH and
resolve every command to its own handler, for the fuzz-reach hooks
(lane s1011-laneS).

The census entry set for this row (52 commands) came from the guest's own
``help`` output (``tools/m8_inventory_guard.json``). This tool derives the set
a second, independent way -- from the code that DISPATCHES -- and cross-checks
the two. Inputs: ``configs/vesc.bin`` and the build's own symbol table
``configs/vesc_addrs.yaml`` (emitted from the same ELF by
``tools/extract_firmware.py``; it names ``terminal_process_string``,
``strcmp``, ``terminal_register_command_callback`` and ``commands_printf``).

``terminal_process_string(char *str)`` does, in this build, in this order:

1. tokenise into argv, lower-case argv[0] in place; argv[0] is held in **r4**;
2. a REGISTERED-CALLBACK loop: ``for i < callback_write: if cbf &&
   strcmp(argv[0], callbacks[i].command) == 0: cbf(argc, argv); return`` --
   so a registered name SHADOWS a built-in one;
3. a BUILT-IN ``strcmp`` chain: each link is ``ldr r1,=<name>; mov r0,r4;
   bl strcmp`` followed by ``cbnz``/``cbz``/``cmp r0,#0;bne``/``beq``. The
   handler is the EQUAL edge; the NOT-EQUAL edge must land exactly on the next
   link. The walk starts at the callback loop's exit and stops at the first
   not-equal edge that is not a link, which must be the block that prints the
   firmware's own ``Invalid command: %s`` (asserted, else the tool raises);
4. that default block.

Registered callbacks are found by scanning every function body in the image
for ``bl terminal_register_command_callback`` with r0 (command) and r3 (cbf)
loaded from PC-relative literals. Their handler is ``cbf(argc, argv)``.

Identity at hit time: a built-in handler block runs with r4 == argv[0] (the
string ``strcmp`` just matched); a callback runs with r1 == argv. Both are read
from guest memory by the hook.

Writes ``src/rehostry_vesc_bldc_f405/configs/fuzz_reach_targets.json``;
``--check`` re-derives and compares (PASS/FAIL), touching nothing.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

import capstone  # type: ignore
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CFG = ROOT / "src" / "rehostry_vesc_bldc_f405" / "configs"
IMG = CFG / "vesc.bin"
SYMS = CFG / "vesc_addrs.yaml"
GUARD = HERE / "m8_inventory_guard.json"
OUT = CFG / "fuzz_reach_targets.json"
ROW = "device-vesc-bldc-f405"
B = 0x08000000
USART3_IRQ = 39          # STM32F405 RM0090 vector table position


class Undetermined(Exception):
    pass


def _load():
    d = IMG.read_bytes()
    sy = yaml.safe_load(SYMS.read_text())["symbols"]
    names: dict = {}
    for a, n in sy.items():
        names.setdefault(n, []).append(a)
    return d, sy, names


def _one(names, n):
    v = names.get(n) or []
    if len(v) != 1:
        raise Undetermined("symbol %s: %d matches" % (n, len(v)))
    return v[0]


def _md():
    return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)


def _lit(d, i):
    """Value of `ldr rX, [pc, #imm]`, else None."""
    if not i.mnemonic.startswith("ldr") or "[pc" not in i.op_str:
        return None
    imm = int(i.op_str.split("#")[-1].rstrip("]"), 16)
    a = ((i.address + 4) & ~3) + imm
    return struct.unpack_from("<I", d, a - B)[0]


def _cstr(d, a, limit=64):
    if not (B <= a < B + len(d)):
        return None
    o = a - B
    e = d.find(b"\x00", o, o + limit)
    return d[o:e].decode("latin-1") if e > o else None


def _body(d, sy, lo):
    """Disassemble one function: from lo to the next symbol of ANY kind
    ($d literal pools included), resuming after $d at the next $t."""
    keys = sorted(a for a in sy if B <= a < B + len(d))
    nxt_fn = min((a for a in keys if a > lo and not str(sy[a]).startswith("$")),
                  default=B + len(d))
    marks = sorted((a, sy[a]) for a in keys if lo < a < nxt_fn and sy[a] in ("$d", "$t"))
    md = _md()
    out = []
    cur, mode = lo, "$t"
    for a, n in marks + [(nxt_fn, "$end")]:
        if mode == "$t" and a > cur:
            p = cur
            while p < a:
                got = list(md.disasm(d[p - B:a - B], p))
                out += got
                p = (got[-1].address + got[-1].size) if got else p
                if p < a and (not got or got[-1].address + got[-1].size < a):
                    p += 2
        cur, mode = a, n
    return out


def _target(op):
    return int(op.split("#")[-1], 16)


def derive() -> dict:
    d, sy, names = _load()
    tps = _one(names, "terminal_process_string")
    strcmp = _one(names, "strcmp")
    reg = _one(names, "terminal_register_command_callback")
    printf = _one(names, "commands_printf")
    ins = _body(d, sy, tps)
    at = {i.address: k for k, i in enumerate(ins)}
    bl_strcmp = "#0x%x" % strcmp

    def link_at(addr):
        """A chain link starting at addr: ldr r1,=lit ; mov r0,r4 ; bl strcmp."""
        k = at.get(addr)
        if k is None or k + 2 >= len(ins):
            return None
        a, b, c = ins[k], ins[k + 1], ins[k + 2]
        if not (a.mnemonic.startswith("ldr") and a.op_str.startswith("r1, [pc")):
            return None
        if not (b.mnemonic == "mov" and b.op_str == "r0, r4"):
            return None
        if not (c.mnemonic == "bl" and c.op_str == bl_strcmp):
            return None
        name = _cstr(d, _lit(d, a))
        # the equal / not-equal edges
        j = k + 3
        while ins[j].mnemonic == "mov" and ins[j].op_str.endswith(", r0"):
            j += 1              # `mov r7, r0` etc. keep the result
        x = ins[j]
        br = x.address if x.mnemonic in ("cbnz", "cbz") else ins[j + 1].address
        if x.mnemonic == "cbnz":
            eq, ne = ins[j + 1].address, _target(x.op_str)
        elif x.mnemonic == "cbz":
            eq, ne = _target(x.op_str), ins[j + 1].address
        elif x.mnemonic == "cmp" and x.op_str == "r0, #0":
            y = ins[j + 1]
            if y.mnemonic in ("bne", "bne.w"):
                eq, ne = ins[j + 2].address, _target(y.op_str)
            elif y.mnemonic in ("beq", "beq.w"):
                eq, ne = _target(y.op_str), ins[j + 2].address
            else:
                raise Undetermined("link %#x: unexpected %s %s" % (addr, y.mnemonic, y.op_str))
        else:
            raise Undetermined("link %#x: unexpected %s %s" % (addr, x.mnemonic, x.op_str))
        return {"name": name, "site": a.address, "eq": eq, "ne": ne, "branch": br}

    # The callback loop: the ONE strcmp site whose r1 is NOT a literal and
    # whose equal edge reaches a `blx` (the registered cbf).
    loops = []
    for k, i in enumerate(ins):
        if i.mnemonic == "bl" and i.op_str == bl_strcmp and ins[k - 2].mnemonic.startswith("ldr") \
                and "[pc" not in ins[k - 2].op_str:
            win = ins[k + 1:k + 6]
            if any(w.mnemonic == "blx" for w in win):
                loops.append(i.address)
    if len(loops) != 1:
        raise Undetermined("callback loop: %d candidate sites" % len(loops))
    # Its exit: the first conditional branch in the loop header that leaves it.
    k0 = at[loops[0]]
    exits = [w for w in ins[max(0, k0 - 10):k0] if w.mnemonic in ("ble", "bge", "bls", "bhs")]
    if len(exits) != 1:
        raise Undetermined("callback loop exit: %d candidates" % len(exits))
    start = _target(exits[0].op_str)
    chain, seen, addr = [], set(), start
    while True:
        ln = link_at(addr)
        if ln is None:
            break
        if addr in seen:
            raise Undetermined("chain loops at %#x" % addr)
        seen.add(addr)
        chain.append(ln)
        addr = ln["ne"]
    default = addr
    k = at.get(default)
    fmt = _cstr(d, _lit(d, ins[k])) if k is not None else None
    if not (fmt and fmt.startswith("Invalid command") and ins[k + 1].op_str == "r1, r4"
            and ins[k + 2].op_str == "#0x%x" % printf):
        raise Undetermined("chain end %#x is not the Invalid-command block (%r)" % (default, fmt))

    # The function's common exit: `add sp, #..` then `pop {.., pc}` (via vpop).
    def _is_exit(a):
        k = at.get(a)
        return (k is not None and ins[k].mnemonic == "add" and ins[k].op_str.startswith("sp, ")
                and any(w.mnemonic.startswith("pop") and "pc" in w.op_str for w in ins[k + 1:k + 3]))
    exits_fn = sorted({c["eq"] for c in chain if _is_exit(c["eq"])})
    for c in chain:
        c["eq_is_function_exit"] = _is_exit(c["eq"])

    # Registered callbacks, image-wide.
    fn = sorted(a for a, n in sy.items() if B <= a < B + len(d)
                and not str(n).startswith("$") and (struct.unpack_from("<H", d, a - B)[0] != 0xFFFF))
    regs, unresolved = [], []
    want = "#0x%x" % reg
    for a in fn:
        body = _body(d, sy, a)
        for k, i in enumerate(body):
            if i.mnemonic in ("bl", "b.w") and i.op_str == want:
                # Walk back to the previous call/branch (which would clobber
                # r0..r3); the LAST write to r0 and r3 before the call wins.
                got: dict = {}
                for j in range(k - 1, max(k - 40, -1), -1):
                    m = body[j].mnemonic
                    if m in ("bl", "blx", "bx", "b", "b.w") or m.startswith("cb") or (m.startswith("pop") and "pc" in body[j].op_str):
                        break
                    r = body[j].op_str.split(",")[0].strip()
                    if r in ("r0", "r3") and r not in got:
                        got[r] = _lit(d, body[j])
                cmd = _cstr(d, got["r0"]) if got.get("r0") else None
                cbf = got.get("r3")
                if cmd is None or cbf is None or not (cbf & 1):
                    unresolved.append({"site": "0x%08x" % i.address, "fn": sy[a]})
                    continue
                regs.append({"name": cmd, "site": i.address, "cbf": cbf & ~1,
                             "cbf_symbol": sy.get(cbf & ~1), "registered_in": sy[a]})
    vec = struct.unpack_from("<%dI" % (16 + 82), d, 0)
    return {"image_sha256": hashlib.sha256(d).hexdigest(), "image_bytes": len(d),
            "terminal_process_string": tps, "strcmp": strcmp,
            "register_fn": reg, "callback_loop_site": loops[0], "chain_start": start,
            "chain": chain, "default": default, "default_format": fmt,
            "function_exit": exits_fn,
            "callbacks": regs, "unresolved_registrations": unresolved,
            "systick_handler": vec[15] & ~1, "usart3_handler": vec[16 + USART3_IRQ] & ~1}


def build() -> dict:
    r = derive()
    guard = json.loads(GUARD.read_text())
    help_set = list(guard["pairs"])
    cb_names = [c["name"] for c in r["callbacks"]]
    ch_names = [c["name"] for c in r["chain"]]
    if len(set(cb_names)) != len(cb_names) or len(set(ch_names)) != len(ch_names):
        raise Undetermined("duplicate names in the dispatch")
    shadowed = sorted(set(cb_names) & set(ch_names))
    entries = []
    for c in r["chain"]:
        if c["eq_is_function_exit"]:
            # An EMPTY case: its equal edge is the function's common exit,
            # which every command that returns also runs. The handler is then
            # the DISPATCH DECISION itself: hook the conditional branch and
            # require r0 (strcmp's result) == 0 with r4 == the name.
            entries.append({"id": c["name"], "name": c["name"], "kind": "builtin",
                            "handler": "0x%08x" % c["branch"], "site": "0x%08x" % c["site"],
                            "abi": "decision", "empty_case_exit": "0x%08x" % c["eq"]})
            continue
        entries.append({"id": c["name"], "name": c["name"], "kind": "builtin",
                        "handler": "0x%08x" % c["eq"], "site": "0x%08x" % c["site"],
                        "abi": "r4"})
    for c in r["callbacks"]:
        entries.append({"id": c["name"], "name": c["name"], "kind": "callback",
                        "handler": "0x%08x" % c["cbf"], "site": "0x%08x" % c["site"],
                        "cbf_symbol": c["cbf_symbol"], "registered_in": c["registered_in"],
                        "abi": "argv_r1"})
    dispatch_set = [e["name"] for e in entries]
    # Order entries as the census lists them (the help menu), then the rest.
    order = {n: k for k, n in enumerate(help_set)}
    entries.sort(key=lambda e: (order.get(e["name"], 10 ** 6), e["name"]))
    for i, e in enumerate(entries):
        e["next_entry"] = entries[(i + 1) % len(entries)]["id"]
        e["in_help"] = e["name"] in order
    hooks = []
    by: dict = {}
    for e in entries:
        by.setdefault((e["handler"], e["abi"]), []).append(e["id"])
    for (a, abi), ids in sorted(by.items()):
        hooks.append({"addr": a, "kind": abi, "label": "|".join(ids)})
    hooks.append({"addr": "0x%08x" % r["default"], "kind": "default",
                  "label": "Invalid-command default"})
    for x in r["function_exit"]:
        hooks.append({"addr": "0x%08x" % x, "kind": "exit",
                      "label": "terminal_process_string common exit (shared label)"})
    hooks.append({"addr": "0x%08x" % r["systick_handler"], "kind": "isr",
                  "label": "SysTick_Handler"})
    hooks.append({"addr": "0x%08x" % r["usart3_handler"], "kind": "isr",
                  "label": "USART3 IRQ handler"})
    ids = sorted(e["id"] for e in entries)
    return {
        "row": ROW, "bin": IMG.name, "image_sha256": r["image_sha256"],
        "source": "the image's own dispatch in terminal_process_string (strcmp chain "
                  "+ registered-callback loop) and every terminal_register_command_callback "
                  "call site; cross-checked against the help-menu guard",
        "terminal_process_string": "0x%08x" % r["terminal_process_string"],
        "callback_loop_site": "0x%08x" % r["callback_loop_site"],
        "chain_start": "0x%08x" % r["chain_start"],
        "default": "0x%08x" % r["default"], "default_format": r["default_format"],
        "function_exit": ["0x%08x" % x for x in r["function_exit"]],
        "chain_links": len(r["chain"]), "callbacks_registered": len(r["callbacks"]),
        "unresolved_registrations": r["unresolved_registrations"],
        "callback_shadows_builtin": shadowed,
        "help_guard_size": len(help_set),
        "dispatch_not_in_help": sorted(set(dispatch_set) - set(help_set)),
        "help_not_in_dispatch": sorted(set(help_set) - set(dispatch_set)),
        "inventory_size": len(entries),
        "id_set_sha256": hashlib.sha256("\n".join(ids).encode()).hexdigest(),
        "entries": entries, "hooks": hooks,
        "isr_control": {"systick": "0x%08x" % r["systick_handler"],
                        "usart3": "0x%08x" % r["usart3_handler"]},
        "controls": [
            {"id": "ctl-undeclared", "input": "rehostryqz",
             "why": "absent from the dispatch and from the image bytes"},
            {"id": "ctl-prefix-hel", "input": "hel", "why": "strict prefix of `help`"},
            {"id": "ctl-suffix-helpx", "input": "helpx", "why": "`help` plus one byte"},
            {"id": "ctl-upper-HELP", "input": "HELP",
             "why": "argv[0] is lower-cased in place before dispatch: expected to REACH help"},
            {"id": "ctl-empty", "input": "", "why": "an empty command string"},
            {"id": "ctl-silence", "input": None, "why": "send nothing; only the liveness probe"},
        ],
    }


def main(argv: list) -> int:
    t = build()
    blob = json.dumps(t, indent=1) + "\n"
    if "--check" in argv:
        try:
            cur = OUT.read_text()
        except OSError:
            print("FAIL (absent)")
            return 1
        ok = cur == blob
        print("PASS entries=%d hooks=%d id_set_sha256=%s" % (
            len(t["entries"]), len(t["hooks"]), t["id_set_sha256"][:16])
            if ok else "FAIL (differs)")
        return 0 if ok else 1
    OUT.write_text(blob)
    print(json.dumps({k: v for k, v in t.items() if k not in ("entries", "hooks")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
