#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Derive this device's flash image + symbol table from the VESC build's ELF.

The VESC firmware is built from source (see ``FIRMWARE.md``); the build leaves an
**unstripped** ``builds/100_250/100_250.elf`` next to the ``.bin``. This tool
turns that ELF into what the re-host needs, in
``src/rehostry_vesc_bldc_f405/configs/``:

  ``vesc.bin``         every PT_LOAD laid at its PHYSICAL address from
                       ``0x08000000``, then padded out to the STM32F405RG's full
                       1 MiB of flash with ``0xFF``. The padding is not
                       cosmetic: ``flash_helper.c`` treats the QML/LISP sectors
                       as *erased* only when they read ``0xFF``, and
                       ``qmlui_check()``'s verdict is one of the bytes the
                       pre-boot prediction in PROVENANCE.md depends on.

  ``vesc_addrs.yaml``  decimal address -> name, for intercept resolution. Thumb
                       LSB cleared; ``STT_FUNC`` wins ties; and where two symbols
                       share an address a **unique synthetic name** is emitted
                       for each, because the core keeps one name per address and
                       an intercept keyed on the loser is dropped in silence
                       (playbook §2.26).

It HARD-FAILS if the recovered vector table disagrees with what
``vesc_config.yaml`` hardcodes, or if the reset vector does not point at Thumb
code — a different upstream revision, or a wrong load base, then fails at
extraction instead of somewhere unrelated mid-boot (playbook §2.81).

Firmware bytes are never committed (`.gitignore`); this regenerates them::

    python3 tools/extract_firmware.py /path/to/builds/100_250/100_250.elf
"""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys

# STM32F405RG: 1 MiB of flash at the ARMv7-M code region base. The VESC
# application is linked at the flash base itself -- VESC's own bootloader lives
# in sector 11 at 0x080E0000, i.e. ABOVE the application -- so unlike most
# bootloader-offset images there is no hole under this one.
FLASH_BASE = 0x08000000
FLASH_SIZE = 0x00100000

# Recovered from the pinned build (vedderb/bldc @ e4db57a8, `make 100_250`).
# vesc_config.yaml hardcodes the same two values; they must agree.
EXPECT_INIT_SP = 0x20000800
EXPECT_RESET = 0x0800C001  # Thumb


def _load_image(elf) -> bytearray:
    chunks = []
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD" or not seg["p_filesz"]:
            continue
        paddr = seg["p_paddr"]
        data = seg.data()[: seg["p_filesz"]]
        chunks.append((paddr, data))
        note = "" if paddr == seg["p_vaddr"] else \
            f"  (vaddr 0x{seg['p_vaddr']:08x} -- .data init image in flash)"
        print(f"  LOAD paddr 0x{paddr:08x} len 0x{len(data):06x}{note}")
    if not chunks:
        raise SystemExit("error: no PT_LOAD segments in the ELF")

    # Erased flash reads 0xFF. flash_helper.c scans for that.
    image = bytearray(b"\xff" * FLASH_SIZE)
    for paddr, data in chunks:
        off = paddr - FLASH_BASE
        if off < 0 or off + len(data) > FLASH_SIZE:
            raise SystemExit(
                f"error: segment 0x{paddr:08x}+0x{len(data):x} is outside the "
                f"1 MiB flash window at 0x{FLASH_BASE:08x}")
        image[off:off + len(data)] = data
    return image


def _guard_vector_table(image: bytearray) -> tuple[int, int]:
    init_sp, reset = struct.unpack_from("<II", image, 0)
    if init_sp != EXPECT_INIT_SP or reset != EXPECT_RESET:
        raise SystemExit(
            f"error: vector table mismatch -- got SP 0x{init_sp:08x} "
            f"reset 0x{reset:08x}, expected SP 0x{EXPECT_INIT_SP:08x} "
            f"reset 0x{EXPECT_RESET:08x}.\n"
            "       A different upstream revision or hardware target shifts "
            "every address; vesc_config.yaml's entry_addr/init_sp would then be "
            "silently wrong.")
    if not reset & 1:
        raise SystemExit(
            f"error: reset vector 0x{reset:08x} has no Thumb bit -- this is not "
            "an ARMv7-M image loaded at the right base")
    off = (reset & ~1) - FLASH_BASE
    if not 0 <= off < FLASH_SIZE - 2:
        raise SystemExit(
            f"error: reset vector 0x{reset:08x} is outside the flash window")
    # The reset handler must be code, not data. ChibiOS' crt0 opens by loading
    # the process stack pointer, so the first halfword is an `ldr rN,[pc,#imm]`
    # (0x48xx-0x4Fxx) or an `msr`/`mov` -- what matters is that it is NOT the
    # 0xFFFF of erased flash or 0x0000 of a hole.
    first = struct.unpack_from("<H", image, off)[0]
    if first in (0x0000, 0xFFFF):
        raise SystemExit(
            f"error: reset vector 0x{reset:08x} points at 0x{first:04x} -- "
            "erased flash or a hole, i.e. the load base is wrong")
    print(f"  vector table OK: init_SP 0x{init_sp:08x} reset 0x{reset:08x} "
          f"(first halfword 0x{first:04x})")
    return init_sp, reset


def _symbols(elf) -> dict[int, str]:
    """addr -> name, with a UNIQUE name per address (playbook §2.26)."""
    rank_of = {"STT_FUNC": 3, "STT_OBJECT": 2, "STT_NOTYPE": 1}
    by_addr: dict[int, list[tuple[int, str]]] = {}
    for sec in elf.iter_sections():
        if sec.name not in (".symtab", ".dynsym"):
            continue
        for sym in sec.iter_symbols():
            name = sym.name
            if not name:
                continue
            stype = sym["st_info"]["type"]
            if stype not in rank_of:
                continue
            addr = sym["st_value"]
            if not addr:
                continue
            if stype == "STT_FUNC":
                addr &= ~1
            by_addr.setdefault(addr, []).append((rank_of[stype], name))

    out: dict[int, str] = {}
    aliases: dict[int, list[str]] = {}
    for addr, cands in by_addr.items():
        cands.sort(key=lambda c: (-c[0], c[1]))
        out[addr] = cands[0][1]
        if len(cands) > 1:
            aliases[addr] = [n for _, n in cands[1:]]
    return out, aliases


# `dsb sy ; b .` -- the tail of CMSIS' NVIC_SystemReset(). Encoded little-endian
# as halfwords F3BF 8F4F (dsb sy) then E7FE (b .).
_DSB_SPIN = bytes((0xBF, 0xF3, 0x4F, 0x8F, 0xFE, 0xE7))
# AIRCR VECTKEY | SYSRESETREQ, the literal the same function loads.
_AIRCR_KEY = (0x05FA0004).to_bytes(4, "little")


def _find_sysresetreq(image: bytes) -> list:
    """Addresses of the `b .` at the end of every inlined NVIC_SystemReset().

    unicorn implements no SYSRESETREQ, so the reset the firmware asks for never
    arrives and this self-branch is a permanent, silent hang (playbook §2.54).
    VESC reaches one on its **first** boot: ``flash_helper_verify_flash_memory()``
    finds the app-CRC slot blank, programs the CRC, and reboots so the value
    takes effect.

    The site is found by scanning rather than hardcoded, so a rebuild moves it
    automatically instead of leaving an intercept pointing at the wrong
    instruction (the technique from playbook §2.31). ``NVIC_SystemReset`` is
    ``__STATIC_INLINE`` in CMSIS, so there is no symbol to key on -- the
    extractor emits a synthetic one.
    """
    hits = []
    start = 0
    while True:
        i = image.find(_DSB_SPIN, start)
        if i < 0:
            break
        start = i + 2
        # The AIRCR key is a literal in the pool just past the code.
        if _AIRCR_KEY in image[i:i + 1024]:
            hits.append(FLASH_BASE + i + 4)     # the `b .` itself
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("elf", help="path to builds/100_250/100_250.elf")
    ap.add_argument("--outdir", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "src", "rehostry_vesc_bldc_f405", "configs"))
    a = ap.parse_args()

    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        print("needs pyelftools:  pip install pyelftools", file=sys.stderr)
        return 1

    raw = open(a.elf, "rb").read()
    print(f"elf sha256 {hashlib.sha256(raw).hexdigest()}  ({len(raw)} bytes)")

    with open(a.elf, "rb") as fh:
        elf = ELFFile(fh)
        image = _load_image(elf)
        _guard_vector_table(image)
        syms, aliases = _symbols(elf)

    outdir = a.outdir
    os.makedirs(outdir, exist_ok=True)

    bin_path = os.path.join(outdir, "vesc.bin")
    with open(bin_path, "wb") as fh:
        fh.write(image)
    used = sum(1 for b in image if b != 0xFF)
    print(f"wrote {bin_path}  ({len(image)} bytes, {used} non-erased)  "
          f"sha256 {hashlib.sha256(bytes(image)).hexdigest()}")

    # Synthetic symbols for sites that have no name of their own.
    resets = _find_sysresetreq(bytes(image))
    if not resets:
        raise SystemExit(
            "error: no inlined NVIC_SystemReset() found. VESC reaches one on "
            "its first boot (flash_helper_verify_flash_memory), and without an "
            "intercept there the rehost hangs forever on a `b .` with nothing "
            "in the log. If the idiom really has gone, update _find_sysresetreq.")
    for n, addr in enumerate(resets):
        syms[addr] = "sysresetreq_spin_%d" % n
        print(f"  synthetic symbol sysresetreq_spin_{n} @ 0x{addr:08x} "
              "(NVIC_SystemReset self-branch)")

    yaml_path = os.path.join(outdir, "vesc_addrs.yaml")
    with open(yaml_path, "w") as fh:
        fh.write("# Generated by tools/extract_firmware.py -- do not edit.\n")
        fh.write("# vedderb/bldc @ e4db57a8d90747091a4ea98c381fe3efc83a8722, "
                 "`make 100_250`.\n")
        fh.write("symbols:\n")
        for addr in sorted(syms):
            fh.write(f"  {addr}: {syms[addr]}\n")
    print(f"wrote {yaml_path}  ({len(syms)} symbols, "
          f"{len(aliases)} addresses with aliases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
