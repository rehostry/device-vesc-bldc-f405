<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Building the firmware

The VESC project publishes **no prebuilt `.bin` in the firmware repository**
(VESC Tool bundles release images; `vedderb/bldc` is source only). This device
therefore builds its firmware from source, and **no firmware bytes are committed
here** — the image is GPL-3.0 and the fleet rule is that firmware is never
committed. Build it once, run `tools/extract_firmware.py`, and the device is
ready.

## What was built, exactly

| | |
|---|---|
| upstream | <https://github.com/vedderb/bldc> |
| pinned commit | `e4db57a8d90747091a4ea98c381fe3efc83a8722` (`master`, 2026-08-04T12:27:08Z) |
| hardware target | `100_250` — Trampa VESC 100/250, STM32F405RG, `hwconf/trampa/100_250/hw_100_250.h` |
| firmware version | 7.01, test version 1 (`conf_general.h:24-27`) |
| toolchain | `arm-none-eabi-gcc (Arm GNU Toolchain 15.2.Rel1) 15.2.1`, at `/Users/user/Development/toolchains/arm-gnu-15.2/bin` |
| host | macOS 15 (Darwin 25.5.0), arm64 |
| licence | GPL-3.0-only |

Artifacts produced by that build:

| file | size | sha256 |
|---|---|---|
| source tarball (`codeload` of the pinned commit) | 21 329 577 | `b3b23723c5aac14c443004b723ed420d7e9eace2bb7d0cea62527dcd132e4338` |
| `build/100_250/100_250.elf` | 4 007 972 | `2e9f3014a30a4f7a3a3df813ffcffdbe9ffd110622af15eefcca94f267bda335` |
| `build/100_250/100_250.bin` | 524 280 | `2598dc695be3456108f9cf6ed51c19c44dbf72065c73ab1252a2a1c1fa962f87` |
| `configs/vesc.bin` (what this device runs) | 1 048 576 | `ea6e96f9c282f93fe0199db77991dcfd422cbf88f174a8043e987455b643bed9` |

`configs/vesc.bin` is **not** the `make`-produced `.bin`. The extractor lays the
ELF's PT_LOAD segments at their physical addresses and pads the rest of the 1 MiB
flash with `0xFF` — erased flash — where `objcopy` filled the inter-section gaps
with `0x00`. That matters: VESC's emulated EEPROM (`driver/eeprom.h`, pages at
`0x08004000` and `0x08008000`) recognises an unused page by its `0xFFFF` status
halfword, and `flash_helper.c` scans the QML/LISP sectors for `0xFF` to decide
whether they hold code. Everything the ELF actually contains is byte-identical
between the two.

## Recipe

```bash
# 1. Source, pinned. (A shallow git clone works too; the repo has no submodules.)
mkdir -p ~/scratch && cd ~/scratch
curl -L -o bldc.tar.gz \
  https://codeload.github.com/vedderb/bldc/tar.gz/e4db57a8d90747091a4ea98c381fe3efc83a8722
tar xzf bldc.tar.gz && mv bldc-e4db57a8* bldc && cd bldc

# 2. Build. `make <board>` is the documented target; output lands in build/<board>/.
PATH=/Users/user/Development/toolchains/arm-gnu-15.2/bin:$PATH make 100_250 -j8

# 3. Turn the (unstripped) ELF into this device's flash image + symbol table.
cd /path/to/device-vesc-bldc-f405
python3 tools/extract_firmware.py ~/scratch/bldc/build/100_250/100_250.elf
```

## Notes on building it on macOS

The build worked **first time**, with no patches, on macOS 15/arm64 with GCC
15.2. Three things are worth recording anyway, because they are the parts that
could have gone wrong:

* **Use ARM's toolchain, not Homebrew's.** `/opt/homebrew/bin/arm-none-eabi-gcc`
  (16.1.0) ships **no libc** — its include search path contains only gcc's own
  directory, so every translation unit dies on `stdint.h: No such file or
  directory` (playbook §2.46). The ARM GNU toolchain at
  `/Users/user/Development/toolchains/arm-gnu-15.2` has a full newlib and is what
  the hashes above come from.
* **GCC 15 builds it cleanly.** VESC targets much older compilers; this build
  produced no errors. The linker emits three cosmetic warnings (`_getpid`/`_kill`
  not implemented in newlib-nano, and "LOAD segment with RWX permissions"). Two
  regions come out nearly full — `flash` 95.0 %, `flash2` 94.8 %, `ram4`
  99.6 % — so a target with more enabled features may not fit.
* **The tree does not need to be a git checkout.** The Makefile asks git for a
  branch name and commit hash to `-D` into the build; from a tarball those come
  out empty, which only affects two version strings the firmware prints.
* **`make` writes to `build/`, not `builds/`.** The artifacts are
  `build/100_250/100_250.{elf,bin,hex,map,list}`.

## Verifying you built the same thing

`tools/extract_firmware.py` hard-fails unless the recovered vector table is
exactly `initial SP 0x20000800`, `reset 0x0800c001`, and unless the reset vector
points at real code. A different upstream revision or hardware target shifts
every address, so it fails at extraction rather than somewhere unrelated
mid-boot.

`tests/test_structure.py` then checks the artifact itself: that the config's
`entry_addr`/`init_sp` match the image, that every intercepted symbol resolves,
and that VESC's `crc16_tab` appears verbatim in the image bytes (playbook §2.19 —
the compiler can rewrite a CRC loop, so the table in the shipped artifact is the
thing to verify).
