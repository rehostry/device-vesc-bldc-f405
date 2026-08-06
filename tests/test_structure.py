# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""No-emulator structural tests for device-vesc-bldc-f405.

These run without booting anything. They check the things that go wrong
silently: a config that disagrees with the image, an intercept whose symbol does
not resolve (which is dropped in silence -- playbook §2.26), a CRC
implementation that is subtly wrong, and a peripheral map with an overlap or a
misaligned region.

The firmware image is not committed. Tests that need it skip when it is absent;
build it per FIRMWARE.md and run tools/extract_firmware.py.
"""
from __future__ import annotations

import os
import struct
import sys

import pytest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
CONFIGS = os.path.join(SRC, "rehostry_vesc_bldc_f405", "configs")
sys.path.insert(0, SRC)

FLASH_BASE = 0x08000000
EXPECT_INIT_SP = 0x20000800
EXPECT_RESET = 0x0800C001


def _cfg():
    with open(os.path.join(CONFIGS, "vesc_config.yaml")) as fh:
        return yaml.safe_load(fh)


def _addrs():
    with open(os.path.join(CONFIGS, "vesc_addrs.yaml")) as fh:
        return yaml.safe_load(fh)["symbols"]


def _image():
    path = os.path.join(CONFIGS, "vesc.bin")
    if not os.path.isfile(path):
        pytest.skip("firmware not built; see FIRMWARE.md")
    with open(path, "rb") as fh:
        return fh.read()


# --- the spawn contract -----------------------------------------------------

def test_spawn_argv_runs_the_installed_core():
    from rehostry_vesc_bldc_f405 import spawn
    argv = spawn.spawn_argv()
    assert argv[1:3] == ["-m", "halucinator.main"]
    assert "--emulator" in argv and argv[argv.index("--emulator") + 1] == "unicorn"
    # Deconflicted ZMQ bus ports: two devices left on the core's 5555/5556
    # defaults silently share one peripheral bus.
    assert argv[argv.index("--rx_port") + 1] == "6102"
    assert argv[argv.index("--tx_port") + 1] == "6103"


def test_spawn_env_strips_source_tree_injection():
    from rehostry_vesc_bldc_f405 import spawn
    os.environ["HALUCINATOR_SRC"] = "/nonexistent/x"
    os.environ["PYTHONPATH"] = "/nonexistent/x"
    try:
        env = spawn.spawn_env()
    finally:
        os.environ.pop("HALUCINATOR_SRC", None)
        os.environ.pop("PYTHONPATH", None)
    assert "HALUCINATOR_SRC" not in env
    assert "PYTHONPATH" not in env
    # The STM32F405 is an M4F and ChibiOS' crt0 touches the FPU immediately; the
    # YAML `cpu_model:` key does NOT select this (playbook §2.120).
    assert env["HAL_CORTEXM_CPU_MODEL"] == "UC_CPU_ARM_CORTEX_M4"
    # HAL_DET_TICK is inert on cortex-m unless the run is chunked (§2.50).
    assert int(env["HAL_IRQ_CHUNK"]) > 0


def test_config_files_ship_in_the_package():
    from rehostry_vesc_bldc_f405 import paths
    for f in paths.CONFIG_FILES + ["logging.cfg"]:
        assert (paths.configs_dir() / f).is_file(), f


# --- the config agrees with the image ---------------------------------------

def test_machine_matches_the_vector_table():
    cfg = _cfg()
    assert cfg["machine"]["entry_addr"] == EXPECT_RESET
    assert cfg["machine"]["init_sp"] == EXPECT_INIT_SP
    assert cfg["machine"]["vector_base"] == FLASH_BASE
    img = _image()
    init_sp, reset = struct.unpack_from("<II", img, 0)
    assert (init_sp, reset) == (EXPECT_INIT_SP, EXPECT_RESET)


def test_every_intercept_symbol_resolves():
    """An intercept whose `function:` does not resolve is DROPPED SILENTLY --
    the handler simply never runs, with no warning (playbook §2.26)."""
    cfg = _cfg()
    names = set(_addrs().values())
    missing = [i["function"] for i in cfg["intercepts"]
               if i["function"] not in names]
    assert not missing, "unresolvable intercept symbols: %r" % missing


def test_sysresetreq_sites_are_intercepted():
    """unicorn implements no SYSRESETREQ, so an un-intercepted
    NVIC_SystemReset() is a permanent silent hang (playbook §2.54). The
    extractor emits one synthetic symbol per site; every one must be covered."""
    syms = _addrs()
    sites = {n for n in syms.values() if n.startswith("sysresetreq_spin_")}
    assert sites, "the extractor found no NVIC_SystemReset site"
    covered = {i["function"] for i in _cfg()["intercepts"]}
    assert sites <= covered, "un-intercepted reset sites: %r" % (sites - covered)


def test_peripheral_regions_are_4k_aligned_and_do_not_overlap():
    """Regions must be 4 KiB-aligned multiples of 4 KiB (§2.61), and an overlap
    leaves the overlapping bytes mapped by NEITHER region (§2.39)."""
    spans = []
    for group in ("memories", "peripherals"):
        for name, r in _cfg()[group].items():
            base, size = r["base_addr"], r["size"]
            if group == "peripherals":
                assert base % 0x1000 == 0, name
                assert size % 0x1000 == 0 and size > 0, name
            spans.append((base, base + size, name))
    spans.sort()
    for (a0, a1, an), (b0, b1, bn) in zip(spans, spans[1:]):
        assert a1 <= b0, "%s [0x%x,0x%x) overlaps %s [0x%x,0x%x)" % (
            an, a0, a1, bn, b0, b1)


def test_the_die_uid_page_is_mapped_and_not_left_to_a_catch_all():
    """STM32_UUID_8 is 0x1FFF7A10 (conf_general.h:145) and COMM_FW_VERSION puts
    those twelve bytes in its reply. Unmapped it aborts the run (§2.80)."""
    from rehostry_vesc_bldc_f405.peripheral_models import stm32_sysmem as sm
    per = _cfg()["peripherals"]["uid_page"]
    assert per["base_addr"] <= sm.UID_ADDR < per["base_addr"] + per["size"]
    assert "Stm32SystemMemory" in per["emulate"]
    assert len(sm.UID_BYTES) == 12


# --- the protocol implementation --------------------------------------------

def test_crc16_matches_an_independent_implementation():
    """A structural CRC property test can have no teeth at all (§2.118): a
    'append the CRC and the remainder is zero' check passes for ANY tap
    constant. So compare against a bit-by-bit reference AND assert that the
    plausible wrong polynomial DISAGREES, proving the test can fail."""
    from rehostry_vesc_bldc_f405 import vesc_comm as vc

    def bitwise(buf, poly=0x1021):
        ck = 0
        for b in buf:
            ck ^= b << 8
            for _ in range(8):
                ck = ((ck << 1) ^ poly) & 0xFFFF if ck & 0x8000 else (ck << 1) & 0xFFFF
        return ck

    for data in (b"\x00", b"\x0e", bytes(range(256)), b"100_250\x00" * 7):
        assert vc.crc16(data) == bitwise(data)
    # 0x8005 (CRC-16/IBM) is the natural wrong guess; it must NOT agree.
    assert vc.crc16(bytes(range(64))) != bitwise(bytes(range(64)), poly=0x8005)


def test_crc16_table_is_in_the_image_verbatim():
    """GCC can replace a hand-written CRC loop with a table-driven one that
    looks nothing like the source (playbook §2.19), so verify the table in the
    SHIPPED ARTIFACT against an independently generated one."""
    from rehostry_vesc_bldc_f405 import vesc_comm as vc
    img = _image()
    packed = b"".join(struct.pack("<H", v) for v in vc.CRC16_TAB)
    assert packed in img, "VESC's crc16_tab is not in the image as expected"


def test_frame_round_trips_and_uses_the_right_length_form():
    from rehostry_vesc_bldc_f405 import vesc_comm as vc
    short = vc.frame(bytes([vc.COMM_FW_VERSION]))
    assert short == bytes.fromhex("020100000003")
    assert vc.unframe(short)[0] == bytes([0])
    big = vc.frame(bytes([vc.COMM_GET_MCCONF]) + b"\x5a" * 488)
    assert big[0] == 3 and (big[1] << 8 | big[2]) == 489
    assert vc.unframe(big)[0][0] == vc.COMM_GET_MCCONF
    # A corrupted CRC is not a frame -- try_decode_packet() drops it.
    bad = bytearray(short)
    bad[-3] ^= 0xFF
    assert vc.unframe(bytes(bad)) == (None, 0)


def test_float32_auto_matches_vescs_own_arithmetic():
    """buffer_append_float32_auto() builds the word out of frexpf() rather than
    punning the float; check the shortcut (`>f`) against a transcription of the
    firmware's actual arithmetic instead of assuming they agree."""
    import math
    from rehostry_vesc_bldc_f405 import vesc_comm as vc

    def vesc_encode(number):
        if abs(number) < 1.5e-38:
            number = 0.0
        sig, e = math.frexp(number)
        sig_abs = abs(sig)
        sig_i = 0
        if sig_abs >= 0.5:
            sig_i = int((sig_abs - 0.5) * 2.0 * 8388608.0)
            e += 126
        res = ((e & 0xFF) << 23) | (sig_i & 0x7FFFFF)
        if sig < 0:
            res |= 1 << 31
        return struct.pack(">I", res)

    for v in (0.0, 1.0, 60.0, -60.0, 271.0, 250.0, 0.5, 1234.5):
        assert vc.float32_auto(v) == vesc_encode(v), v


def test_mcconf_field_offsets_match_the_serializer():
    """confgenerator_serialize_mcconf() writes signature(4), then four bytes of
    modes, then l_current_max. The attack rewrites bytes at that offset, so if
    it is wrong the attack silently corrupts a different field."""
    from rehostry_vesc_bldc_f405 import vesc_comm as vc
    assert vc.MCCONF_OFF_SIGNATURE == 0
    assert vc.MCCONF_OFF_L_CURRENT_MAX == 4 + 4
    assert vc.MCCONF_OFF_L_CURRENT_MIN == vc.MCCONF_OFF_L_CURRENT_MAX + 4
    assert vc.MCCONF_SIGNATURE == 0x9307410D


# --- peripheral-model invariants --------------------------------------------

def test_can_msr_mirrors_mcr_in_both_directions():
    """A 'ready' bit that is always ready breaks the opposite wait (§2.72):
    can_lld_start waits for INAK to SET, then for it to CLEAR."""
    from rehostry_vesc_bldc_f405.peripheral_models.stm32_bxcan import (
        Stm32BxCan, MCR, MSR, MCR_INRQ, MSR_INAK)
    can = Stm32BxCan("can", 0x40006000, 0x1000)
    can.hw_write(0x400 + MCR, 4, MCR_INRQ)
    assert can.hw_read(0x400 + MSR, 4) & MSR_INAK
    can.hw_write(0x400 + MCR, 4, 0)
    assert not can.hw_read(0x400 + MSR, 4) & MSR_INAK


def test_gpio_input_register_reflects_what_the_pin_drives():
    """A push-pull output reads back on IDR the level it is driving; firmware
    leans on that to ask 'is this output already on?' (playbook §2.72/§2.72b)."""
    from rehostry_vesc_bldc_f405.peripheral_models.soc_catchall import (
        SocCatchAll, GPIO_BSRR, GPIO_IDR)
    gpio = SocCatchAll("gpio", 0x40020000, 0x3000)
    gpio.hw_write(GPIO_BSRR, 4, 1 << 5)          # set pin 5
    assert gpio.hw_read(GPIO_IDR, 4) & (1 << 5)
    gpio.hw_write(GPIO_BSRR, 4, 1 << (16 + 5))   # reset pin 5
    assert not gpio.hw_read(GPIO_IDR, 4) & (1 << 5)


def test_timer_counter_is_free_running_and_wraps_at_arr():
    """VESC's timer_sleep() blocks on TIM5->CNT; a stored-but-static counter
    makes that loop unsatisfiable."""
    from rehostry_vesc_bldc_f405.peripheral_models.soc_catchall import (
        SocCatchAll, TIM_ARR, TIM_CNT)
    tim = SocCatchAll("tim", 0x40000000, 0x4000)
    base = 0xC00                       # TIM5 within this region
    tim.hw_write(base + TIM_ARR, 4, 0xFFFFFFFF)
    a = tim.hw_read(base + TIM_CNT, 4)
    b = tim.hw_read(base + TIM_CNT, 4)
    assert b > a
    tim.hw_write(base + TIM_ARR, 4, 4)          # a short period
    tim.hw_write(base + TIM_CNT, 4, 0)
    seen = {tim.hw_read(base + TIM_CNT, 4) for _ in range(20)}
    assert max(seen) <= 4, seen


def test_stm32_crc_unit_matches_the_silicon():
    """A plausible-but-different CRC fails statistically rather than obviously
    (§2.82). 0xC704DD7B is the STM32 unit's answer for a single zero word."""
    from rehostry_vesc_bldc_f405.peripheral_models.stm32_clock import Stm32ClockBlock
    assert Stm32ClockBlock._crc32_word(0xFFFFFFFF, 0) == 0xC704DD7B


def test_rcc_reports_hsi_running_out_of_reset():
    """RCC_CR resets to 0x83 on silicon. A model that reads 0 is a lie the
    firmware acts on somewhere else entirely (playbook §2.84)."""
    from rehostry_vesc_bldc_f405.peripheral_models.stm32_clock import (
        Stm32ClockBlock, RCC_OFF, RCC_CR)
    blk = Stm32ClockBlock("clk", 0x40023000, 0x1000)
    assert blk.hw_read(RCC_OFF + RCC_CR, 4) & 1


def test_usart_reports_a_line_only_when_the_firmware_enabled_it():
    from rehostry_vesc_bldc_f405.peripheral_models import stm32_usart as u
    bus = u.get_uart_bus()
    port = bus.ports[u.BRIDGE_OFFSET]
    port.regs.clear()
    port.rx.clear()
    assert bus.pending_irq() is None            # peripheral disabled
    port.regs[u.CR1] = u.CR1_UE | u.CR1_RXNEIE
    assert bus.pending_irq() is None            # enabled, nothing received
    port.rx.append(0x02)
    assert bus.pending_irq() == 39              # USART3's NVIC line
    port.rx.clear()
    port.regs[u.CR1] = u.CR1_UE | u.CR1_TXEIE
    assert bus.pending_irq() == 39              # transmit is interrupt-driven too


def test_attack_contract():
    """playbook §2a: run_attack(on_stage=None, log_dir=None) -> dict."""
    import inspect
    from rehostry_vesc_bldc_f405 import attack
    sig = inspect.signature(attack.run_attack)
    assert list(sig.parameters) == ["on_stage", "log_dir"]
    assert callable(attack.main)
    # The attacker's value must be inside this hardware's own ceiling, or the
    # firmware clamps it and the read-back tests the clamp, not the write.
    assert 0 < attack.ATTACK_IN_CURRENT_MAX <= 300.0
    assert 0.0 <= attack.ATTACK_CURRENT_MAX_SCALE <= 1.0
