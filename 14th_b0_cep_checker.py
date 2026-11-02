from __future__ import annotations

import importlib.util
import struct
import sys
import unittest
from pathlib import Path


TOOL_DIR = Path(__file__).resolve().parent
PATCHER_PATH = TOOL_DIR / "14th_b0_cep_patcher.py"
spec = importlib.util.spec_from_file_location("cep_patcher", PATCHER_PATH)
if spec is None or spec.loader is None:
    raise ImportError(f"Could not load patcher module from {PATCHER_PATH}")
cep = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cep
spec.loader.exec_module(cep)


def make_ffs(
    body: bytes,
    *,
    large: bool = False,
    file_checksum: bool = False,
) -> bytes:
    header_size = 32 if large else 24
    file_size = header_size + len(body)
    ffs = bytearray(file_size)
    ffs[0x12] = 0x07
    attributes = 0
    if large:
        attributes |= cep.FFS_ATTRIB_LARGE_FILE
        struct.pack_into("<Q", ffs, 0x18, file_size)
    else:
        ffs[0x14:0x17] = file_size.to_bytes(3, "little")
    if file_checksum:
        attributes |= cep.FFS_ATTRIB_CHECKSUM
    ffs[0x13] = attributes
    ffs[0x17] = 0xF8
    ffs[0x11] = (
        cep.calculate_ffs_file_checksum(body)
        if file_checksum
        else cep.FFS_FIXED_CHECKSUM
    )
    ffs[0x10] = cep.calculate_ffs_header_checksum(ffs[:header_size])
    ffs[header_size:] = body
    return bytes(ffs)


class FfsChecksumTests(unittest.TestCase):
    def test_standard_header_sentinel(self) -> None:
        validation = cep.validate_ffs(make_ffs(b"payload"))
        self.assertEqual(validation["header_type"], "header")
        self.assertTrue(validation["header_checksum_valid"])
        self.assertTrue(validation["file_checksum_sentinel"])

    def test_header2_file_checksum(self) -> None:
        ffs = make_ffs(b"header2-body", large=True, file_checksum=True)
        validation = cep.validate_ffs(ffs)
        self.assertEqual(validation["header_type"], "header2")
        self.assertEqual(validation["header_size"], 32)
        self.assertTrue(validation["file_checksum_enabled"])
        self.assertEqual(
            validation["file_checksum"],
            validation["file_checksum_calculated"],
        )

    def test_file_checksum_is_recalculated_after_body_change(self) -> None:
        ffs = make_ffs(b"AAAA", file_checksum=True)
        changed = bytearray(ffs)
        changed[-1] ^= 0x01

        updated, recalculated, calculated = cep.update_ffs_file_checksum(bytes(changed))

        self.assertTrue(recalculated)
        self.assertIsNotNone(calculated)
        validation = cep.validate_ffs(updated)
        self.assertEqual(validation["file_checksum"], calculated)
        self.assertEqual(validation["header_checksum"], ffs[0x10])


class ModuleMappingTests(unittest.TestCase):
    def module(self, base: int, size: int) -> cep.ModuleInfo:
        return cep.ModuleInfo(
            base=base,
            size=size,
            guid=cep.MODULE_GUID,
            text=cep.MODULE_NAME,
            info_path="",
            te_body_path="",
        )

    def test_exact_mapping_is_limited_to_module(self) -> None:
        te_body = b"VZ" + b"T" * 30
        rom = b"\x00" * 0x80 + te_body + b"\x00" * 0x40
        module = self.module(0x80, len(te_body) + 0x20)
        self.assertEqual(cep.map_te_to_rom(rom, te_body, module), 0x80)

    def test_duplicate_te_in_module_is_rejected(self) -> None:
        te_body = b"VZ" + b"T" * 30
        rom = b"\x00" * 0x80 + te_body + b"\x00" * 8 + te_body
        module = self.module(0x80, len(rom) - 0x80)
        with self.assertRaises(cep.PatchError):
            cep.map_te_to_rom(rom, te_body, module)

    def test_te_outside_module_is_rejected(self) -> None:
        te_body = b"VZ" + b"T" * 30
        rom = te_body + b"\x00" * 0x80 + te_body
        module = self.module(0x100, len(te_body))
        with self.assertRaises(cep.PatchError):
            cep.map_te_to_rom(rom, te_body, module)


class ToolchainTests(unittest.TestCase):
    def test_default_output_stays_next_to_source(self) -> None:
        source = Path("bios/example/board.rom")
        self.assertEqual(
            cep.default_output_path(source),
            Path("bios/example/board_IA_GT_CEP_OFF.rom"),
        )

    def test_tested_uefiextract_version_passes(self) -> None:
        self.assertTrue(
            cep.validate_uefiextract_version(
                cep.UEFIEXTRACT_TESTED_VERSION,
                False,
            )
        )

    def test_untested_uefiextract_version_requires_override(self) -> None:
        with self.assertRaises(cep.PatchError):
            cep.validate_uefiextract_version("NE alpha 99", False)
        self.assertFalse(cep.validate_uefiextract_version("NE alpha 99", True))


class TeSectionTests(unittest.TestCase):
    def make_te(self, section_name: bytes, *, executable: bool) -> bytes:
        raw = b"\x90" * 16
        te = bytearray(0x28 + 40 + len(raw))
        te[:2] = b"VZ"
        te[4] = 1
        te[0x28:0x30] = section_name.ljust(8, b"\x00")
        struct.pack_into("<IIII", te, 0x30, len(raw), 0, len(raw), 0x50)
        characteristics = 0x60000020 if executable else 0xC0000040
        struct.pack_into("<I", te, 0x28 + 36, characteristics)
        te[0x50:] = raw
        return bytes(te)

    def test_executable_text_section_is_found(self) -> None:
        self.assertEqual(
            cep.te_text_ranges(self.make_te(b".text", executable=True)),
            [(0x50, 0x60)],
        )

    def test_executable_non_text_section_is_found(self) -> None:
        self.assertEqual(
            cep.te_text_ranges(self.make_te(b".code", executable=True)),
            [(0x50, 0x60)],
        )

    def test_no_executable_section_fails_closed(self) -> None:
        with self.assertRaises(cep.PatchError):
            cep.te_text_ranges(self.make_te(b".data", executable=False))


def make_fsp_s_pe(
    *,
    include_801: bool = True,
    include_901: bool = True,
    valid_gate: bool = True,
) -> bytes:
    pe = bytearray(0x800)
    pe[:2] = b"MZ"
    pe_header = 0x80
    struct.pack_into("<I", pe, 0x3C, pe_header)
    pe[pe_header : pe_header + 4] = b"PE\x00\x00"
    struct.pack_into("<H", pe, pe_header + 6, 1)
    struct.pack_into("<H", pe, pe_header + 0x14, 0xE0)
    optional = pe_header + 0x18
    struct.pack_into("<H", pe, optional, 0x10B)
    section = optional + 0xE0
    pe[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", pe, section + 16, len(pe))
    struct.pack_into("<I", pe, section + 20, 0)
    struct.pack_into("<I", pe, section + 36, 0x60000020)

    function_start = 0x300
    pe[function_start : function_start + 10] = bytes.fromhex(
        "55 8B EC 83 EC 20 53 56 8B F1"
    )
    if include_801:
        pe[0x320:0x325] = cep.FSP_S_MOV_EDX_801
    if include_901:
        pe[0x330:0x335] = cep.FSP_S_MOV_EDX_901
    helper = 0x500
    helper_call = 0x335
    pe[helper_call] = 0xE8
    struct.pack_into("<i", pe, helper_call + 1, helper - (helper_call + 5))
    pe[0x340:0x344] = cep.FSP_S_FUNCTION_EPILOGUE

    gate_start = 0x40A
    parent_call = 0x430
    if valid_gate:
        gate = bytes.fromhex("83 7D E0 00 74 02 90 90 83 7D E4 00 75 02 90 90 8B 5D E8")
        gate += b"\x90" * (parent_call - gate_start - len(gate))
    else:
        gate = b"\x90" * (parent_call - gate_start - 3) + bytes.fromhex("8B 5D E8")
    pe[gate_start:parent_call] = gate
    pe[parent_call] = 0xE8
    struct.pack_into(
        "<i",
        pe,
        parent_call + 1,
        function_start - (parent_call + 5),
    )
    pe[parent_call + 5 : parent_call + 8] = bytes.fromhex("8B 43 1C")

    pe[helper : helper + 6] = bytes.fromhex("8B 45 08 8B 4D 0C C3")
    return bytes(pe)


class FspSPatchTests(unittest.TestCase):
    def test_native_801_901_pair_is_detected(self) -> None:
        detection = cep.detect_fsp_s_patch(make_fsp_s_pe())

        self.assertIsNotNone(detection)
        assert detection is not None
        self.assertEqual(detection.function_start, 0x300)
        self.assertEqual(detection.helper, 0x500)
        self.assertEqual(detection.gate_start, 0x40A)
        self.assertEqual(detection.preserved_instruction_offset, 0x10)

    def test_single_801_or_901_is_skipped(self) -> None:
        self.assertIsNone(cep.detect_fsp_s_patch(make_fsp_s_pe(include_901=False)))
        self.assertIsNone(cep.detect_fsp_s_patch(make_fsp_s_pe(include_801=False)))

    def test_paired_signatures_with_invalid_gate_fail_closed(self) -> None:
        with self.assertRaises(cep.PatchError):
            cep.detect_fsp_s_patch(make_fsp_s_pe(valid_gate=False))

    def test_patch_preserves_load_at_original_gate_offset(self) -> None:
        pe = make_fsp_s_pe()
        detection = cep.detect_fsp_s_patch(pe)
        assert detection is not None

        patched, payload, _, _, gate = cep.patch_fsp_s_pe(pe, detection)

        self.assertEqual(
            patched[
                detection.injection_offset : detection.injection_offset + len(payload)
            ],
            payload,
        )
        self.assertEqual(payload[-6:], cep.FSP_S_PAYLOAD_SUFFIX)
        preserved = detection.preserved_instruction
        start = detection.preserved_instruction_offset
        self.assertEqual(gate[:start], b"\x90" * start)
        self.assertEqual(gate[start : start + len(preserved)], preserved)
        self.assertEqual(
            gate[start + len(preserved) :],
            b"\x90" * (len(gate) - start - len(preserved)),
        )


class ControlFlowTests(unittest.TestCase):
    def test_ebp_local_slot_is_proven(self) -> None:
        body = bytes.fromhex("55 8B EC 83 EC 0C 56")
        body += b"\x90" * (0x10 - len(body))
        start, depth = cep.validate_status_buffer_frame(
            body,
            0x10,
            [(0, 0x11)],
        )
        self.assertEqual(start, 0)
        self.assertEqual(depth, -0x10)

    def test_saved_esi_in_ebp_minus_four_is_rejected(self) -> None:
        body = bytes.fromhex("55 8B EC 56")
        body += b"\x90" * (0x10 - len(body))
        with self.assertRaises(cep.PatchError):
            cep.validate_status_buffer_frame(body, 0x10, [(0, 0x11)])

    def test_conditional_branch_with_equal_frame_states_passes(self) -> None:
        body = bytearray.fromhex("55 8B EC 83 EC 0C 56 74 02 90 90")
        body += b"\x90" * (0x10 - len(body))
        start, depth = cep.validate_status_buffer_frame(
            bytes(body),
            0x10,
            [(0, 0x11)],
        )
        self.assertEqual(start, 0)
        self.assertEqual(depth, -0x10)

    def test_push_pop_pair_releases_temporary_slot(self) -> None:
        body = bytearray.fromhex("55 8B EC 50 58 83 EC 04")
        body += b"\x90" * (0x10 - len(body))
        start, depth = cep.validate_status_buffer_frame(
            bytes(body),
            0x10,
            [(0, 0x11)],
        )
        self.assertEqual(start, 0)
        self.assertEqual(depth, -4)

    def test_plain_ret_helper_passes(self) -> None:
        ret_offset, instruction, count, max_offset = cep.analyze_helper_returns(
            b"\xc3",
            0,
            [(0, 1)],
        )
        self.assertEqual(
            (ret_offset, instruction, count, max_offset),
            (0, "ret", 1, 0),
        )

    def test_helper_four_argument_offsets_pass(self) -> None:
        body = bytes.fromhex("8B 45 14 C3")
        _, _, _, max_offset = cep.analyze_helper_returns(body, 0, [(0, len(body))])
        self.assertEqual(max_offset, 0x14)

    def test_helper_fifth_argument_offset_is_rejected(self) -> None:
        body = bytes.fromhex("8B 45 18 C3")
        with self.assertRaises(cep.PatchError):
            cep.analyze_helper_returns(body, 0, [(0, len(body))])

    def test_original_call_with_exactly_four_arguments_passes(self) -> None:
        body = bytearray.fromhex("6A 00 6A 03 68 37 01 00 00 6A 01 E8")
        call_site = len(body) - 1
        helper = call_site + 5
        body += struct.pack("<i", helper - (call_site + 5))
        body += b"\xc3"
        arguments = cep.validate_original_cep_call(
            bytes(body),
            call_site,
            helper,
            [(0, len(body))],
        )
        self.assertEqual(len(arguments), 4)

    def test_original_call_with_fifth_argument_is_rejected(self) -> None:
        body = bytearray.fromhex("6A 05 6A 00 6A 03 68 37 01 00 00 6A 01 E8")
        call_site = len(body) - 1
        helper = call_site + 5
        body += struct.pack("<i", helper - (call_site + 5))
        body += b"\xc3"
        with self.assertRaises(cep.PatchError):
            cep.validate_original_cep_call(
                bytes(body),
                call_site,
                helper,
                [(0, len(body))],
            )

    def test_source_inside_instruction_is_detected(self) -> None:
        body = bytes.fromhex("55 8B EC B8 E8 00 00 00 C3")
        self.assertTrue(
            cep.source_inside_decoded_instruction(body, 4, 0, len(body), [0])
        )
        self.assertFalse(
            cep.source_inside_decoded_instruction(body, 3, 0, len(body), [0])
        )

    def test_any_aligned_preceding_push_is_rejected(self) -> None:
        body = bytes.fromhex("05 00 00 6A 01")
        self.assertTrue(cep.has_immediate_preceding_push(body, 5, 0))

    def test_ret_imm16_on_reachable_path_is_rejected(self) -> None:
        body = bytes.fromhex("74 01 C3 C2 10 00")
        with self.assertRaises(cep.PatchError):
            cep.analyze_helper_returns(body, 0, [(0, len(body))])

    def test_raw_xref_inside_another_branch_is_ignored(self) -> None:
        data = bytearray(0x40)
        data[0] = 0xE8
        struct.pack_into("<i", data, 1, 0x20 - 5)
        data[8] = 0xE9
        data[9] = 0xEB
        data[10] = 0x16

        hits = cep.raw_direct_xrefs(data, 0, len(data), 0x20, 0x30)

        self.assertTrue(any("raw 0x0" in hit for hit in hits))
        self.assertFalse(any("raw 0x9" in hit for hit in hits))

    def test_raw_xref_at_instruction_boundary_is_reported(self) -> None:
        data = bytearray.fromhex("55 8B EC 90 90 90 90 90 E9")
        data += struct.pack("<i", 0x20 - (0x08 + 5))
        data += b"\x90" * (0x40 - len(data))

        hits = cep.raw_direct_xrefs(
            data,
            0,
            len(data),
            0x20,
            0x30,
            [0],
        )

        self.assertTrue(any("raw 0x8" in hit for hit in hits))


if __name__ == "__main__":
    unittest.main()
