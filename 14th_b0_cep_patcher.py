#!/usr/bin/env python3
"""
Structure-only CEP-blind-write pipeline for UEFI BIOS images.

The script:
1. Extracts the ROM with UEFIExtract.
2. Locates and patches SiInitPreMemFsp by GUID.
3. Optionally locates SiInitFsp and its native 0x801/0x901 path.
4. Forces both FSP-M and FSP-S to send 0x901/1 data=3 when present.
5. Repacks compressed FSP-S images without changing FFS or ROM size.
6. Validates checksums, disassembly, diff ranges, and reparsed output.

No SHA256 allowlist or per-version offset profile is used. The source hash is
reported for traceability only. Patching proceeds only when every structural
anchor is found uniquely.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from bisect import bisect_right
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from capstone import CS_ARCH_X86, CS_GRP_JUMP, CS_MODE_32, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

try:
    from uefi_firmware import efi_compressor
except ImportError:
    efi_compressor = None


WORKSPACE = Path(__file__).resolve().parents[2]
TOOL_DIR = Path(__file__).resolve().parent
DEFAULT_UEFIEXTRACT = TOOL_DIR / "tools" / "UEFIExtract.exe"

MODULE_NAME = "SiInitPreMemFsp"
MODULE_GUID = "D9117BD7-0807-4F38-B773-AD86A791EAFC"
FSP_S_MODULE_NAME = "SiInitFsp"
FSP_S_MODULE_GUID = "80A845AC-210F-43B0-995B-477BE41AB4E8"
FSP_S_MOV_EDX_801 = bytes.fromhex("BA 01 08 00 00")
FSP_S_MOV_EDX_901 = bytes.fromhex("BA 01 09 00 00")
FSP_S_FUNCTION_EPILOGUE = bytes.fromhex("5E 5B C9 C3")
FSP_S_PARENT_GATE_BYTES = 0x26
FSP_S_COMPRESSED_SECTION_HEADER_SIZE = 9
FSP_S_PAYLOAD_PREFIX = bytes.fromhex("8D 4D F8 51 6A 03 33 C9 41 BA 01 09 00 00")
FSP_S_PAYLOAD_SUFFIX = bytes.fromhex("59 59 5E 5B C9 C3")
EXPECTED_FSP_S_PAYLOAD_SIZE = len(FSP_S_PAYLOAD_PREFIX) + 5 + len(FSP_S_PAYLOAD_SUFFIX)

BRANCH_PREFIX = bytes.fromhex("F6 46 1C 01 75 04 33 C0 EB")
CEP_OLD_CALL_PREFIX = bytes.fromhex("68 37 01 00 00 6A 01 E8")
FFS_ATTRIB_LARGE_FILE = 0x01
FFS_ATTRIB_CHECKSUM = 0x40
FFS_FIXED_CHECKSUM = 0xAA
IMAGE_SCN_MEM_EXECUTE = 0x20000000
UEFIEXTRACT_TESTED_VERSION = "NE alpha 75 (Jul 10 2026)"
MAX_LOCAL_DECODE_INSTRUCTIONS = 40000

EPILOGUES = {
    bytes.fromhex("5E C9 C3"): "pop esi; leave; ret",
    bytes.fromhex("5E 8B E5 5D C3"): "pop esi; mov esp,ebp; pop ebp; ret",
}

PAYLOAD_PREFIX = bytes.fromhex("8D 45 FC 50 6A 03 68 01 09 00 00 6A 01")
PAYLOAD_SUFFIX = bytes.fromhex("83 C4 10 33 C0")
CALL_OFFSET_IN_PAYLOAD = len(PAYLOAD_PREFIX)
EXPECTED_PAYLOAD_SIZE = 23


class PatchError(RuntimeError):
    pass


@dataclass
class ModuleInfo:
    base: int
    size: int
    guid: str
    text: str
    info_path: str
    te_body_path: str


@dataclass(frozen=True)
class FfsHeaderInfo:
    header_size: int
    file_size: int
    attributes: int
    uses_file_checksum: bool


@dataclass
class Analysis:
    profile_code: str
    profile_description: str
    profile_resolution: str
    source_sha256: str
    module: ModuleInfo
    te_body_size: int
    rom_te_base: int
    block_start_te: int
    epilogue_te: int
    block_size: int
    epilogue_asm: str
    old_cep_call_te: int
    helper_argument_count: int
    helper_arguments: list[str]
    helper_max_argument_offset: int
    helper_te: int
    helper_ret_offset_te: int
    helper_ret_instruction: str
    helper_return_count: int
    function_start_te: int
    frame_depth_at_block: int
    status_pointer_frame_offset: int
    external_xref_count: int
    ffs_header_size: int
    ffs_file_checksum_offset_rom: int | None
    new_call_site_te: int
    new_rel32: int
    payload_hex: str
    replacement_hex: str
    block_start_rom: int
    block_end_rom_exclusive: int


@dataclass
class FspSResult:
    status: str
    reason: str
    module_base: int | None = None
    module_size: int | None = None
    function_start: int | None = None
    injection_offset: int | None = None
    function_end: int | None = None
    helper: int | None = None
    helper_call_site: int | None = None
    helper_return_count: int | None = None
    helper_max_argument_offset: int | None = None
    mov_801_site: int | None = None
    mov_901_site: int | None = None
    parent_call_site: int | None = None
    gate_start: int | None = None
    preserved_instruction_offset: int | None = None
    preserved_instruction_hex: str | None = None
    gate_replacement_hex: str | None = None
    payload_hex: str | None = None
    original_pe_sha256: str | None = None
    patched_pe_sha256: str | None = None
    pe_offset_in_decompressed_body: int | None = None
    compressed_section_offset: int | None = None
    compressed_offset: int | None = None
    compressed_size_before: int | None = None
    compressed_size: int | None = None
    decompressed_size: int | None = None
    entropy_pad_bytes: int | None = None
    ffs_file_checksum_offset_rom: int | None = None
    ffs_file_checksum_recalculated: bool | None = None
    ffs_file_checksum_calculated: int | None = None


@dataclass
class FspSDetection:
    function_start: int
    injection_offset: int
    function_end: int
    helper: int
    helper_call_site: int
    mov_801_site: int
    mov_901_site: int
    parent_call_site: int
    gate_start: int
    preserved_instruction: bytes
    preserved_instruction_offset: int
    preserved_instruction_text: str
    helper_return_count: int
    helper_max_argument_offset: int


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def profile_code_from_filename(source: Path) -> str:
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", source.stem).strip("._-")
    return safe_stem[:48] or "AUTO"


def inferred_profile(source: Path) -> dict[str, object]:
    return {
        "code": profile_code_from_filename(source),
        "description": source.name,
        "profile_resolution": "structure_only",
    }


def find_all(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return hits
        hits.append(offset)
        start = offset + 1


def parse_hex_field(text: str, field: str) -> int:
    match = re.search(
        rf"^{re.escape(field)}:\s*([0-9A-Fa-f]+)h",
        text,
        flags=re.MULTILINE,
    )
    if not match:
        raise PatchError(f"Missing field {field!r} in module info")
    return int(match.group(1), 16)


def parse_text_field(text: str, field: str) -> str:
    match = re.search(
        rf"^{re.escape(field)}:\s*(.+?)\s*$",
        text,
        flags=re.MULTILINE,
    )
    if not match:
        raise PatchError(f"Missing field {field!r} in module info")
    return match.group(1)


def run_uefiextract(exe: Path, image: Path, workdir: Path) -> Path:
    if not exe.is_file():
        raise PatchError(f"UEFIExtract not found: {exe}")

    local_image = workdir / "input.rom"
    shutil.copy2(image, local_image)
    result = subprocess.run(
        [str(exe), str(local_image)],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise PatchError(
            f"UEFIExtract failed ({result.returncode}):\n{result.stdout[-4000:]}"
        )

    dump = workdir / "input.rom.dump"
    if not dump.is_dir():
        raise PatchError(f"UEFIExtract did not create {dump}")
    return dump


def get_uefiextract_version(exe: Path) -> str:
    if not exe.is_file():
        raise PatchError(f"UEFIExtract not found: {exe}")
    result = subprocess.run(
        [str(exe), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        check=False,
    )
    version = next(
        (line.strip() for line in result.stdout.splitlines() if line.strip()),
        "",
    )
    if result.returncode != 0 or not version:
        raise PatchError(
            f"Could not determine UEFIExtract version: {result.stdout[-1000:]}"
        )
    return version


def validate_uefiextract_version(version: str, allow_override: bool) -> bool:
    matches = version == UEFIEXTRACT_TESTED_VERSION
    if not matches and not allow_override:
        raise PatchError(
            "Untested UEFIExtract version: "
            f"{version}; expected {UEFIEXTRACT_TESTED_VERSION}. "
            "Use --allow-uefiextract-version only after validating its "
            "info.txt format."
        )
    return matches


def find_modules(
    dump: Path,
    module_name: str,
    module_guid: str,
) -> list[ModuleInfo]:
    candidates: list[ModuleInfo] = []
    for info_path in dump.rglob("info.txt"):
        text = info_path.read_text(encoding="utf-8", errors="replace")
        if f"Text: {module_name}" not in text:
            continue
        if module_guid.lower() not in text.lower():
            continue
        bodies = sorted(
            (
                path
                for path in info_path.parent.rglob("body.bin")
                if (
                    "TE image section" in str(path) or "PE32 image section" in str(path)
                )
            ),
            key=str,
        )
        if len(bodies) != 1:
            if not bodies:
                continue
            raise PatchError(
                f"{module_name} ({module_guid}) has {len(bodies)} image bodies; "
                "the image body must be unambiguous"
            )
        body = bodies[0]
        if not body.is_file():
            continue
        candidates.append(
            ModuleInfo(
                base=parse_hex_field(text, "Base"),
                size=parse_hex_field(text, "Full size"),
                guid=module_guid,
                text=module_name,
                info_path=str(info_path),
                te_body_path=str(body),
            )
        )
    return candidates


def find_module(dump: Path) -> ModuleInfo:
    candidates = find_modules(dump, MODULE_NAME, MODULE_GUID)

    if len(candidates) != 1:
        raise PatchError(f"Expected one {MODULE_NAME}, found {len(candidates)}")
    return candidates[0]


def find_optional_module(
    dump: Path,
    module_name: str,
    module_guid: str,
) -> ModuleInfo | None:
    candidates = find_modules(dump, module_name, module_guid)
    if not candidates:
        return None
    if len(candidates) != 1:
        raise PatchError(f"Expected at most one {module_name}, found {len(candidates)}")
    return candidates[0]


def map_te_to_rom(
    rom: bytes,
    te_body: bytes,
    module: ModuleInfo,
) -> int:
    if module.size <= 0 or module.base < 0:
        raise PatchError("Invalid module range")
    module_end = module.base + module.size
    if module_end > len(rom):
        raise PatchError(f"Module range exceeds ROM: {module_end:#x} > {len(rom):#x}")

    module_data = rom[module.base : module_end]
    hits = find_all(module_data, te_body)
    if len(hits) != 1:
        if not hits:
            raise PatchError(
                "TE body is not stored verbatim in the target module; "
                "compressed or encapsulated TE images are not supported"
            )
        raise PatchError(
            "TE body appears multiple times inside the target module: "
            + ", ".join(f"{module.base + hit:#x}" for hit in hits)
        )

    rom_te_base = module.base + hits[0]
    if rom[rom_te_base : rom_te_base + len(te_body)] != te_body:
        raise PatchError("TE-to-ROM exact-slice validation failed")
    return rom_te_base


def te_text_ranges(te_body: bytes) -> list[tuple[int, int]]:
    if len(te_body) < 0x28:
        raise PatchError("TE image is too small")
    if te_body[:2] != b"VZ":
        raise PatchError("TE signature not found")
    section_count = te_body[4]
    if section_count == 0:
        raise PatchError("TE image has no sections")
    table = 0x28
    ranges: list[tuple[int, int]] = []
    for _ in range(section_count):
        if table + 40 > len(te_body):
            raise PatchError("TE section table is truncated")
        name = te_body[table : table + 8].rstrip(b"\x00")
        _, _, raw_size, raw_pointer = struct.unpack_from("<IIII", te_body, table + 8)
        characteristics = struct.unpack_from("<I", te_body, table + 36)[0]
        if characteristics & IMAGE_SCN_MEM_EXECUTE:
            raw_end = raw_pointer + raw_size
            if raw_size and raw_end > len(te_body):
                raise PatchError(
                    f"TE section {name.decode(errors='replace')!r} "
                    "has an invalid raw range"
                )
            if raw_size:
                ranges.append((raw_pointer, raw_end))
        table += 40
    if not ranges:
        raise PatchError("No executable TE section with raw data found")
    return ranges


def find_policy_block(
    te_body: bytes,
    text_ranges: list[tuple[int, int]],
) -> tuple[int, int, int, str]:
    candidates: list[tuple[int, int, int, str]] = []
    for range_start, range_end in text_ranges:
        for relative_hit in find_all(
            te_body[range_start:range_end],
            BRANCH_PREFIX,
        ):
            hit = range_start + relative_hit
            if hit + 10 > range_end:
                continue
            displacement = struct.unpack_from("<b", te_body, hit + 9)[0]
            epilogue = hit + 10 + displacement
            if epilogue <= hit or epilogue >= range_end:
                continue
            for signature, description in EPILOGUES.items():
                if epilogue + len(signature) > range_end:
                    continue
                if te_body[epilogue : epilogue + len(signature)] != signature:
                    continue
                block_size = epilogue - hit
                if block_size >= EXPECTED_PAYLOAD_SIZE:
                    candidates.append((hit, epilogue, block_size, description))
                break

    if len(candidates) != 1:
        raise PatchError(
            "Expected one policy block, found "
            f"{len(candidates)}: " + ", ".join(hex(item[0]) for item in candidates)
        )
    return candidates[0]


def range_containing(
    address: int,
    text_ranges: list[tuple[int, int]],
) -> tuple[int, int]:
    for start, end in text_ranges:
        if start <= address < end:
            return start, end
    raise PatchError(f"Address {address:#x} is outside executable TE sections")


def instruction_text(insn) -> str:
    return f"{insn.mnemonic} {insn.op_str}".strip()


def decode_instruction(
    te_body: bytes,
    address: int,
    range_end: int,
):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return next(
        md.disasm(te_body[address : min(range_end, address + 16)], address),
        None,
    )


def has_immediate_preceding_push(
    te_body: bytes,
    address: int,
    range_start: int,
) -> bool:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for window_start in range(max(range_start, address - 15), address):
        instructions = list(md.disasm(te_body[window_start:address], window_start))
        if not instructions:
            continue
        last = instructions[-1]
        if last.address + last.size == address:
            if last.mnemonic == "push":
                return True
    return False


def validate_status_buffer_frame(
    te_body: bytes,
    block_start: int,
    text_ranges: list[tuple[int, int]],
) -> tuple[int, int]:
    range_start, range_end = range_containing(block_start, text_ranges)
    search_start = max(range_start, block_start - 0x800)
    candidates = [
        search_start + hit
        for hit in find_all(
            te_body[search_start:block_start],
            bytes.fromhex("55 8B EC"),
        )
    ]

    failures: list[str] = []
    for function_start in reversed(candidates):
        first = decode_instruction(te_body, function_start, block_start)
        if first is None:
            continue
        second_address = first.address + first.size
        second = decode_instruction(te_body, second_address, block_start)
        if second is None:
            continue
        if not (
            first.mnemonic == "push"
            and first.op_str == "ebp"
            and second.mnemonic == "mov"
            and second.op_str.replace(" ", "") == "ebp,esp"
        ):
            continue

        after_prologue = second.address + second.size
        worklist: list[tuple[int, int, tuple[int, ...]]] = [(after_prologue, 0, ())]
        visited: set[tuple[int, int, tuple[int, ...]]] = set()
        block_states: set[tuple[int, tuple[int, ...]]] = set()
        reason = ""
        steps = 0

        while worklist:
            address, frame_depth, occupied_slots = worklist.pop()
            state = (address, frame_depth, occupied_slots)
            if state in visited:
                continue
            if len(visited) >= 4000:
                reason = "stack-frame control-flow analysis exceeded limit"
                break
            visited.add(state)

            if address == block_start:
                block_states.add((frame_depth, occupied_slots))
                continue
            if address < range_start or address >= block_start:
                continue

            insn = decode_instruction(te_body, address, range_end)
            if insn is None:
                reason = f"could not decode instruction at {address:#x}"
                break
            steps += 1
            if steps >= 8000:
                reason = "stack-frame control-flow analysis exceeded limit"
                break

            mnemonic = insn.mnemonic
            operands = insn.operands
            next_address = insn.address + insn.size
            if mnemonic == "push":
                if not operands:
                    reason = f"unsupported push at {insn.address:#x}"
                    break
                slot = frame_depth - 4
                worklist.append(
                    (
                        next_address,
                        slot,
                        tuple(sorted(occupied_slots + (slot,))),
                    )
                )
                continue
            if mnemonic == "pop":
                if not operands:
                    reason = f"unsupported pop at {insn.address:#x}"
                    break
                slot = frame_depth
                remaining = tuple(value for value in occupied_slots if value != slot)
                worklist.append((next_address, frame_depth + 4, remaining))
                continue
            if mnemonic in {"leave", "iret", "iretd"}:
                continue
            if mnemonic == "enter":
                reason = f"unsupported stack instruction {instruction_text(insn)}"
                break
            if mnemonic in {"sub", "add"} and operands:
                first_operand = operands[0]
                if (
                    first_operand.type == X86_OP_REG
                    and insn.reg_name(first_operand.reg) == "esp"
                ):
                    if len(operands) < 2 or operands[1].type != X86_OP_IMM:
                        reason = f"dynamic stack adjustment {instruction_text(insn)}"
                        break
                    amount = int(operands[1].imm)
                    if mnemonic == "sub":
                        worklist.append(
                            (next_address, frame_depth - amount, occupied_slots)
                        )
                    else:
                        new_depth = frame_depth + amount
                        remaining = tuple(
                            value
                            for value in occupied_slots
                            if not (frame_depth <= value < new_depth)
                        )
                        worklist.append((next_address, new_depth, remaining))
                    continue
            if mnemonic in {"mov", "xchg", "and", "or"} and operands:
                first_operand = operands[0]
                if (
                    first_operand.type == X86_OP_REG
                    and insn.reg_name(first_operand.reg) == "esp"
                ):
                    reason = f"frame reset before block: {instruction_text(insn)}"
                    break
            if insn.group(CS_GRP_JUMP):
                if not operands or operands[0].type != X86_OP_IMM:
                    reason = f"indirect jump before block: {instruction_text(insn)}"
                    break
                target = int(operands[0].imm)
                if not (range_start <= target < range_end):
                    reason = (
                        f"jump leaves executable range: "
                        f"{insn.address:#x} -> {target:#x}"
                    )
                    break
                worklist.append((target, frame_depth, occupied_slots))
                if mnemonic != "jmp":
                    worklist.append((next_address, frame_depth, occupied_slots))
                continue
            if mnemonic.startswith("ret"):
                continue
            worklist.append((next_address, frame_depth, occupied_slots))

        if reason:
            failures.append(f"{function_start:#x}: {reason}")
            continue
        if not block_states:
            failures.append(f"{function_start:#x}: no control-flow path reaches block")
            continue
        if len(block_states) != 1:
            failures.append(f"{function_start:#x}: conflicting frame states at block")
            continue
        frame_depth, occupied_slots = next(iter(block_states))
        if frame_depth > -4:
            failures.append(
                f"{function_start:#x}: frame depth {frame_depth:#x} "
                "does not allocate [ebp-4]"
            )
            continue
        if -4 in occupied_slots:
            failures.append(
                f"{function_start:#x}: [ebp-4] is a saved or temporary slot"
            )
            continue
        return function_start, frame_depth

    details = "; ".join(failures) if failures else "no valid function entry"
    raise PatchError(
        "Could not prove that [ebp-4] is an allocated local buffer: " + details
    )


def validate_original_cep_call(
    te_body: bytes,
    call_site: int,
    helper: int,
    text_ranges: list[tuple[int, int]],
) -> list[str]:
    range_start, _ = range_containing(call_site, text_ranges)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    earliest = max(range_start, call_site - 0x40)

    for window_start in range(earliest, call_site):
        instructions = list(
            md.disasm(
                te_body[window_start : call_site + 5],
                window_start,
            )
        )
        if not instructions:
            continue
        call_insn = instructions[-1]
        if call_insn.address != call_site or call_insn.mnemonic != "call":
            continue
        if (
            not call_insn.operands
            or call_insn.operands[0].type != X86_OP_IMM
            or call_insn.operands[0].imm != helper
        ):
            continue

        pushes = []
        valid = True
        reversed_instructions = list(reversed(instructions[:-1]))
        for index, insn in enumerate(reversed_instructions):
            if insn.mnemonic == "push":
                if not insn.operands:
                    valid = False
                    break
                pushes.append(insn)
                if len(pushes) == 4:
                    if has_immediate_preceding_push(
                        te_body,
                        pushes[-1].address,
                        range_start,
                    ):
                        valid = False
                        break
                    for older in reversed_instructions[index + 1 :]:
                        if older.mnemonic == "push":
                            valid = False
                            break
                        if older.mnemonic in {"call", "ret"}:
                            break
                        if older.group(CS_GRP_JUMP):
                            break
                        if older.mnemonic in {"add", "sub", "and"}:
                            operands = older.operands
                            if (
                                operands
                                and operands[0].type == X86_OP_REG
                                and older.reg_name(operands[0].reg) == "esp"
                            ):
                                break
                    break
                continue
            if not pushes:
                continue
            operands = insn.operands
            if insn.mnemonic in {"pop", "leave", "enter", "call", "ret"}:
                valid = False
                break
            if insn.group(CS_GRP_JUMP):
                valid = False
                break
            if insn.mnemonic in {"add", "sub", "and"} and operands:
                first_operand = operands[0]
                if (
                    first_operand.type == X86_OP_REG
                    and insn.reg_name(first_operand.reg) == "esp"
                ):
                    valid = False
                    break
        if not valid or len(pushes) != 4:
            continue

        # Pushes are collected backwards from the call. This order is also
        # the x86 cdecl argument order: the last value pushed is argument 1.
        arguments = pushes
        subcommand = arguments[0].operands[0]
        command = arguments[1].operands[0]
        if (
            subcommand.type != X86_OP_IMM
            or subcommand.imm != 1
            or command.type != X86_OP_IMM
            or command.imm != 0x137
        ):
            continue
        return [instruction_text(insn) for insn in arguments]

    raise PatchError(
        f"Original 0x137 call at {call_site:#x} does not have a verified "
        "four-argument mailbox ABI"
    )


def analyze_helper_returns(
    te_body: bytes,
    helper: int,
    text_ranges: list[tuple[int, int]],
) -> tuple[int, str, int, int]:
    _, range_end = range_containing(helper, text_ranges)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    worklist = [helper]
    visited: set[int] = set()
    returns: list[tuple[int, str]] = []
    max_argument_offset = 0

    while worklist:
        address = worklist.pop()
        if address in visited:
            continue
        if len(visited) >= 4000:
            raise PatchError("Mailbox helper control-flow analysis exceeded limit")
        visited.add(address)
        if not (helper <= address < range_end):
            raise PatchError(
                f"Mailbox helper control flow leaves function range: {address:#x}"
            )

        insn = next(
            md.disasm(te_body[address : min(range_end, address + 16)], address), None
        )
        if insn is None:
            raise PatchError(
                f"Could not decode mailbox helper instruction at {address:#x}"
            )
        for operand in insn.operands:
            if (
                operand.type == X86_OP_MEM
                and insn.reg_name(operand.mem.base) == "ebp"
                and operand.mem.disp > max_argument_offset
            ):
                max_argument_offset = operand.mem.disp

        next_address = insn.address + insn.size
        if insn.mnemonic.startswith("ret"):
            if insn.mnemonic != "ret" or insn.op_str:
                raise PatchError(
                    f"Mailbox helper has non-caller-cleanup return at "
                    f"{insn.address:#x}: {instruction_text(insn)}"
                )
            returns.append((insn.address, instruction_text(insn)))
            continue

        if insn.group(CS_GRP_JUMP):
            if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                raise PatchError(
                    f"Mailbox helper has indirect jump at {insn.address:#x}"
                )
            target = int(insn.operands[0].imm)
            if not (helper <= target < range_end):
                raise PatchError(
                    f"Mailbox helper jump leaves function range: "
                    f"{insn.address:#x} -> {target:#x}"
                )
            worklist.append(target)
            if insn.mnemonic != "jmp":
                worklist.append(next_address)
            continue

        if next_address >= range_end:
            raise PatchError(
                f"Mailbox helper reaches section end without a return "
                f"at {insn.address:#x}"
            )
        worklist.append(next_address)

    if not returns:
        raise PatchError(f"No reachable ret found in mailbox helper {helper:#x}")
    if max_argument_offset > 0x14:
        raise PatchError(
            f"Mailbox helper reads stack argument at [ebp+{max_argument_offset:#x}], "
            "which exceeds the four-argument payload ABI"
        )
    first_offset, first_instruction = min(returns)
    return first_offset, first_instruction, len(returns), max_argument_offset


def source_inside_decoded_instruction(
    te_body: bytes,
    source: int,
    range_start: int,
    range_end: int,
    function_entries: list[int],
) -> bool:
    index = bisect_right(function_entries, source) - 1
    if index < 0:
        return False
    address = function_entries[index]
    if address < range_start or source - address > 0x8000:
        return False

    for _ in range(MAX_LOCAL_DECODE_INSTRUCTIONS):
        insn = decode_instruction(te_body, address, range_end)
        if insn is None:
            return False
        instruction_end = insn.address + insn.size
        if insn.address < source < instruction_end:
            return True
        if insn.address == source or instruction_end > source:
            return False
        if insn.mnemonic.startswith("ret"):
            return False
        address = instruction_end
    return False


def raw_direct_xrefs(
    te_body: bytes,
    range_start: int,
    range_end: int,
    block_start: int,
    block_end: int,
    function_entries: list[int] | None = None,
) -> list[str]:
    function_entries = function_entries or []
    branches: list[tuple[int, int, int]] = []
    for address in range(range_start, range_end):
        opcode = te_body[address]
        length = 0
        displacement_offset = 0
        displacement_size = 0
        if opcode in {0xE8, 0xE9}:
            length, displacement_offset, displacement_size = 5, 1, 4
        elif (
            opcode == 0x0F
            and address + 1 < range_end
            and 0x80 <= te_body[address + 1] <= 0x8F
        ):
            length, displacement_offset, displacement_size = 6, 2, 4
        elif opcode == 0xEB or 0x70 <= opcode <= 0x7F:
            length, displacement_offset, displacement_size = 2, 1, 1
        if not length or address + length > range_end:
            continue
        if displacement_size == 4:
            displacement = struct.unpack_from(
                "<i",
                te_body,
                address + displacement_offset,
            )[0]
        else:
            displacement = struct.unpack_from(
                "<b",
                te_body,
                address + displacement_offset,
            )[0]
        target = address + length + displacement
        branches.append((address, length, target))

    hits: list[str] = []
    for address, _, target in branches:
        if block_start <= target < block_end and not (
            block_start <= address < block_end
        ):
            inside_other_branch = any(
                other_start < address < other_start + other_length
                for other_start, other_length, _ in branches
            )
            if inside_other_branch:
                continue
            if source_inside_decoded_instruction(
                te_body,
                address,
                range_start,
                range_end,
                function_entries,
            ):
                continue
            hits.append(f"raw {address:#x} -> {target:#x}")
    return hits


def validate_no_external_xrefs(
    te_body: bytes,
    block_start: int,
    block_end: int,
    text_ranges: list[tuple[int, int]],
) -> list[str]:
    function_entries: list[int] = []
    for start, end in text_ranges:
        function_entries.extend(
            start + hit
            for hit in find_all(
                te_body[start:end],
                bytes.fromhex("55 8B EC"),
            )
        )
    function_entries = sorted(set(function_entries))

    external: set[str] = set()
    for start, end in text_ranges:
        external.update(
            raw_direct_xrefs(
                te_body,
                start,
                end,
                block_start,
                block_end,
                function_entries,
            )
        )
    if external:
        raise PatchError(
            "External control flow enters replacement block: "
            + ", ".join(sorted(external))
        )
    return sorted(external)


def resolve_cep_helper(
    te_body: bytes,
    text_ranges: list[tuple[int, int]],
) -> tuple[int, int, str, int, int, list[str], int, int]:
    targets: list[tuple[int, int, list[str]]] = []
    for hit in find_all(te_body, CEP_OLD_CALL_PREFIX):
        call_site = hit + len(CEP_OLD_CALL_PREFIX) - 1
        if call_site + 5 > len(te_body):
            continue
        rel32 = struct.unpack_from("<i", te_body, call_site + 1)[0]
        helper = call_site + 5 + rel32
        if not (0 <= helper < len(te_body)):
            continue
        try:
            arguments = validate_original_cep_call(
                te_body,
                call_site,
                helper,
                text_ranges,
            )
        except PatchError:
            continue
        targets.append((helper, call_site, arguments))

    if not targets:
        raise PatchError(
            "No original 0x137 mailbox write call with a verified "
            "four-argument ABI was found"
        )

    counts = Counter(helper for helper, _, _ in targets)
    if len(counts) != 1:
        helpers = ", ".join(f"{helper:#x}" for helper in sorted(counts))
        raise PatchError(
            "Verified original 0x137 calls resolve to multiple mailbox "
            f"helpers: {helpers}"
        )
    helper = next(iter(counts))
    _, old_call_site, arguments = next(item for item in targets if item[0] == helper)
    (
        ret_offset,
        ret_instruction,
        return_count,
        max_argument_offset,
    ) = analyze_helper_returns(te_body, helper, text_ranges)
    return (
        helper,
        ret_offset,
        ret_instruction,
        old_call_site,
        len(arguments),
        arguments,
        return_count,
        max_argument_offset,
    )


def build_analysis(
    rom: bytes,
    profile: dict[str, object],
    module: ModuleInfo,
    te_body: bytes,
    ffs_info: FfsHeaderInfo,
) -> Analysis:
    rom_te_base = map_te_to_rom(rom, te_body, module)
    text_ranges = te_text_ranges(te_body)

    (
        block_start,
        epilogue,
        block_size,
        epilogue_asm,
    ) = find_policy_block(te_body, text_ranges)

    function_start, frame_depth = validate_status_buffer_frame(
        te_body,
        block_start,
        text_ranges,
    )

    external_xrefs = validate_no_external_xrefs(
        te_body,
        block_start,
        epilogue,
        text_ranges,
    )

    (
        helper,
        helper_ret_offset,
        helper_ret_instruction,
        old_call_site,
        helper_argument_count,
        helper_arguments,
        helper_return_count,
        helper_max_argument_offset,
    ) = resolve_cep_helper(te_body, text_ranges)

    call_site = block_start + CALL_OFFSET_IN_PAYLOAD
    new_rel32 = helper - (call_site + 5)
    if not (-0x80000000 <= new_rel32 <= 0x7FFFFFFF):
        raise PatchError(f"rel32 out of range: {new_rel32}")

    payload = PAYLOAD_PREFIX + b"\xe8" + struct.pack("<i", new_rel32) + PAYLOAD_SUFFIX
    if len(payload) != EXPECTED_PAYLOAD_SIZE:
        raise PatchError(
            f"Payload size mismatch: {len(payload)} != {EXPECTED_PAYLOAD_SIZE}"
        )
    if len(payload) > block_size:
        raise PatchError("Payload does not fit replacement block")

    replacement = payload + b"\x90" * (block_size - len(payload))
    block_start_rom = rom_te_base + block_start
    block_end_rom = rom_te_base + epilogue
    module_end = module.base + module.size
    if not (
        module.base <= rom_te_base
        and block_start_rom >= module.base
        and block_end_rom <= module_end
    ):
        raise PatchError("Patch block is outside the target FFS module")

    return Analysis(
        profile_code=str(profile["code"]),
        profile_description=str(profile["description"]),
        profile_resolution=str(profile.get("profile_resolution", "unknown")),
        source_sha256=sha256_bytes(rom),
        module=module,
        te_body_size=len(te_body),
        rom_te_base=rom_te_base,
        block_start_te=block_start,
        epilogue_te=epilogue,
        block_size=block_size,
        epilogue_asm=epilogue_asm,
        old_cep_call_te=old_call_site,
        helper_argument_count=helper_argument_count,
        helper_arguments=helper_arguments,
        helper_max_argument_offset=helper_max_argument_offset,
        helper_te=helper,
        helper_ret_offset_te=helper_ret_offset,
        helper_ret_instruction=helper_ret_instruction,
        helper_return_count=helper_return_count,
        function_start_te=function_start,
        frame_depth_at_block=frame_depth,
        status_pointer_frame_offset=-4,
        external_xref_count=len(external_xrefs),
        ffs_header_size=ffs_info.header_size,
        ffs_file_checksum_offset_rom=(
            module.base + 0x11 if ffs_info.uses_file_checksum else None
        ),
        new_call_site_te=call_site,
        new_rel32=new_rel32,
        payload_hex=payload.hex(" ").upper(),
        replacement_hex=replacement.hex(" ").upper(),
        block_start_rom=block_start_rom,
        block_end_rom_exclusive=block_end_rom,
    )


def calculate_ffs_header_checksum(header: bytes) -> int:
    if len(header) < 24:
        raise PatchError("FFS header is too small")
    return (0x100 - (sum(header) - header[0x10] - header[0x11] - header[0x17])) & 0xFF


def calculate_ffs_file_checksum(data: bytes) -> int:
    return (-sum(data)) & 0xFF


def parse_ffs_header(ffs: bytes) -> FfsHeaderInfo:
    if len(ffs) < 24:
        raise PatchError("FFS file is too small")
    attributes = ffs[0x13]
    if attributes & FFS_ATTRIB_LARGE_FILE:
        if len(ffs) < 32:
            raise PatchError("FFS Header2 is truncated")
        header_size = 32
        file_size = struct.unpack_from("<Q", ffs, 0x18)[0]
        if any(ffs[0x14:0x17]):
            raise PatchError("FFS Header2 Size field is not zero")
    else:
        header_size = 24
        file_size = int.from_bytes(ffs[0x14:0x17], "little")

    if file_size < header_size or file_size > len(ffs):
        raise PatchError(
            f"Invalid FFS file size {file_size:#x} for {len(ffs):#x} bytes"
        )
    return FfsHeaderInfo(
        header_size=header_size,
        file_size=file_size,
        attributes=attributes,
        uses_file_checksum=bool(attributes & FFS_ATTRIB_CHECKSUM),
    )


def validate_ffs(ffs: bytes) -> dict[str, object]:
    info = parse_ffs_header(ffs)
    if info.file_size != len(ffs):
        raise PatchError(
            f"FFS header size {info.file_size:#x} does not match "
            f"module size {len(ffs):#x}"
        )

    header = ffs[: info.header_size]
    calculated = calculate_ffs_header_checksum(header)
    if header[0x10] != calculated:
        raise PatchError(
            f"FFS header checksum invalid: {header[0x10]:#x} != {calculated:#x}"
        )

    file_checksum = header[0x11]
    calculated_file: int | None = None
    if info.uses_file_checksum:
        calculated_file = calculate_ffs_file_checksum(ffs[info.header_size :])
        if file_checksum != calculated_file:
            raise PatchError(
                f"FFS file checksum invalid: {file_checksum:#x} != {calculated_file:#x}"
            )
    elif file_checksum != FFS_FIXED_CHECKSUM:
        raise PatchError(
            "FFS file checksum must be the 0xAA sentinel when "
            "FFS_ATTRIB_CHECKSUM is clear"
        )

    return {
        "header_type": "header2" if info.header_size == 32 else "header",
        "header_size": info.header_size,
        "file_size": info.file_size,
        "attributes": info.attributes,
        "header_checksum": header[0x10],
        "header_checksum_calculated": calculated,
        "header_checksum_valid": True,
        "file_checksum": file_checksum,
        "file_checksum_calculated": calculated_file,
        "file_checksum_enabled": info.uses_file_checksum,
        "file_checksum_sentinel": file_checksum == FFS_FIXED_CHECKSUM,
    }


def update_ffs_file_checksum(ffs: bytes) -> tuple[bytes, bool, int | None]:
    info = parse_ffs_header(ffs)
    if not info.uses_file_checksum:
        return ffs, False, None
    calculated = calculate_ffs_file_checksum(ffs[info.header_size :])
    updated = bytearray(ffs)
    updated[0x11] = calculated
    return bytes(updated), True, calculated


def pe_text_ranges(pe: bytes) -> list[tuple[int, int]]:
    if len(pe) < 0x40 or pe[:2] != b"MZ":
        raise PatchError("FSP-S PE image has no MZ signature")
    pe_header = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe_header + 0x18 + 2 > len(pe):
        raise PatchError("FSP-S PE header is truncated")
    if struct.unpack_from("<H", pe, pe_header + 0x18)[0] != 0x10B:
        raise PatchError("FSP-S image is not PE32")

    section_count = struct.unpack_from("<H", pe, pe_header + 6)[0]
    optional_header_size = struct.unpack_from("<H", pe, pe_header + 0x14)[0]
    table = pe_header + 0x18 + optional_header_size
    ranges: list[tuple[int, int]] = []
    for index in range(section_count):
        entry = table + index * 40
        if entry + 40 > len(pe):
            raise PatchError("FSP-S PE section table is truncated")
        raw_size, raw_pointer = struct.unpack_from("<II", pe, entry + 16)
        characteristics = struct.unpack_from("<I", pe, entry + 36)[0]
        if not (characteristics & IMAGE_SCN_MEM_EXECUTE):
            continue
        raw_end = raw_pointer + raw_size
        if raw_size == 0 or raw_pointer >= len(pe) or raw_end > len(pe):
            raise PatchError("FSP-S executable section has an invalid raw range")
        ranges.append((raw_pointer, raw_end))
    if not ranges:
        raise PatchError("FSP-S PE image has no executable raw section")
    return ranges


def find_fsp_s_prologue(
    pe: bytes,
    hint: int,
) -> tuple[int, int] | None:
    search_start = max(0, hint - 0x400)
    candidates = [
        search_start + hit
        for hit in find_all(
            pe[search_start:hint],
            bytes.fromhex("55 8B EC"),
        )
    ]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for candidate in reversed(candidates):
        instructions = list(
            md.disasm(
                pe[candidate : min(len(pe), candidate + 0x20)],
                candidate,
            )
        )
        if len(instructions) < 6:
            continue
        first = instructions[:6]
        if not (
            first[0].mnemonic == "push"
            and first[0].op_str == "ebp"
            and first[1].mnemonic == "mov"
            and first[1].op_str.replace(" ", "") == "ebp,esp"
            and first[2].mnemonic == "sub"
            and len(first[2].operands) == 2
            and first[2].operands[0].type == X86_OP_REG
            and first[2].reg_name(first[2].operands[0].reg) == "esp"
            and first[2].operands[1].type == X86_OP_IMM
            and int(first[2].operands[1].imm) >= 8
            and first[3].mnemonic == "push"
            and first[3].op_str == "ebx"
            and first[4].mnemonic == "push"
            and first[4].op_str == "esi"
            and first[5].mnemonic == "mov"
            and first[5].op_str.replace(" ", "") == "esi,ecx"
        ):
            continue
        return candidate, first[5].address + first[5].size
    return None


def find_next_direct_call(
    pe: bytes,
    start: int,
    end: int,
) -> tuple[int, int] | None:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for insn in md.disasm(pe[start : min(len(pe), end)], start):
        if (
            insn.mnemonic == "call"
            and insn.operands
            and insn.operands[0].type == X86_OP_IMM
        ):
            return insn.address, int(insn.operands[0].imm)
    return None


def find_direct_call_refs(pe: bytes, target: int) -> list[int]:
    refs: list[int] = []
    for offset in find_all(pe, b"\xe8"):
        if offset + 5 > len(pe):
            continue
        rel32 = struct.unpack_from("<i", pe, offset + 1)[0]
        if offset + 5 + rel32 == target:
            refs.append(offset)
    return refs


def decode_gate_block(
    pe: bytes,
    gate_start: int,
    call_site: int,
) -> list[object] | None:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    instructions = list(md.disasm(pe[gate_start:call_site], gate_start))
    if not instructions:
        return None
    if instructions[0].address != gate_start:
        return None
    if instructions[-1].address + instructions[-1].size != call_site:
        return None
    return instructions


def detect_fsp_s_patch(pe: bytes) -> FspSDetection | None:
    if len(pe) < 0x100 or pe[:2] != b"MZ":
        return None
    pe_header = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe_header + 0x18 + 2 > len(pe):
        return None
    if struct.unpack_from("<H", pe, pe_header + 0x18)[0] != 0x10B:
        return None

    hits_801 = find_all(pe, FSP_S_MOV_EDX_801)
    hits_901 = find_all(pe, FSP_S_MOV_EDX_901)
    if not hits_801 and not hits_901:
        return None
    if not hits_801 or not hits_901:
        return None

    text_ranges = pe_text_ranges(pe)
    checksum_offset = pe_header + 0x18 + 0x40
    if checksum_offset + 4 > len(pe):
        raise PatchError("FSP-S PE checksum field is truncated")
    if struct.unpack_from("<I", pe, checksum_offset)[0] != 0:
        raise PatchError(
            "FSP-S PE checksum is not zero; refusing an unchecked checksum update"
        )

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    detections: list[FspSDetection] = []
    for mov_901_site in hits_901:
        prologue = find_fsp_s_prologue(pe, mov_901_site)
        if prologue is None:
            continue
        function_start, injection_offset = prologue
        before = [hit for hit in hits_801 if function_start < hit < mov_901_site]
        if not before:
            continue
        mov_801_site = before[-1]
        helper_call = find_next_direct_call(
            pe,
            mov_901_site + len(FSP_S_MOV_EDX_901),
            mov_901_site + 0x40,
        )
        if helper_call is None:
            continue
        helper_call_site, helper = helper_call

        function_end = -1
        for insn in md.disasm(
            pe[function_start : min(len(pe), function_start + 0x1000)],
            function_start,
        ):
            if insn.address > helper_call_site and insn.mnemonic == "ret":
                function_end = insn.address + insn.size
                break
        if function_end < 0:
            continue
        if (
            function_end < len(FSP_S_FUNCTION_EPILOGUE)
            or pe[function_end - len(FSP_S_FUNCTION_EPILOGUE) : function_end]
            != FSP_S_FUNCTION_EPILOGUE
        ):
            continue
        if injection_offset + EXPECTED_FSP_S_PAYLOAD_SIZE > function_end:
            continue

        parent_calls = find_direct_call_refs(pe, function_start)
        if len(parent_calls) != 1:
            continue
        parent_call_site = parent_calls[0]
        gate_start = parent_call_site - FSP_S_PARENT_GATE_BYTES
        if gate_start < 0:
            continue
        gate_instructions = decode_gate_block(
            pe,
            gate_start,
            parent_call_site,
        )
        if gate_instructions is None:
            continue
        conditional_jumps = [
            insn
            for insn in gate_instructions
            if insn.group(CS_GRP_JUMP) and insn.mnemonic != "jmp"
        ]
        if len(conditional_jumps) < 2:
            continue

        load_candidates = []
        for insn in gate_instructions:
            if (
                insn.mnemonic != "mov"
                or len(insn.operands) != 2
                or insn.operands[0].type != X86_OP_REG
                or insn.operands[1].type != X86_OP_MEM
            ):
                continue
            memory = insn.operands[1].mem
            if insn.reg_name(memory.base) == "ebp" and memory.disp < 0:
                load_candidates.append(insn)
        if len(load_candidates) != 1:
            continue
        load = load_candidates[0]
        load_register = load.reg_name(load.operands[0].reg)

        register_used_after_call = False
        for insn in md.disasm(
            pe[parent_call_site + 5 : min(len(pe), parent_call_site + 0x80)],
            parent_call_site + 5,
        ):
            if any(
                operand.type == X86_OP_MEM
                and insn.reg_name(operand.mem.base) == load_register
                and operand.mem.disp == 0x1C
                for operand in insn.operands
            ):
                register_used_after_call = True
                break
        if not register_used_after_call:
            continue

        try:
            _, _, helper_return_count, helper_max_argument_offset = (
                analyze_helper_returns(pe, helper, text_ranges)
            )
        except PatchError:
            continue
        if helper_max_argument_offset > 0x0C:
            continue

        detections.append(
            FspSDetection(
                function_start=function_start,
                injection_offset=injection_offset,
                function_end=function_end,
                helper=helper,
                helper_call_site=helper_call_site,
                mov_801_site=mov_801_site,
                mov_901_site=mov_901_site,
                parent_call_site=parent_call_site,
                gate_start=gate_start,
                preserved_instruction=bytes(load.bytes),
                preserved_instruction_offset=load.address - gate_start,
                preserved_instruction_text=(f"{load.mnemonic} {load.op_str}".strip()),
                helper_return_count=helper_return_count,
                helper_max_argument_offset=helper_max_argument_offset,
            )
        )

    unique_detections = {
        (
            item.function_start,
            item.injection_offset,
            item.function_end,
            item.helper,
            item.parent_call_site,
        ): item
        for item in detections
    }
    if not unique_detections:
        raise PatchError(
            "SiInitFsp contains both 0x801 and 0x901 signatures, but no "
            "single safely decodable native CEP synchronization path was found"
        )
    if len(unique_detections) != 1:
        locations = ", ".join(
            f"{item.function_start:#x}" for item in unique_detections.values()
        )
        raise PatchError(
            "Multiple native FSP-S CEP synchronization paths are ambiguous: "
            + locations
        )
    return next(iter(unique_detections.values()))


def build_fsp_s_payload(detection: FspSDetection) -> bytes:
    call_site = detection.injection_offset + len(FSP_S_PAYLOAD_PREFIX)
    rel32 = detection.helper - (call_site + 5)
    if not (-0x80000000 <= rel32 <= 0x7FFFFFFF):
        raise PatchError("FSP-S helper call rel32 is out of range")
    payload = (
        FSP_S_PAYLOAD_PREFIX + b"\xe8" + struct.pack("<i", rel32) + FSP_S_PAYLOAD_SUFFIX
    )
    if len(payload) != EXPECTED_FSP_S_PAYLOAD_SIZE:
        raise PatchError("FSP-S payload size mismatch")
    return payload


def patch_fsp_s_pe(
    pe: bytes,
    detection: FspSDetection,
) -> tuple[bytes, bytes, int, int, bytes]:
    patched = bytearray(pe)
    payload = build_fsp_s_payload(detection)
    patched[detection.injection_offset : detection.injection_offset + len(payload)] = (
        payload
    )
    patched[detection.injection_offset + len(payload) : detection.function_end] = (
        b"\x90" * (detection.function_end - detection.injection_offset - len(payload))
    )

    gate_size = detection.parent_call_site - detection.gate_start
    gate_replacement = bytearray(b"\x90" * gate_size)
    preserved_start = detection.preserved_instruction_offset
    preserved_end = preserved_start + len(detection.preserved_instruction)
    if not (0 <= preserved_start and preserved_end <= gate_size):
        raise PatchError("Preserved FSP-S instruction lies outside the gate block")
    gate_replacement[preserved_start:preserved_end] = detection.preserved_instruction
    patched[detection.gate_start : detection.parent_call_site] = gate_replacement

    pe_header = struct.unpack_from("<I", patched, 0x3C)[0]
    checksum_offset = pe_header + 0x18 + 0x40
    struct.pack_into("<I", patched, checksum_offset, 0)
    return (
        bytes(patched),
        payload,
        detection.injection_offset + len(payload),
        detection.function_end,
        bytes(gate_replacement),
    )


def deterministic_pad(seed: bytes, size: int) -> bytes:
    result = bytearray()
    block = seed
    while len(result) < size:
        block = hashlib.sha256(block).digest()
        result.extend(block)
    return bytes(result[:size])


def find_compression_balance_pad(
    image: bytearray,
    pad_start: int,
    pad_end: int,
    target_size: int,
) -> tuple[bytearray, int]:
    seed = b"CEPPAD"
    for pad_size in range(pad_end - pad_start + 1):
        candidate = bytearray(image)
        candidate[pad_start:pad_end] = b"\x90" * (pad_end - pad_start)
        candidate[pad_start : pad_start + pad_size] = deterministic_pad(seed, pad_size)
        compressed = efi_compressor.EfiCompress(
            bytes(candidate),
            len(candidate),
        )
        if len(compressed) == target_size:
            return candidate, pad_size
    raise PatchError("Could not balance FSP-S compressed stream to original size")


def find_compressed_section_info(
    module: ModuleInfo,
) -> tuple[Path, dict[str, int]] | None:
    body_path = Path(module.te_body_path)
    module_dir = Path(module.info_path).parent
    matches: list[tuple[Path, dict[str, int]]] = []
    for info_path in module_dir.rglob("info.txt"):
        text = info_path.read_text(encoding="utf-8", errors="replace")
        if "Subtype: Compressed" not in text:
            continue
        try:
            body_path.relative_to(info_path.parent)
        except ValueError:
            continue
        matches.append(
            (
                info_path,
                {
                    "offset": parse_hex_field(text, "Offset"),
                    "body_size": parse_hex_field(text, "Body size"),
                    "decompressed_size": parse_hex_field(
                        text,
                        "Decompressed size",
                    ),
                    "compression_type": parse_hex_field(
                        text,
                        "Compression type",
                    ),
                },
            )
        )
    if not matches:
        return None
    if len(matches) != 1:
        raise PatchError(
            f"Expected one compressed section in {module.text}, found {len(matches)}"
        )
    return matches[0]


def patch_fsp_s_if_supported(
    dump: Path,
    rom: bytearray,
) -> tuple[FspSResult, tuple[int, bytes] | None, bytes | None]:
    module = find_optional_module(
        dump,
        FSP_S_MODULE_NAME,
        FSP_S_MODULE_GUID,
    )
    if module is None:
        return (
            FspSResult(
                status="skipped",
                reason="SiInitFsp module not found",
            ),
            None,
            None,
        )

    original_ffs = bytes(rom[module.base : module.base + module.size])
    validate_ffs(original_ffs)
    pe = Path(module.te_body_path).read_bytes()
    detection = detect_fsp_s_patch(pe)
    if detection is None:
        return (
            FspSResult(
                status="skipped",
                reason=(
                    "No supported native 0x801/0x901 CEP synchronization "
                    "path found in SiInitFsp"
                ),
                module_base=module.base,
                module_size=module.size,
            ),
            None,
            None,
        )

    (
        patched_pe,
        payload,
        pad_start_pe,
        pad_end_pe,
        gate_replacement,
    ) = patch_fsp_s_pe(pe, detection)

    compressed_section_offset: int | None = None
    compressed_offset_data: int | None = None
    compressed_size_before: int | None = None
    decompressed_size: int | None = None
    pe_offset: int | None = None
    entropy_pad_bytes: int | None = None
    compressed_info = find_compressed_section_info(module)
    if compressed_info is None:
        module_bytes = rom[module.base : module.base + module.size]
        hits = find_all(module_bytes, pe)
        if len(hits) != 1:
            raise PatchError("Uncompressed FSP-S PE body could not be uniquely mapped")
        replacement_offset = module.base + hits[0]
        rom[replacement_offset : replacement_offset + len(pe)] = patched_pe
        replacement = (replacement_offset, patched_pe)
    else:
        if efi_compressor is None:
            raise PatchError(
                "FSP-S uses EFI compression but uefi_firmware is not installed"
            )
        _, info = compressed_info
        if info["compression_type"] != 0x01:
            raise PatchError("Only EFI 1.1 compressed FSP-S sections are supported")
        compressed_section_offset = module.base + info["offset"]
        compressed_offset_data = (
            compressed_section_offset + FSP_S_COMPRESSED_SECTION_HEADER_SIZE
        )
        compressed_size_before = info["body_size"]
        decompressed_size = info["decompressed_size"]
        module_end = module.base + module.size
        compressed_end = compressed_offset_data + compressed_size_before
        if not (
            module.base
            <= compressed_section_offset
            < compressed_offset_data
            < compressed_end
            <= module_end
        ):
            raise PatchError("FSP-S compressed section lies outside its FFS file")

        compressed = bytes(rom[compressed_offset_data:compressed_end])
        uncompressed = bytearray(
            efi_compressor.EfiDecompress(
                compressed,
                decompressed_size,
            )
        )
        if len(uncompressed) != decompressed_size:
            raise PatchError(
                "FSP-S decompressed size differs from the section metadata"
            )
        pe_hits = find_all(uncompressed, pe)
        if len(pe_hits) != 1:
            raise PatchError("Decompressed FSP-S PE body could not be uniquely located")
        pe_offset = pe_hits[0]
        if uncompressed[pe_offset : pe_offset + len(pe)] != pe:
            raise PatchError("Decompressed FSP-S PE body does not match UEFIExtract")
        uncompressed[pe_offset : pe_offset + len(patched_pe)] = patched_pe
        balanced, entropy_pad_bytes = find_compression_balance_pad(
            uncompressed,
            pe_offset + pad_start_pe,
            pe_offset + pad_end_pe,
            info["body_size"],
        )
        patched_pe = bytes(balanced[pe_offset : pe_offset + len(pe)])
        recompressed = efi_compressor.EfiCompress(
            bytes(balanced),
            len(balanced),
        )
        if len(recompressed) != compressed_size_before:
            raise PatchError(
                "FSP-S recompressed size differs from the original: "
                f"{len(recompressed):#x} != {compressed_size_before:#x}"
            )
        if efi_compressor.EfiDecompress(
            recompressed,
            decompressed_size,
        ) != bytes(balanced):
            raise PatchError("FSP-S compression round-trip failed")
        rom[compressed_offset_data:compressed_end] = recompressed
        replacement = (compressed_offset_data, recompressed)

    ffs = bytes(rom[module.base : module.base + module.size])
    ffs, file_checksum_recalculated, calculated_file_checksum = (
        update_ffs_file_checksum(ffs)
    )
    rom[module.base : module.base + module.size] = ffs
    ffs_info = parse_ffs_header(ffs)
    validate_ffs(ffs)
    result = FspSResult(
        status="patched",
        reason=("Native 0x801/0x901 synchronization path forced to 0x901/1 data=3"),
        module_base=module.base,
        module_size=module.size,
        function_start=detection.function_start,
        injection_offset=detection.injection_offset,
        function_end=detection.function_end,
        helper=detection.helper,
        helper_call_site=detection.helper_call_site,
        helper_return_count=detection.helper_return_count,
        helper_max_argument_offset=detection.helper_max_argument_offset,
        mov_801_site=detection.mov_801_site,
        mov_901_site=detection.mov_901_site,
        parent_call_site=detection.parent_call_site,
        gate_start=detection.gate_start,
        preserved_instruction_offset=detection.preserved_instruction_offset,
        preserved_instruction_hex=(detection.preserved_instruction.hex(" ").upper()),
        gate_replacement_hex=gate_replacement.hex(" ").upper(),
        payload_hex=payload.hex(" ").upper(),
        original_pe_sha256=sha256_bytes(pe),
        patched_pe_sha256=sha256_bytes(patched_pe),
        pe_offset_in_decompressed_body=pe_offset,
        compressed_section_offset=compressed_section_offset,
        compressed_offset=(replacement[0] if compressed_info else None),
        compressed_size_before=compressed_size_before,
        compressed_size=(len(replacement[1]) if compressed_info else None),
        decompressed_size=decompressed_size,
        entropy_pad_bytes=entropy_pad_bytes,
        ffs_file_checksum_offset_rom=(
            module.base + 0x11 if ffs_info.uses_file_checksum else None
        ),
        ffs_file_checksum_recalculated=file_checksum_recalculated,
        ffs_file_checksum_calculated=calculated_file_checksum,
    )
    return result, replacement, patched_pe


def disassemble_patched_block(
    replacement: bytes,
    te_address: int,
    *,
    compact_nops: bool = False,
) -> list[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines: list[str] = []
    nop_start: int | None = None
    nop_count = 0
    for insn in md.disasm(replacement, te_address):
        if compact_nops and insn.mnemonic == "nop":
            if nop_start is None:
                nop_start = insn.address
            nop_count += 1
            continue
        if compact_nops and nop_start is not None:
            lines.append(f"{nop_start:08X}: {nop_count} NOP padding bytes")
            nop_start = None
            nop_count = 0
        lines.append(
            f"{insn.address:08X}: "
            f"{insn.bytes.hex(' '):<24} "
            f"{insn.mnemonic:<8} {insn.op_str}"
        )
    if compact_nops and nop_start is not None:
        lines.append(f"{nop_start:08X}: {nop_count} NOP padding bytes")
    return lines


def validate_patched_payload(
    replacement: bytes,
    block_start: int,
    helper: int,
) -> None:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    instructions = list(md.disasm(replacement, block_start))
    by_address = {insn.address: insn for insn in instructions}

    call_address = block_start + CALL_OFFSET_IN_PAYLOAD
    call_insn = by_address.get(call_address)
    if (
        call_insn is None
        or call_insn.mnemonic != "call"
        or not call_insn.operands
        or call_insn.operands[0].type != X86_OP_IMM
        or call_insn.operands[0].imm != helper
    ):
        raise PatchError("Patched payload does not call the resolved mailbox helper")

    cleanup_address = call_address + call_insn.size
    cleanup_insn = by_address.get(cleanup_address)
    if (
        cleanup_insn is None
        or cleanup_insn.mnemonic != "add"
        or len(cleanup_insn.operands) != 2
        or cleanup_insn.operands[0].type != X86_OP_REG
        or cleanup_insn.reg_name(cleanup_insn.operands[0].reg) != "esp"
        or cleanup_insn.operands[1].type != X86_OP_IMM
        or cleanup_insn.operands[1].imm != 0x10
    ):
        raise PatchError("Patched payload does not clean four arguments")

    xor_address = cleanup_address + cleanup_insn.size
    xor_insn = by_address.get(xor_address)
    if (
        xor_insn is None
        or xor_insn.mnemonic != "xor"
        or xor_insn.op_str.replace(" ", "") != "eax,eax"
    ):
        raise PatchError("Patched payload does not return zero in EAX")


def verify_patched_extraction(
    uefiextract: Path,
    patched_rom: bytes,
    expected_module: ModuleInfo,
    expected_te_base: int,
    block_start: int,
    block_end: int,
    replacement: bytes,
    workdir: Path,
    expected_fsp_s: FspSResult | None = None,
    expected_fsp_s_pe: bytes | None = None,
) -> dict[str, object]:
    verify_dir = workdir / "verify"
    verify_dir.mkdir()
    verify_image = verify_dir / "patched.rom"
    verify_image.write_bytes(patched_rom)
    dump = run_uefiextract(uefiextract, verify_image, verify_dir)
    module = find_module(dump)
    if module.base != expected_module.base or module.size != expected_module.size:
        raise PatchError("Patched extraction changed module base or size")
    te_body = Path(module.te_body_path).read_bytes()
    if te_body[block_start:block_end] != replacement:
        raise PatchError(
            "Re-extracted TE body does not contain the expected patch block"
        )
    te_base = map_te_to_rom(patched_rom, te_body, module)
    if te_base != expected_te_base:
        raise PatchError(
            f"Re-extracted TE base changed: {te_base:#x} != {expected_te_base:#x}"
        )
    ffs = patched_rom[module.base : module.base + module.size]
    ffs_validation = validate_ffs(ffs)
    validation: dict[str, object] = {
        "module_base": module.base,
        "module_size": module.size,
        "te_base": te_base,
        "patch_block_exact": True,
        "ffs": ffs_validation,
    }
    if expected_fsp_s is not None and expected_fsp_s.status == "patched":
        if expected_fsp_s_pe is None:
            raise PatchError("Expected patched FSP-S PE body is missing")
        fsp_s_module = find_optional_module(
            dump,
            FSP_S_MODULE_NAME,
            FSP_S_MODULE_GUID,
        )
        if fsp_s_module is None:
            raise PatchError("Patched FSP-S module disappeared after reparse")
        if (
            fsp_s_module.base != expected_fsp_s.module_base
            or fsp_s_module.size != expected_fsp_s.module_size
        ):
            raise PatchError("Patched extraction changed FSP-S module base or size")
        extracted_pe = Path(fsp_s_module.te_body_path).read_bytes()
        if extracted_pe != expected_fsp_s_pe:
            raise PatchError("Re-extracted FSP-S PE body does not match the patched PE")
        fsp_s_ffs = patched_rom[
            fsp_s_module.base : fsp_s_module.base + fsp_s_module.size
        ]
        validation["fsp_s"] = {
            "module_base": fsp_s_module.base,
            "module_size": fsp_s_module.size,
            "pe_sha256": sha256_bytes(extracted_pe),
            "pe_exact": True,
            "ffs": validate_ffs(fsp_s_ffs),
        }
    return validation


def default_output_path(source: Path) -> Path:
    return source.parent / f"{source.stem}_IA_GT_CEP_OFF{source.suffix}"


def default_ffs_path(output: Path, code: str) -> Path:
    return output.parent / f"SiInitPreMemFsp_{code}_IA_GT_CEP_OFF.ffs"


def default_fsp_s_pe_path(output: Path, code: str) -> Path:
    return output.parent / f"SiInitFsp_{code}_IA_GT_CEP_OFF.pe32"


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=("Apply the structure-driven fixed CEP-blind-write patch.")
    )
    parser.add_argument("input", type=Path, help="Original BIOS image")
    parser.add_argument("--output", type=Path, help="Patched ROM output path")
    parser.add_argument("--report", type=Path, help="Analysis report JSON path")
    parser.add_argument(
        "--uefiextract",
        type=Path,
        default=DEFAULT_UEFIEXTRACT,
        help="Path to UEFIExtract.exe",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze and print the patch without writing files",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output files",
    )
    parser.add_argument(
        "--allow-uefiextract-version",
        action="store_true",
        help="Allow an UEFIExtract version other than the tested parser",
    )
    args = parser.parse_args(argv)

    source = args.input.resolve()
    if not source.is_file():
        raise PatchError(f"Input file not found: {source}")
    rom = source.read_bytes()
    profile = inferred_profile(source)
    uefiextract = args.uefiextract.resolve()
    uefiextract_version = get_uefiextract_version(uefiextract)
    uefiextract_version_matches = validate_uefiextract_version(
        uefiextract_version,
        args.allow_uefiextract_version,
    )

    with tempfile.TemporaryDirectory(prefix="14th_b0_cep_patcher_") as temp:
        workdir = Path(temp)
        dump = run_uefiextract(uefiextract, source, workdir)
        module = find_module(dump)
        te_body = Path(module.te_body_path).read_bytes()
        original_ffs = rom[module.base : module.base + module.size]
        ffs_info = parse_ffs_header(original_ffs)
        original_ffs_validation = validate_ffs(original_ffs)
        analysis = build_analysis(
            rom,
            profile,
            module,
            te_body,
            ffs_info,
        )

        block = slice(
            analysis.block_start_rom,
            analysis.block_end_rom_exclusive,
        )
        replacement = bytes.fromhex(analysis.replacement_hex)
        patched = bytearray(rom)
        patched[block] = replacement

        if len(patched) != len(rom):
            raise PatchError("Patch changed ROM length")

        patched_ffs = bytes(patched[module.base : module.base + module.size])
        (
            patched_ffs,
            file_checksum_recalculated,
            calculated_file_checksum,
        ) = update_ffs_file_checksum(patched_ffs)
        patched[module.base : module.base + module.size] = patched_ffs
        ffs_validation = validate_ffs(patched_ffs)

        (
            fsp_s_result,
            fsp_s_replacement,
            fsp_s_patched_pe,
        ) = patch_fsp_s_if_supported(dump, patched)
        fsp_s_ffs: bytes | None = None
        if (
            fsp_s_result.status == "patched"
            and fsp_s_result.module_base is not None
            and fsp_s_result.module_size is not None
        ):
            fsp_s_ffs = bytes(
                patched[
                    fsp_s_result.module_base : fsp_s_result.module_base
                    + fsp_s_result.module_size
                ]
            )

        differences = [
            index for index, (old, new) in enumerate(zip(rom, patched)) if old != new
        ]
        if not differences:
            raise PatchError("Patch produced no changes")
        allowed_target_ranges = [
            (
                analysis.block_start_rom,
                analysis.block_end_rom_exclusive,
            )
        ]
        if fsp_s_replacement is not None:
            allowed_target_ranges.append(
                (
                    fsp_s_replacement[0],
                    fsp_s_replacement[0] + len(fsp_s_replacement[1]),
                )
            )
        outside_target = [
            index
            for index in differences
            if not any(start <= index < end for start, end in allowed_target_ranges)
        ]
        allowed_checksum_offsets = {
            offset
            for offset in (
                analysis.ffs_file_checksum_offset_rom,
                fsp_s_result.ffs_file_checksum_offset_rom,
            )
            if offset is not None
        }
        unexpected = [
            index
            for index in differences
            if not (
                any(start <= index < end for start, end in allowed_target_ranges)
                or index in allowed_checksum_offsets
            )
        ]
        if unexpected:
            raise PatchError(
                f"{len(unexpected)} unexpected differences outside "
                "all target ranges and allowed FFS checksum bytes"
            )

        reconstructed = bytearray(rom)
        reconstructed[block] = replacement
        reconstructed[module.base : module.base + module.size] = patched_ffs
        if fsp_s_ffs is not None and fsp_s_result.module_base is not None:
            reconstructed[
                fsp_s_result.module_base : fsp_s_result.module_base + len(fsp_s_ffs)
            ] = fsp_s_ffs
        if reconstructed != patched:
            raise PatchError("Reconstructed patch does not match output")

        ffs = patched_ffs

        exact_disassembly = disassemble_patched_block(
            replacement,
            analysis.block_start_te,
        )
        display_disassembly = disassemble_patched_block(
            replacement,
            analysis.block_start_te,
            compact_nops=True,
        )
        validate_patched_payload(
            replacement,
            analysis.block_start_te,
            analysis.helper_te,
        )
        fsp_s_payload_disassembly: list[str] = []
        if fsp_s_result.status == "patched":
            if fsp_s_result.payload_hex is None:
                raise PatchError("Patched FSP-S payload bytes are missing")
            if fsp_s_result.injection_offset is None:
                raise PatchError("Patched FSP-S injection offset is missing")
            fsp_s_payload_disassembly = disassemble_patched_block(
                bytes.fromhex(fsp_s_result.payload_hex),
                fsp_s_result.injection_offset,
            )

        output = args.output.resolve() if args.output else default_output_path(source)
        ffs_output = default_ffs_path(output, analysis.profile_code)
        fsp_s_pe_output = (
            default_fsp_s_pe_path(output, analysis.profile_code)
            if fsp_s_result.status == "patched"
            else None
        )
        report = (
            args.report.resolve()
            if args.report
            else output.with_name(output.name + ".report.json")
        )

        print(f"Profile: {analysis.profile_code}")
        print(f"Description: {analysis.profile_description}")
        print(f"Profile resolution: {analysis.profile_resolution}")
        print("SHA256 allowlist: none (source hash is traceability only)")
        print("Hardware compatibility: unverified")
        print(f"UEFIExtract: {uefiextract_version}")
        print(f"Source SHA256: {analysis.source_sha256}")
        print(f"Module: {analysis.module.text} ({analysis.module.guid})")
        print(f"TE-to-ROM base: {analysis.rom_te_base:#x}")
        print(
            "Block: "
            f"TE {analysis.block_start_te:#x}-"
            f"{analysis.epilogue_te - 1:#x}, "
            f"ROM {analysis.block_start_rom:#x}-"
            f"{analysis.block_end_rom_exclusive - 1:#x}, "
            f"size {analysis.block_size:#x}"
        )
        print(f"Epilogue: {analysis.epilogue_asm}")
        print(
            "Status buffer frame: "
            f"[ebp{analysis.status_pointer_frame_offset:+#x}], "
            f"frame depth {analysis.frame_depth_at_block:#x}"
        )
        print(f"Function start: {analysis.function_start_te:#x}")
        print(f"Mailbox helper: {analysis.helper_te:#x}")
        print(
            "Helper ABI: "
            f"{analysis.helper_argument_count} arguments, "
            f"{analysis.helper_return_count} return paths, "
            f"max [ebp+{analysis.helper_max_argument_offset:#x}]"
        )
        print(f"Helper arguments: {', '.join(analysis.helper_arguments)}")
        print(
            f"New call: {analysis.new_call_site_te:#x}, rel32 {analysis.new_rel32:#x}"
        )
        print(f"Payload: {analysis.payload_hex}")
        print(f"FSP-S: {fsp_s_result.status} ({fsp_s_result.reason})")
        if fsp_s_result.status == "patched":
            print(
                "FSP-S path: "
                f"0x801@{fsp_s_result.mov_801_site:#x}, "
                f"0x901@{fsp_s_result.mov_901_site:#x}, "
                f"helper@{fsp_s_result.helper:#x}, "
                f"gate@{fsp_s_result.gate_start:#x}"
            )
            print(f"FSP-S payload: {fsp_s_result.payload_hex}")
            if fsp_s_result.compressed_size_before is not None:
                print(
                    "FSP-S compressed stream: "
                    f"{fsp_s_result.compressed_size_before:#x} -> "
                    f"{fsp_s_result.compressed_size:#x}"
                )
            else:
                print("FSP-S storage: uncompressed XIP image")
        print(
            "FFS checksum: "
            f"header={ffs_validation['header_checksum']:#x}, "
            f"file={ffs_validation['file_checksum']:#x}, "
            f"recalculated={file_checksum_recalculated}"
        )
        print(f"Differences: {len(differences)}")
        print(f"Outside all target ranges: {len(outside_target)}")
        print(f"Unexpected differences: {len(unexpected)}")
        print("Patched block:")
        for line in display_disassembly:
            print(f"  {line}")

        if args.dry_run:
            print("Dry run: no files written")
            return 0

        output_paths = [output, ffs_output, report]
        if fsp_s_pe_output is not None:
            output_paths.append(fsp_s_pe_output)
        for path in output_paths:
            if path.exists() and not args.force:
                raise PatchError(f"Output exists, use --force to overwrite: {path}")
            path.parent.mkdir(parents=True, exist_ok=True)

        reparse_validation = verify_patched_extraction(
            uefiextract,
            bytes(patched),
            module,
            analysis.rom_te_base,
            analysis.block_start_te,
            analysis.epilogue_te,
            replacement,
            workdir,
            fsp_s_result,
            fsp_s_patched_pe,
        )

        output.write_bytes(patched)
        ffs_output.write_bytes(ffs)
        if fsp_s_pe_output is not None:
            if fsp_s_patched_pe is None:
                raise PatchError("Patched FSP-S PE body is missing")
            fsp_s_pe_output.write_bytes(fsp_s_patched_pe)

        report_data = {
            "analysis": asdict(analysis),
            "output": {
                "rom": str(output),
                "rom_sha256": sha256_bytes(patched),
                "ffs": str(ffs_output),
                "ffs_sha256": sha256_bytes(ffs),
                "fsp_s_pe": (
                    str(fsp_s_pe_output) if fsp_s_pe_output is not None else None
                ),
                "fsp_s_pe_sha256": (
                    sha256_bytes(fsp_s_patched_pe)
                    if fsp_s_patched_pe is not None
                    else None
                ),
                "report": str(report),
            },
            "toolchain": {
                "uefiextract_version": uefiextract_version,
                "uefiextract_tested_version": UEFIEXTRACT_TESTED_VERSION,
                "uefiextract_version_matches_tested": uefiextract_version_matches,
                "uefiextract_version_override": (
                    args.allow_uefiextract_version and not uefiextract_version_matches
                ),
                "uefi_firmware_efi_compressor": efi_compressor is not None,
            },
            "validation": {
                "structure_validation": "passed",
                "source_sha256_used_for_patch_selection": False,
                "hardware_compatibility": "unverified",
                "same_length": len(patched) == len(rom),
                "difference_count": len(differences),
                "allowed_target_ranges": [
                    {"start": start, "end_exclusive": end}
                    for start, end in allowed_target_ranges
                ],
                "outside_target_count": len(outside_target),
                "unexpected_difference_count": len(unexpected),
                "module_scoped_te_mapping": True,
                "status_buffer_frame_validated": True,
                "helper_abi": {
                    "argument_count": analysis.helper_argument_count,
                    "arguments": analysis.helper_arguments,
                    "return_count": analysis.helper_return_count,
                    "max_stack_argument_offset": analysis.helper_max_argument_offset,
                    "caller_cleanup_only": True,
                },
                "external_xref_count": analysis.external_xref_count,
                "ffs_file_checksum_recalculated": file_checksum_recalculated,
                "ffs_file_checksum_calculated": calculated_file_checksum,
                "reconstruction_exact": reconstructed == patched,
                "original_ffs": original_ffs_validation,
                "ffs": ffs_validation,
                "uefiextract_reparse": reparse_validation,
                "fsp_s": asdict(fsp_s_result),
                "fsp_s_patched_disassembly": fsp_s_payload_disassembly,
                "patched_disassembly": exact_disassembly,
                "patched_disassembly_display": display_disassembly,
            },
        }
        report.write_text(
            json.dumps(report_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        print(f"ROM: {output}")
        print(f"ROM SHA256: {sha256_bytes(patched)}")
        print(f"FFS: {ffs_output}")
        print(f"FFS SHA256: {sha256_bytes(ffs)}")
        if fsp_s_pe_output is not None:
            print(f"FSP-S PE: {fsp_s_pe_output}")
            print(f"FSP-S PE SHA256: {fsp_s_result.patched_pe_sha256}")
        print(f"Report: {report}")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PatchError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except (OSError, struct.error, ValueError, CsError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2)
