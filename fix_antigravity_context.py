#!/usr/bin/env python3
"""
Automatic Go pclntab locator and context/rules patcher for Antigravity:
- Supports Windows x86_64 PE (agy.exe for Antigravity IDE + CLI, language_server.exe for Antigravity Desktop)
- Supports macOS ARM64 Mach-O (agy), with ad-hoc signing before replacement
- Supports Linux x86_64 ELF and Linux ARM64 (aarch64) ELF (agy / language_server)
- Zero third-party dependencies (Python 3 standard library only)

What it patches (dynamically located via Go 1.20+ pclntab & getter instruction decoding):
1. applyFeatureProviderCheckpointOverrideConfig -> jumps to trampoline in hooks.checkpointNeeded+0x20
2. hooks.checkpointNeeded -> returns (false, nil) at entry; hosts Argon 1M trampoline at +0x20
   Sets max_token_limit = 1000000 (actual request window 983040) for Argon High/Medium/Low (1417/1418/1419)
3. readGlobalRules / parseRuleFile / convertSkillPath -> per-file byte limit 24000 -> 1048576 (1 MiB)
4. computeTruncatedCustomizations -> rules & customizations token budgets 20000 -> 131072 tokens
"""

import argparse
import csv
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TARGET_FUNCS = {
    "GetPlannerConfig": "google3/third_party/jetski/cortex_pb/cortex_go_proto.(*CascadeConfig).GetPlannerConfig",
    "GetPlanModel": "google3/third_party/jetski/cortex_pb/cortex_go_proto.(*CascadePlannerConfig).GetPlanModel",
    "GetMaxTokenLimit": "google3/third_party/jetski/cortex_pb/cortex_go_proto.(*CheckpointConfig).GetMaxTokenLimit",
    "applyOverride": "google3/third_party/jetski/cortex/config/config.applyFeatureProviderCheckpointOverrideConfig",
    "checkpointNeeded": "google3/third_party/oneharness/internal/core/hooks/hooks.checkpointNeeded",
    "readGlobalRules": "google3/third_party/jetski/cortex/customizations/customizations.(*Manager).readGlobalRules",
    "parseRuleFile": "google3/third_party/jetski/cortex/customizations/customizations.(*Manager).parseRuleFile",
    "convertSkillPath": "google3/third_party/jetski/cortex/customizations/customizations.convertSkillPath",
    "computeTruncated": "google3/third_party/jetski/cortex/customizations/customizations.(*Manager).computeTruncatedCustomizations",
}


class BinaryImage:
    def __init__(self, data: bytes):
        self.data = data
        self.fmt = None
        self.arch = None
        self.segments = []  # (name, va, vsize, raw_ptr, raw_size, is_exec)
        self._parse()

    def _parse(self):
        if self.data[:2] == b"MZ":
            self.fmt = "PE"
            e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
            if self.data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
                raise ValueError("Invalid PE signature")
            machine, num_sections, _, _, _, opt_hdr_size, _ = struct.unpack_from("<HHIIIHH", self.data, e_lfanew + 4)
            if machine == 0x8664:
                self.arch = "x86_64"
            elif machine == 0xAA64:
                self.arch = "arm64"
            else:
                raise ValueError(f"Unsupported PE machine: {hex(machine)}")
            opt_off = e_lfanew + 24
            magic = struct.unpack_from("<H", self.data, opt_off)[0]
            if magic != 0x20B:
                raise ValueError(f"Expected PE32+ (0x20b), got {hex(magic)}")
            image_base = struct.unpack_from("<Q", self.data, opt_off + 24)[0]
            sec_off = opt_off + opt_hdr_size
            for i in range(num_sections):
                s = self.data[sec_off + i * 40 : sec_off + (i + 1) * 40]
                name = s[:8].rstrip(b"\x00").decode("ascii", errors="replace")
                vsize, rva, raw_size, raw_ptr, _, _, _, _, chars = struct.unpack_from("<IIIIIIHHI", s, 8)
                is_exec = bool(chars & 0x20000000) or name == ".text"
                self.segments.append((name, image_base + rva, max(vsize, raw_size), raw_ptr, raw_size, is_exec))
        elif self.data[:4] == b"\x7fELF":
            self.fmt = "ELF"
            if len(self.data) < 64:
                raise ValueError("Truncated ELF64 header")
            ei_class, ei_data = self.data[4], self.data[5]
            if ei_class != 2 or ei_data != 1:
                raise ValueError("Only 64-bit little-endian ELF is supported")
            e_machine = struct.unpack_from("<H", self.data, 18)[0]
            if e_machine == 0x3E:
                self.arch = "x86_64"
            elif e_machine == 0xB7:
                self.arch = "arm64"
            else:
                raise ValueError(f"Unsupported ELF machine: {hex(e_machine)}")
            e_phoff = struct.unpack_from("<Q", self.data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", self.data, 54)
            if e_phentsize < 56 or e_phoff + e_phentsize * e_phnum > len(self.data):
                raise ValueError("Invalid ELF64 program header table")
            for i in range(e_phnum):
                ph = self.data[e_phoff + i * e_phentsize : e_phoff + (i + 1) * e_phentsize]
                p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<IIQQQQQQ", ph, 0)
                if p_type == 1:  # PT_LOAD
                    if p_filesz > p_memsz or p_offset + p_filesz > len(self.data):
                        raise ValueError("Invalid ELF64 load segment")
                    is_exec = bool(p_flags & 1)
                    self.segments.append((f"LOAD_{i}", p_vaddr, max(p_memsz, p_filesz), p_offset, p_filesz, is_exec))
        elif self.data[:4] == bytes.fromhex("cffaedfe"):
            self.fmt = "Mach-O"
            if len(self.data) < 32:
                raise ValueError("Truncated Mach-O header")
            _, cpu, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from("<8I", self.data)
            if cpu != 0x0100000C:
                raise ValueError("Only thin ARM64 Mach-O is supported on macOS")
            self.arch = "arm64"
            end = 32 + sizeofcmds
            if end > len(self.data) or ncmds > sizeofcmds // 8:
                raise ValueError("Invalid Mach-O load command table")
            off = 32
            for _ in range(ncmds):
                if off + 8 > end:
                    raise ValueError("Truncated Mach-O load command")
                cmd, size = struct.unpack_from("<II", self.data, off)
                if size < 8 or off + size > end:
                    raise ValueError("Invalid Mach-O load command size")
                if cmd == 0x19:  # LC_SEGMENT_64
                    if size < 72:
                        raise ValueError("Truncated Mach-O segment")
                    _, _, name, va, vsize, raw_ptr, raw_size, _, prot, _, _ = struct.unpack_from(
                        "<II16sQQQQiiII", self.data, off
                    )
                    if raw_ptr + raw_size > len(self.data):
                        raise ValueError("Mach-O segment exceeds file size")
                    self.segments.append((name.rstrip(bytes([0])).decode("ascii", errors="replace"),
                                          va, vsize, raw_ptr, raw_size, bool(prot & 4)))
                off += size
        else:
            raise ValueError("Unsupported binary format (expected PE, ELF or thin ARM64 Mach-O)")

    def va_to_file(self, va: int) -> int:
        for _, sva, _, raw_ptr, raw_size, _ in self.segments:
            if sva <= va < sva + raw_size:
                return raw_ptr + (va - sva)
        raise ValueError(f"Virtual address {hex(va)} is not mapped to file bytes")


def locate_go_functions(img: BinaryImage):
    magic = b"\xf1\xff\xff\xff\x00\x00\x01\x08" if img.arch == "x86_64" else b"\xf1\xff\xff\xff\x00\x00\x04\x08"
    want_rev = {v: k for k, v in TARGET_FUNCS.items()}
    pos = 0
    while True:
        idx = img.data.find(magic, pos)
        if idx == -1:
            break
        pos = idx + 1
        if idx + 72 > len(img.data):
            continue
        nfunc, nfiles, text_start, funcname_off, cu_off, filetab_off, pctab_off, pcln_off = struct.unpack_from(
            "<8Q", img.data, idx + 8
        )
        if not (1000 < nfunc < 5000000 and funcname_off < len(img.data) and pcln_off < len(img.data)):
            continue
        ftab_base = idx + pcln_off
        names_base = idx + funcname_off
        if ftab_base + (nfunc + 1) * 8 > len(img.data):
            continue
        found = {}
        for i in range(nfunc):
            entry_off, func_off = struct.unpack_from("<II", img.data, ftab_base + i * 8)
            func_rec = ftab_base + func_off
            if func_rec + 8 > len(img.data):
                continue
            name_off = struct.unpack_from("<i", img.data, func_rec + 4)[0]
            if name_off < 0 or names_base + name_off >= len(img.data):
                continue
            end_s = img.data.find(b"\x00", names_base + name_off)
            if end_s == -1:
                continue
            name = img.data[names_base + name_off : end_s].decode("utf-8", errors="replace")
            if name in want_rev:
                next_entry_off = struct.unpack_from("<I", img.data, ftab_base + (i + 1) * 8)[0]
                found[want_rev[name]] = (entry_off, next_entry_off)
                if len(found) == len(TARGET_FUNCS):
                    break
        if len(found) == len(TARGET_FUNCS):
            go_text_va = text_start
            if go_text_va == 0:
                total_len = struct.unpack_from("<I", img.data, ftab_base + nfunc * 8)[0]
                exec_ranges = [(sva, sva + svsize) for _, sva, svsize, _, _, is_exec in img.segments if is_exec]
                for _, sva, svsize, raw_ptr, raw_size, is_exec in img.segments:
                    if is_exec:
                        continue
                    for off in range(raw_ptr, raw_ptr + raw_size - 16, 8):
                        minpc, maxpc = struct.unpack_from("<QQ", img.data, off)
                        if maxpc - minpc == total_len and any(lo <= minpc < hi for lo, hi in exec_ranges):
                            go_text_va = minpc
                            break
                    if go_text_va != 0:
                        break
            if go_text_va == 0:
                raise RuntimeError("Found pclntab but could not resolve Go text base VA from moduledata")
            funcs = {}
            for k, (s_off, e_off) in found.items():
                va_s = go_text_va + s_off
                va_e = go_text_va + e_off
                foff_s = img.va_to_file(va_s)
                foff_e = foff_s + (e_off - s_off)
                funcs[k] = {
                    "symbol": TARGET_FUNCS[k],
                    "pc_start": s_off,
                    "pc_end": e_off,
                    "va_start": va_s,
                    "va_end": va_e,
                    "file_start": foff_s,
                    "file_end": foff_e,
                }
            return idx, go_text_va, funcs
    raise RuntimeError("Could not locate the 9 required Go functions in pclntab")


def build_x86_64_plan(img: BinaryImage, funcs: dict):
    data = img.data

    def fbytes(k):
        f = funcs[k]
        return data[f["file_start"] : f["file_end"]]

    # 1. Extract struct field offsets from getters
    b_planner = fbytes("GetPlannerConfig")
    if b_planner[:7] != b"\x48\x85\xc0\x74\x05\x48\x8b" or b_planner[7] != 0x40 or b_planner[9] != 0xC3:
        raise RuntimeError(f"Unexpected GetPlannerConfig bytes: {b_planner[:12].hex()}")
    planner_off = b_planner[8]

    b_model = fbytes("GetPlanModel")
    if b_model[:6] != b"\x48\x85\xc0\x74\x04\x8b" or b_model[6] != 0x40 or b_model[8] != 0xC3:
        raise RuntimeError(f"Unexpected GetPlanModel bytes: {b_model[:12].hex()}")
    plan_model_off = b_model[7]

    b_limit = fbytes("GetMaxTokenLimit")
    if b_limit[:6] != b"\x48\x85\xc0\x74\x04\x8b" or b_limit[6] != 0x40 or b_limit[8] != 0xC3:
        raise RuntimeError(f"Unexpected GetMaxTokenLimit bytes: {b_limit[:12].hex()}")
    max_limit_off = b_limit[7]

    # 2. Locate final merge exit in applyFeatureProviderCheckpointOverrideConfig
    b_apply = fbytes("applyOverride")
    f_apply = funcs["applyOverride"]
    tail_idx = b_apply.find(b"\x31\xc9\xc9\xc3")
    if tail_idx < 6 or b_apply.find(b"\x31\xc9\xc9\xc3", tail_idx + 1) != -1:
        raise RuntimeError("Could not uniquely locate epilogue (31 c9 c9 c3) in applyFeatureProviderCheckpointOverrideConfig")
    exit_rel = tail_idx - 6
    exit_va = f_apply["va_start"] + exit_rel
    exit_foff = f_apply["file_start"] + exit_rel
    exit_cur = b_apply[exit_rel : exit_rel + 6]

    f_chk = funcs["checkpointNeeded"]
    if f_chk["file_end"] - f_chk["file_start"] < 128:
        raise RuntimeError("hooks.checkpointNeeded is too small to host trampoline")
    chk_va = f_chk["va_start"]
    chk_foff = f_chk["file_start"]
    tramp_va = chk_va + 0x20
    tramp_foff = chk_foff + 0x20

    if exit_cur[:3] == b"\x48\x89\x48" and exit_cur[4:6] == b"\x31\xdb":
        checkpoint_off = exit_cur[3]
    else:
        tramp_done = data[tramp_foff + 35 : tramp_foff + 41]
        if tramp_done[:3] == b"\x48\x89\x48" and tramp_done[4:6] == b"\x31\xdb":
            checkpoint_off = tramp_done[3]
        else:
            raise RuntimeError(f"Unrecognized instruction sequence at applyOverride exit: {exit_cur.hex()}")

    exit_before = bytes([0x48, 0x89, 0x48, checkpoint_off, 0x31, 0xDB])
    jmp_to_tramp_rel = tramp_va - (exit_va + 5)
    if not (-0x80000000 <= jmp_to_tramp_rel <= 0x7FFFFFFF):
        raise RuntimeError("Trampoline is out of 32-bit relative jump range")
    exit_after = b"\xe9" + struct.pack("<i", jmp_to_tramp_rel) + b"\x90"

    jmp_back_rel = (exit_va + 6) - (tramp_va + 46)
    tramp_after = (
        b"\x48\x85\xc9"                                  # test rcx, rcx
        b"\x74\x1e"                                      # je .done (+30 -> 35)
        + bytes([0x48, 0x8B, 0x50, planner_off])         # mov rdx, [rax + planner_off]
        + b"\x48\x85\xd2"                                # test rdx, rdx
        + b"\x74\x15"                                    # je .done (+21 -> 35)
        + bytes([0x8B, 0x52, plan_model_off])            # mov edx, [rdx + plan_model_off]
        + b"\x81\xea\x89\x05\x00\x00"                    # sub edx, 1417
        + b"\x83\xfa\x02"                                # cmp edx, 2
        + b"\x77\x07"                                    # ja .done (+7 -> 35)
        + bytes([0xC7, 0x41, max_limit_off])             # mov dword ptr [rcx + max_limit_off], 1000000
        + struct.pack("<I", 1000000)
        + bytes([0x48, 0x89, 0x48, checkpoint_off])      # .done: mov [rax + checkpoint_off], rcx
        + b"\x31\xdb"                                    # xor ebx, ebx
        + b"\xe9" + struct.pack("<i", jmp_back_rel)      # jmp (exit_va + 6)
    )
    assert len(tramp_after) == 46
    chk_entry_after = b"\x31\xc0\x31\xdb\x31\xc9\xc3"

    # 3. Single-file rule/skill limit: 24000 -> 1048576
    rule_sites = []
    for k in ("readGlobalRules", "parseRuleFile", "convertSkillPath"):
        fb = fbytes(k)
        f_info = funcs[k]
        pat_before = b"\xb9\xc0\x5d\x00\x00"
        pat_after = b"\xb9\x00\x00\x10\x00"
        idxs = [i for i in range(len(fb) - 4) if fb[i : i + 5] in (pat_before, pat_after)]
        if len(idxs) != 1:
            raise RuntimeError(f"Expected 1 occurrence of 24000/1048576 mov ecx in {k}, found {len(idxs)}")
        rel = idxs[0]
        rule_sites.append((k, f_info["va_start"] + rel, f_info["file_start"] + rel, pat_before, pat_after))

    # 4. Aggregate token budgets: 20000 -> 131072
    fb_trunc = fbytes("computeTruncated")
    f_trunc = funcs["computeTruncated"]
    idx_r9 = fb_trunc.find(b"\x41\xb9\x20\x4e\x00\x00")
    idx_edx = fb_trunc.find(b"\xba\x20\x4e\x00\x00")
    if idx_r9 == -1 or idx_edx == -1:
        raise RuntimeError("Could not find 0x4e20 default assignments in computeTruncatedCustomizations")
    store_r9 = fb_trunc.find(b"\x44\x89\x8c\x24", idx_r9, idx_r9 + 128)
    store_edx = fb_trunc.find(b"\x89\x94\x24", idx_edx, idx_edx + 64)
    if store_r9 == -1 or store_edx == -1:
        raise RuntimeError("Could not find stack slot stores for rules/customizations budgets")
    disp_a = fb_trunc[store_r9 + 4 : store_r9 + 8]
    disp_b = fb_trunc[store_edx + 3 : store_edx + 7]

    budget1_before = b"\x8b\x9c\x24" + disp_b
    budget1_after = b"\xbb\x00\x00\x02\x00\x66\x90"
    budget2_before = b"\x8b\x84\x24" + disp_a
    budget2_after = b"\xb8\x00\x00\x02\x00\x66\x90"

    call_matches = []
    for i in range(len(fb_trunc) - 18):
        if (
            fb_trunc[i : i + 7] in (budget1_before, budget1_after)
            and fb_trunc[i + 7 : i + 10] == b"\x48\x89\xc1"
            and fb_trunc[i + 10 : i + 17] in (budget2_before, budget2_after)
            and fb_trunc[i + 17] == 0xE8
        ):
            call_matches.append(i)
    if len(call_matches) != 1:
        raise RuntimeError(f"Expected 1 budget call-site match in computeTruncatedCustomizations, found {len(call_matches)}")
    c_rel = call_matches[0]

    changes = [
        {
            "name": "applyOverride_exit",
            "purpose": "applyFeatureProviderCheckpointOverrideConfig: jump to Argon 1M trampoline",
            "va": hex(exit_va),
            "offset": hex(exit_foff),
            "before": exit_before.hex(),
            "after": exit_after.hex(),
            "fixed_before": True,
        },
        {
            "name": "checkpointNeeded_entry",
            "purpose": "hooks.checkpointNeeded: return (false, nil)",
            "va": hex(chk_va),
            "offset": hex(chk_foff),
            "before": data[chk_foff : chk_foff + len(chk_entry_after)].hex(),
            "after": chk_entry_after.hex(),
            "fixed_before": False,
        },
        {
            "name": "checkpointNeeded_trampoline",
            "purpose": "hooks.checkpointNeeded+0x20: Argon High/Medium/Low (1417..1419) max_token_limit=1000000 trampoline",
            "va": hex(tramp_va),
            "offset": hex(tramp_foff),
            "before": data[tramp_foff : tramp_foff + len(tramp_after)].hex(),
            "after": tramp_after.hex(),
            "fixed_before": False,
        },
    ]
    for k, va, foff, b_bef, b_aft in rule_sites:
        changes.append({
            "name": f"{k}_limit",
            "purpose": f"{k}: per-file byte limit 24000 -> 1048576",
            "va": hex(va),
            "offset": hex(foff),
            "before": b_bef.hex(),
            "after": b_aft.hex(),
            "fixed_before": True,
        })
    changes.append({
        "name": "customizations_budget",
        "purpose": "computeTruncatedCustomizations: customizations token budget -> 131072",
        "va": hex(f_trunc["va_start"] + c_rel),
        "offset": hex(f_trunc["file_start"] + c_rel),
        "before": budget1_before.hex(),
        "after": budget1_after.hex(),
        "fixed_before": True,
    })
    changes.append({
        "name": "rules_budget",
        "purpose": "computeTruncatedCustomizations: rules token budget -> 131072",
        "va": hex(f_trunc["va_start"] + c_rel + 10),
        "offset": hex(f_trunc["file_start"] + c_rel + 10),
        "before": budget2_before.hex(),
        "after": budget2_after.hex(),
        "fixed_before": True,
    })
    return {
        "field_offsets": {
            "planner": planner_off,
            "plan_model": plan_model_off,
            "max_token_limit": max_limit_off,
            "checkpoint": checkpoint_off,
        },
        "changes": changes,
    }


def build_arm64_plan(img: BinaryImage, funcs: dict):
    data = img.data

    def fbytes(k):
        f = funcs[k]
        return data[f["file_start"] : f["file_end"]]

    def find_ldr_imm(fb: bytes, mask: int, op: int, scale: int, name: str) -> int:
        for off in range(0, len(fb) - 3, 4):
            insn = struct.unpack_from("<I", fb, off)[0]
            if (insn & mask) == op:
                return ((insn >> 10) & 0xFFF) * scale
        raise RuntimeError(f"Could not decode field offset from {name}")

    planner_off = find_ldr_imm(fbytes("GetPlannerConfig"), 0xFFC003FF, 0xF9400000, 8, "GetPlannerConfig")
    # Go may sign-extend enum getters with LDRSW rather than LDR W.
    model_bytes = fbytes("GetPlanModel")
    try:
        plan_model_off = find_ldr_imm(model_bytes, 0xFFC003FF, 0xB9400000, 4, "GetPlanModel")
    except RuntimeError:
        plan_model_off = find_ldr_imm(model_bytes, 0xFFC003FF, 0xB9800000, 4, "GetPlanModel")
    max_limit_off = find_ldr_imm(fbytes("GetMaxTokenLimit"), 0xFFC003FF, 0xB9400000, 4, "GetMaxTokenLimit")

    b_apply = fbytes("applyOverride")
    f_apply = funcs["applyOverride"]
    f_chk = funcs["checkpointNeeded"]
    if f_chk["file_end"] - f_chk["file_start"] < 128:
        raise RuntimeError("hooks.checkpointNeeded is too small to host trampoline")
    chk_va = f_chk["va_start"]
    chk_foff = f_chk["file_start"]
    tramp_va = chk_va + 0x20
    tramp_foff = chk_foff + 0x20

    exit_candidates = []
    checkpoint_off = 16
    # Supported compiler layouts: (config pointer, checkpoint pointer, scratch).
    layouts = ((0, 1, 3), (3, 0, 4))
    for off in range(0, len(b_apply) - 3, 4):
        insn = struct.unpack_from("<I", b_apply, off)[0]
        va = f_apply["va_start"] + off
        b_to_tramp = 0x14000000 | (((tramp_va - va) >> 2) & 0x03FFFFFF)
        for config, checkpoint, scratch in layouts:
            store = 0xF9000000 | ((checkpoint_off // 8) << 10) | (config << 5) | checkpoint
            # 1.5.0 returns the config in x0 after storing x0 into [x3].
            suffix = ([0xAA0303E0] if config == 3 else []) + [0xAA1F03E1, 0xAA1F03E2]
            expected_tail = struct.pack(f"<{len(suffix)}I", *suffix)
            if (insn in (store, b_to_tramp) and
                    b_apply[off + 4:off + 4 + len(expected_tail)] == expected_tail):
                exit_candidates.append((off, config, checkpoint, scratch, store))
    if len(exit_candidates) != 1:
        raise RuntimeError(f"Expected 1 exit store in ARM64 applyOverride, found {len(exit_candidates)}")
    exit_rel, config, checkpoint, scratch, checkpoint_store = exit_candidates[0]
    exit_va = f_apply["va_start"] + exit_rel
    exit_foff = f_apply["file_start"] + exit_rel

    word_diff = (tramp_va - exit_va) >> 2
    if not (-0x2000000 <= word_diff <= 0x1FFFFFF):
        raise RuntimeError("ARM64 trampoline out of 26-bit B range")

    exit_before = struct.pack("<I", checkpoint_store)
    exit_after = struct.pack("<I", 0x14000000 | (word_diff & 0x03FFFFFF))

    chk_entry_after = struct.pack("<4I", 0xD2800000, 0xD2800001, 0xD2800002, 0xD65F03C0)
    tramp_insns = [
        0xB4000140 | checkpoint,                              # cbz checkpoint, .done
        0xF9400000 | ((planner_off // 8) << 10) | (config << 5) | scratch,
        0xB4000100 | scratch,                                 # cbz planner, .done
        0xB9400000 | ((plan_model_off // 4) << 10) | (scratch << 5) | scratch,
        0x51162400 | (scratch << 5) | scratch,                 # sub model, model, #1417
        0x7100081F | (scratch << 5),                           # cmp model, #2
        0x54000088,                                           # b.hi .done
        0x52884800 | scratch,                                 # mov scratch, #0x4240
        0x72A001E0 | scratch,                                 # movk scratch, #0xf, lsl #16
        0xB9000000 | ((max_limit_off // 4) << 10) | (checkpoint << 5) | scratch,
        checkpoint_store,                                    # original store
        0x14000000 | ((((exit_va + 4) - (tramp_va + 44)) >> 2) & 0x03FFFFFF),
    ]
    tramp_after = struct.pack(f"<{len(tramp_insns)}I", *tramp_insns)

    rule_sites = []
    for k in ("readGlobalRules", "parseRuleFile", "convertSkillPath"):
        fb = fbytes(k)
        f_info = funcs[k]
        pat_before = struct.pack("<I", 0xD28BB802)
        pat_after = struct.pack("<I", 0xD2A00202)
        idxs = [i for i in range(0, len(fb) - 3, 4) if fb[i : i + 4] in (pat_before, pat_after)]
        if len(idxs) != 1:
            raise RuntimeError(f"Expected 1 occurrence of mov x2, #24000 in {k}, found {len(idxs)}")
        rel = idxs[0]
        rule_sites.append((k, f_info["va_start"] + rel, f_info["file_start"] + rel, pat_before, pat_after))

    fb_trunc = fbytes("computeTruncated")
    f_trunc = funcs["computeTruncated"]
    budget_sites = []
    for off in range(0x10, len(fb_trunc) - 3, 4):
        insn = struct.unpack_from("<I", fb_trunc, off)[0]
        prev_insn = struct.unpack_from("<I", fb_trunc, off - 0x10)[0]
        for rd in range(31):
            mov_20000 = 0xD289C400 | rd
            mov_131072 = 0xD2A00040 | rd
            ldrsw_rd = 0xB9800000 | (rd << 5) | rd
            if (insn == mov_20000 and prev_insn == ldrsw_rd) or (insn == mov_131072 and prev_insn == mov_131072):
                budget_sites.append((off - 0x10, struct.pack("<I", ldrsw_rd), struct.pack("<I", mov_131072), f"reg_x{rd}_cfg"))
                budget_sites.append((off, struct.pack("<I", mov_20000), struct.pack("<I", mov_131072), f"reg_x{rd}_def"))
    if len(budget_sites) != 4:
        raise RuntimeError(f"Expected 4 budget sites in ARM64 computeTruncatedCustomizations, found {len(budget_sites)}")

    changes = [
        {
            "name": "applyOverride_exit",
            "purpose": "applyFeatureProviderCheckpointOverrideConfig: branch to Argon 1M trampoline",
            "va": hex(exit_va),
            "offset": hex(exit_foff),
            "before": exit_before.hex(),
            "after": exit_after.hex(),
            "fixed_before": True,
        },
        {
            "name": "checkpointNeeded_entry",
            "purpose": "hooks.checkpointNeeded: return (false, nil)",
            "va": hex(chk_va),
            "offset": hex(chk_foff),
            "before": data[chk_foff : chk_foff + len(chk_entry_after)].hex(),
            "after": chk_entry_after.hex(),
            "fixed_before": False,
        },
        {
            "name": "checkpointNeeded_trampoline",
            "purpose": "hooks.checkpointNeeded+0x20: Argon High/Medium/Low (1417..1419) max_token_limit=1000000 trampoline",
            "va": hex(tramp_va),
            "offset": hex(tramp_foff),
            "before": data[tramp_foff : tramp_foff + len(tramp_after)].hex(),
            "after": tramp_after.hex(),
            "fixed_before": False,
        },
    ]
    for k, va, foff, b_bef, b_aft in rule_sites:
        changes.append({
            "name": f"{k}_limit",
            "purpose": f"{k}: per-file byte limit 24000 -> 1048576",
            "va": hex(va),
            "offset": hex(foff),
            "before": b_bef.hex(),
            "after": b_aft.hex(),
            "fixed_before": True,
        })
    for rel, b_bef, b_aft, tag in budget_sites:
        changes.append({
            "name": f"budget_{tag}",
            "purpose": f"computeTruncatedCustomizations ({tag}): token budget -> 131072",
            "va": hex(f_trunc["va_start"] + rel),
            "offset": hex(f_trunc["file_start"] + rel),
            "before": b_bef.hex(),
            "after": b_aft.hex(),
            "fixed_before": True,
        })
    return {
        "field_offsets": {
            "planner": planner_off,
            "plan_model": plan_model_off,
            "max_token_limit": max_limit_off,
            "checkpoint": checkpoint_off,
        },
        "changes": changes,
    }


def valid_checkpoint_entry(img, function):
    """Validate the supported Go stack-check sequence, including its branch."""
    start, end = function["file_start"], function["file_end"]
    code = img.data[start:end]
    if img.arch == "arm64":
        if len(code) < 16:
            return False
        load, sub, compare, branch = struct.unpack_from("<4I", code)
        # LDR X16,[X28,#16]; SUB X17,SP,#frame; CMP X17,X16; B.LS slow
        if (load != 0xF9400B90 or sub & 0xFFC003FF != 0xD10003F1 or
                compare != 0xEB10023F or branch & 0xFF00001F != 0x54000009):
            return False
        displacement = (branch >> 5) & 0x7FFFF
        if displacement & 0x40000:
            displacement -= 0x80000
        destination = 12 + displacement * 4
        return 16 <= destination < len(code)
    # CMP RSP,[R14+16] or LEA R12,[RSP-frame]; CMP R12,[R14+16].
    if code.startswith(bytes.fromhex("493b6610")):
        branch_at = 4
    elif code.startswith(bytes.fromhex("4c8da424")) and code[8:12] == bytes.fromhex("4d3b6610"):
        branch_at = 12
    elif code.startswith(bytes.fromhex("4c8d6424")) and code[5:9] == bytes.fromhex("4d3b6610"):
        branch_at = 9
    else:
        return False
    if code[branch_at:branch_at+1] == b"\x76" and len(code) >= branch_at + 2:
        destination = branch_at + 2 + struct.unpack_from("<b", code, branch_at + 1)[0]
        return branch_at + 2 <= destination < len(code)
    if code[branch_at:branch_at+2] == b"\x0f\x86" and len(code) >= branch_at + 6:
        destination = branch_at + 6 + struct.unpack_from("<i", code, branch_at + 2)[0]
        return branch_at + 6 <= destination < len(code)
    return False


def analyze_binary(target: Path):
    data = target.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    img = BinaryImage(data)
    pcln_off, go_text_va, funcs = locate_go_functions(img)
    plan = build_x86_64_plan(img, funcs) if img.arch == "x86_64" else build_arm64_plan(img, funcs)

    all_after = True
    all_fixed_before = True
    for c in plan["changes"]:
        off = int(c["offset"], 16)
        aft = bytes.fromhex(c["after"])
        bef = bytes.fromhex(c["before"])
        cur = data[off : off + len(aft)]
        if cur != aft:
            all_after = False
        if c["fixed_before"] and cur != bef:
            all_fixed_before = False

    if all_after:
        status = "ALREADY_PATCHED"
    elif all_fixed_before:
        # Variable original bytes must not hide an interrupted checkpoint patch.
        entry = next(c for c in plan["changes"] if c["name"] == "checkpointNeeded_entry")
        trampoline = next(c for c in plan["changes"] if c["name"] == "checkpointNeeded_trampoline")
        original_entry = valid_checkpoint_entry(img, funcs["checkpointNeeded"])
        partial = False
        for change in (entry, trampoline):
            current, patched = bytes.fromhex(change["before"]), bytes.fromhex(change["after"])
            if img.arch == "arm64":
                # Original store may legitimately occur in the discarded body.
                excluded = {40} if change is trampoline else set()
                partial |= any(current[i:i+4] == patched[i:i+4]
                               for i in range(0, len(patched), 4) if i not in excluded)
            else:
                partial |= current == patched or current[:5] == patched[:5]
        status = "UNPATCHED" if original_entry and not partial else "UNKNOWN_OR_PARTIAL"
    else:
        status = "UNKNOWN_OR_PARTIAL"

    return {
        "path": str(target),
        "format": img.fmt,
        "arch": img.arch,
        "size": len(data),
        "sha256": sha256,
        "pclntab_offset": hex(pcln_off),
        "go_text_va": hex(go_text_va),
        "status": status,
        "backup_scope": "Pre-patch bytes; instruction validation is not vendor authenticity verification.",
        "field_offsets": plan["field_offsets"],
        "functions": {k: {fk: (hex(fv) if isinstance(fv, int) else fv) for fk, fv in v.items()} for k, v in funcs.items()},
        "changes": plan["changes"],
    }


def update_agy_sidecar_if_present(target: Path):
    sidecar = target.parent / "agy.version.json"
    if not sidecar.exists():
        return
    try:
        meta = json.loads(sidecar.read_text(encoding="utf-8"))
        st = target.stat()
        meta["size"] = st.st_size
        meta["mtimeMs"] = st.st_mtime_ns / 1_000_000.0
        meta["ino"] = 0
        tmp = sidecar.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, sidecar)
        print(f"  [sidecar] Updated {sidecar} (size={st.st_size}, ino=0)")
    except Exception as e:
        print(f"  [sidecar] Note: could not update {sidecar}: {e}")


def get_binary_version(target: Path) -> str:
    for flag in ("--version", "--stamp"):
        try:
            res = subprocess.run([str(target), flag], capture_output=True, text=True, timeout=10)
            out = (res.stdout + "\n" + res.stderr).strip()
            if out:
                first_line = out.splitlines()[0].strip()
                for line in out.splitlines():
                    if "Built at CL:" in line:
                        return "CL" + line.split("Built at CL:")[-1].strip()
                return first_line.replace(" ", "_")
        except Exception:
            pass
    return "unknown"


def unique_targets(paths):
    found = {}
    for path in paths:
        path = path.expanduser().resolve()
        found.setdefault(os.path.normcase(str(path)), path)
    return list(found.values())


def discover_default_targets() -> list[Path]:
    """Bounded discovery of backend files; no whole-disk or other-user scan."""
    home = Path.home()
    names = ("agy.exe", "language_server.exe") if sys.platform == "win32" else (
        "agy", "language_server", "language_server_macos_arm", "language_server_macos_arm64",
        "language_server_macos", "language_server_linux_x64", "language_server_linux_arm",
        "language_server_linux_arm64")
    candidates = [home / ".gemini/bin" / names[0], home / ".local/bin" / names[0]]
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if entry:
            candidates.extend(Path(entry) / name for name in names)
    roots = []
    if sys.platform == "win32":
        roots.append(Path(os.environ.get("LOCALAPPDATA", str(home / "AppData/Local"))) / "Programs")
        for key in ("ProgramFiles", "ProgramFiles(x86)"):
            if os.environ.get(key):
                roots.append(Path(os.environ[key]))
    elif sys.platform == "darwin":
        roots.extend((Path("/Applications"), home / "Applications"))
    else:
        roots.extend((Path("/opt"), Path("/usr/share"), Path("/usr/lib"), home / ".local/share"))
    # Only known product directory names; never recursively walk arbitrary apps.
    for root in roots:
        try:
            products = list(root.iterdir()) if root.is_dir() else []
        except OSError as exc:
            print(f"Discovery note: cannot inspect {root}: {exc}")
            continue
        for product in products:
            if "antigravity" not in product.name.lower() or not product.is_dir():
                continue
            resources = product / "Contents/Resources" if product.suffix.lower() == ".app" else product / "resources"
            locations = (product, product / "bin", resources / "bin", resources / "app/bin",
                         resources / "app/extensions/antigravity/bin",
                         resources / "app/extensions/agy/bin")
            for location in locations:
                candidates.extend(location / name for name in names)
    return unique_targets(c for c in candidates if c.is_file())


def patch_target(target: Path, backup_dir: Path, dry_run: bool = False):
    info = analyze_binary(target)
    print(f"\nTarget : {info['path']}")
    print(f"Format : {info['format']} {info['arch']} ({info['size']} bytes)")
    print(f"SHA256 : {info['sha256']}")
    print(f"pclntab: {info['pclntab_offset']} | Go text VA: {info['go_text_va']}")
    print(f"Offsets: {info['field_offsets']}")
    print(f"Status : {info['status']}")

    for c in info["changes"]:
        print(f"  - [{c['offset']}] ({c['va']}) {c['purpose']}")
        print(f"      before: {c['before']}")
        print(f"      after : {c['after']}")

    if dry_run:
        return info

    if info["status"] == "ALREADY_PATCHED":
        print("  -> Already patched! Nothing to do.")
        update_agy_sidecar_if_present(target)
        return info

    if info["status"] != "UNPATCHED":
        raise RuntimeError(f"Refusing to patch {target}: binary state is {info['status']}")

    ver = get_binary_version(target)
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_file = backup_dir / f"{target.name}-{ver}-original-{info['sha256'][:16]}.bak"
    raw_bytes = target.read_bytes()
    if hashlib.sha256(raw_bytes).hexdigest() != info["sha256"]:
        raise RuntimeError("Backend changed during analysis; rerun before patching")
    if backup_file.exists():
        bak_sha = hashlib.sha256(backup_file.read_bytes()).hexdigest()
        if bak_sha != info["sha256"]:
            raise RuntimeError(f"Backup file {backup_file} exists with different SHA256!")
        # Windows requires a writable handle for fsync; r+b preserves contents.
        with backup_file.open("r+b") as backup:
            os.fsync(backup.fileno())
    else:
        with backup_file.open("xb") as backup:
            backup.write(raw_bytes)
            backup.flush()
            os.fsync(backup.fileno())
    sync_directory(backup_dir)
    if hashlib.sha256(backup_file.read_bytes()).hexdigest() != info["sha256"]:
        raise RuntimeError("Original backup failed SHA256 verification")
    print(f"  [backup] Saved original to {backup_file}")

    out = bytearray(raw_bytes)
    for c in info["changes"]:
        off = int(c["offset"], 16)
        bef = bytes.fromhex(c["before"])
        aft = bytes.fromhex(c["after"])
        assert len(bef) == len(aft)
        if out[off : off + len(bef)] != bef:
            raise RuntimeError(f"Byte mismatch at {c['offset']} ({c['purpose']})")
        out[off : off + len(aft)] = aft

    assert len(out) == len(raw_bytes)
    info["backup_path"] = str(backup_file)
    info["version"] = ver

    manifest_file = backup_dir / f"{target.name}-{ver}-manifest-{info['sha256'][:16]}.json"

    fd, tmp_path_str = tempfile.mkstemp(prefix=f".{target.name}-patch-", dir=str(target.parent))
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(out)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp_path, target.stat().st_mode & 0o777)
        except Exception:
            pass
        if info["format"] == "Mach-O":
            if sys.platform != "darwin":
                raise RuntimeError("Mach-O patching requires macOS codesign")
            # Sign and verify the temporary file before replacing the backend.
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(tmp_path)],
                           check=True, capture_output=True, text=True)
            subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(tmp_path)],
                           check=True, capture_output=True, text=True)
            if analyze_binary(tmp_path)["status"] != "ALREADY_PATCHED":
                raise RuntimeError("Signed binary failed patch verification")
        patched_sha256 = hashlib.sha256(tmp_path.read_bytes()).hexdigest()
        info["patched_sha256"] = patched_sha256
        info["patched_size"] = tmp_path.stat().st_size
        write_manifest(manifest_file, info)
        replace_with_retry(tmp_path, target, info["sha256"])
    except PermissionError as e:
        raise RuntimeError(
            f"PermissionError replacing {target} (file is locked by a running Antigravity/agy process).\n"
            f"Close Antigravity IDE / Desktop / CLI first, or pass --kill to stop running backend processes."
        ) from e
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass

    update_agy_sidecar_if_present(target)
    if analyze_binary(target)["status"] != "ALREADY_PATCHED":
        raise RuntimeError(f"Post-write patch verification failed for {target}; original backup: {backup_file}")
    print(f"  [patched] Successfully patched {target}")
    print(f"  [patched] New SHA256: {patched_sha256}")
    print(f"  [manifest] Saved to {manifest_file}")
    return info


def restore_target(target: Path, backup_dir: Path):
    before_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
    print(f"\nTarget : {target} (SHA256: {before_sha256})")
    mf, mdata, bak = select_restore_backup(target, backup_dir, before_sha256)
    bak_bytes = bak.read_bytes()
    if hashlib.sha256(bak_bytes).hexdigest() != mdata["sha256"]:
        raise RuntimeError(f"Backup hash mismatch: {bak}")
    fd, tmp_str = tempfile.mkstemp(prefix=f".{target.name}-restore-", dir=str(target.parent))
    tmp_p = Path(tmp_str)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(bak_bytes)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp_p, target.stat().st_mode & 0o777)
        except Exception:
            pass
        replace_with_retry(tmp_p, target, before_sha256)
    finally:
        if tmp_p.exists():
            try:
                tmp_p.unlink()
            except Exception:
                pass
    update_agy_sidecar_if_present(target)
    if hashlib.sha256(target.read_bytes()).hexdigest() != mdata["sha256"]:
        raise RuntimeError(f"Restored file hash mismatch: {target}")
    print(f"  [restored] Restored original {mdata['sha256']} from {bak}")
    return {"path": str(target), "operation": "restore", "status": "RESTORED",
            "before_sha256": before_sha256, "restored_sha256": mdata["sha256"],
            "backup_path": str(bak), "manifest_path": str(mf)}


def kill_running_backends(targets):
    for process in running_backends(targets):
        print(f"Stopping PID={process['pid']} name={process['name']}")
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(process['pid'])], check=True, capture_output=True)
        else:
            os.kill(process["pid"], 15)
    time.sleep(0.5)


def running_backends(targets):
    """Match executable names, never arbitrary command-line substrings."""
    names = {p.name.lower() for p in targets}
    if sys.platform.startswith("linux"):
        selected = {str(p.resolve()) for p in targets}
        found = []
        for directory in Path("/proc").iterdir():
            if not directory.name.isdigit():
                continue
            try:
                executable = os.readlink(directory / "exe")
                if executable.endswith(" (deleted)"):
                    executable = executable[:-10]
            except FileNotFoundError:
                continue  # Process exited, or kernel thread has no executable.
            except PermissionError:
                # Inaccessible processes must not silently bypass the guard.
                name = (directory / "comm").read_text().strip()
                if any(n[:15] == name for n in names):
                    raise RuntimeError(f"Cannot inspect possible backend PID={directory.name} name={name}")
                continue
            if executable in selected:
                found.append({"pid": int(directory.name), "name": Path(executable).name})
        return found
    if os.name == "nt":
        result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                                check=True, capture_output=True, text=True)
        return [{"pid": int(row[1]), "name": row[0]} for row in csv.reader(result.stdout.splitlines())
                if len(row) >= 2 and row[0].lower() in names]
    result = subprocess.run(["ps", "-axo", "pid=,comm="],
                            check=True, capture_output=True, text=True)
    found = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and Path(parts[1]).name.lower() in names:
            found.append({"pid": int(parts[0]), "name": Path(parts[1]).name})
    return found


def wait_for_backends(targets):
    while True:
        processes = running_backends(targets)
        if not processes:
            return
        print("\n发现正在运行的后端，请先关闭对应 IDE / CLI：")
        for process in processes:
            print(f"  PID={process['pid']}  name={process['name']}")
        try:
            answer = input("关闭后输入 Y 确认并重新检查；其他输入取消 / Close processes, then Y to retry: ")
        except EOFError:
            raise SystemExit("No interactive input available; close the listed processes and rerun. No backend replaced.")
        if answer.strip().lower() != "y":
            raise SystemExit("Cancelled. No backend replaced.")


def replace_with_retry(source, target, expected_sha256):
    while True:
        wait_for_backends([target])
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected_sha256:
            raise RuntimeError(f"Backend changed before replacement: {target}; rerun the check")
        try:
            os.replace(source, target)
            return
        except PermissionError:
            print(f"无法替换 {target}：文件被占用或目录不可写。")
            for process in running_backends([target]):
                print(f"  PID={process['pid']}  name={process['name']}")
            try:
                answer = input("关闭占用进程或解决权限后输入 Y 重试，其他输入取消: ")
            except EOFError:
                raise SystemExit("Replacement cancelled: no interactive input available.")
            if answer.strip().lower() != "y":
                raise SystemExit("Replacement cancelled.")


def inspect_context(conversation_id=None, db_path=None):
    """Read historical request metadata; absence or parse failure is never 'locked'."""
    from verify_session import inspect_session
    try:
        report = inspect_session(conversation_id=conversation_id, db_path=db_path)
        latest = report["latest_turn"]
        limits = (latest["gen_max_context_tokens"], latest["executor_max_token_limit"])
        if limits == (983040, 983040):
            state = "EXPECTED_WINDOW"
        elif limits == (256000, 256000):
            state = "LIMITED_256K"
        elif limits[0] != limits[1]:
            state = "MIXED_LIMITS"
        else:
            state = "OTHER_WINDOW"
        report["state"] = state
        from verify_session import database_activity
        report["recorded_at"] = database_activity(Path(report["db_path"]))
        report["scope"] = "Latest stored request only; model and current running backend are not verified."
        return report
    except (Exception, SystemExit) as exc:
        return {"state": "UNKNOWN", "error": str(exc),
                "scope": "No conclusion about context limit; DB may be absent, busy, empty or use a new schema."}


def inspect_contexts(conversation_id=None, db_path=None):
    if conversation_id or db_path:
        return [inspect_context(conversation_id, db_path)]
    from verify_session import conversation_dirs, database_activity
    reports = []
    for directory in conversation_dirs():
        try:
            databases = list(directory.glob("*.db"))
            if databases:
                report = inspect_context(db_path=max(databases, key=database_activity))
            else:
                report = {"state": "UNKNOWN", "error": "No conversation database found"}
            report["source"] = str(directory)
            reports.append(report)
        except OSError as exc:
            reports.append({"source": str(directory), "state": "UNKNOWN", "error": str(exc)})
    return reports


def preflight(targets, conversation_id=None, db_path=None):
    binaries = []
    for target in targets:
        target = target.expanduser().resolve()
        try:
            info = analyze_binary(target)
            info["compatible"] = info["status"] in ("UNPATCHED", "ALREADY_PATCHED")
            binaries.append(info)
        except Exception as exc:
            binaries.append({"path": str(target), "status": "UNSUPPORTED_OR_UNRECOGNIZED",
                             "compatible": False, "error": str(exc)})
    compatible = bool(binaries) and all(b["compatible"] for b in binaries)
    sessions = inspect_contexts(conversation_id, db_path)
    report = {"binaries": binaries, "compatible": compatible, "sessions": sessions,
              "session": max(sessions, key=lambda s: s.get("recorded_at", 0))}
    print("\n=== Read-only preflight / 运行前检查 ===")
    for info in binaries:
        print(f"Binary : {info['path']}")
        print(f"Status : {info['status']} | compatible={info['compatible']}")
        if "error" in info:
            print(f"Reason : {info['error']}")
        else:
            print(f"Format : {info['format']} {info['arch']} | sites={len(info['changes'])}")
            print(f"SHA256 : {info['sha256']}")
            print(f"Fields : {info['field_offsets']}")
    if not binaries:
        print("Binary : NOT_FOUND; specify --target <backend path>")
    for session in sessions:
        print(f"Context: {session['state']}")
        if "source" in session:
            print(f"Source : {session['source']}")
        if "latest_turn" in session:
            latest = session["latest_turn"]
            print(f"DB     : {session['db_path']}")
            print(f"Limits : request={latest['gen_max_context_tokens']}, executor={latest['executor_max_token_limit']}")
            print(f"Turns  : gen={latest['gen_idx']}, executor={latest['executor_idx']}")
        else:
            print(f"Reason : {session['error']}")
    print("Note   : Stored requests are not mapped to a particular binary. They do not prove the current model/process or long-session retention.")
    return report


def select_restore_backup(target, backup_dir, current=None):
    current = current or hashlib.sha256(target.read_bytes()).hexdigest()
    for path in sorted(backup_dir.glob(f"{target.name}-*-manifest-*.json"), reverse=True):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("Manifest must be an object")
            original = manifest["sha256"]
            if not isinstance(original, str) or len(original) != 64 or any(c not in "0123456789abcdef" for c in original):
                raise ValueError("Invalid original SHA256")
            if current not in (manifest.get("patched_sha256"), original):
                continue
            backup = Path(manifest["backup_path"])
            if not backup.is_file() or hashlib.sha256(backup.read_bytes()).hexdigest() != original:
                raise ValueError("Backup missing or hash mismatch")
            return path, manifest, backup
        except (ValueError, TypeError, KeyError, OSError) as exc:
            print(f"  [backup warning] Skipping invalid manifest {path}: {exc}")
    raise RuntimeError(f"No verified matching backup for {target} in {backup_dir}")


def find_restore_backup(target, backup_dir):
    return select_restore_backup(target, backup_dir)[2]


def sync_directory(directory):
    # Windows does not support opening directories through os.open.
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_manifest(path, report):
    fd, filename = tempfile.mkstemp(prefix=".manifest-", suffix=".tmp", dir=str(path.parent))
    temporary = Path(filename)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(json.dumps(report, indent=2) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def confirm_actions(targets, backup_dir, restore=False):
    print("\n准备恢复原版 / Restore originals:" if restore else "\n准备备份并修改 / Back up and patch:")
    for target in targets:
        print(f"  {target}")
    print(f"Backup : {backup_dir}")
    try:
        answer = input("输入 Y 继续，其他输入取消 / Continue? [y/N]: ")
    except EOFError:
        raise SystemExit("Cancelled: interactive Y confirmation is required. No files modified.")
    if answer.strip().lower() != "y":
        raise SystemExit("Cancelled. No files modified.")


def validate_report_path(path, targets, backup_dir):
    if path is None:
        return
    path = path.expanduser()
    # Refuse all existing files, including hard links and dangling symlinks.
    if path.exists() or path.is_symlink():
        raise ValueError(f"Report already exists; choose a new filename: {path}")
    resolved = path.expanduser().resolve()
    if resolved in targets or resolved == backup_dir or backup_dir in resolved.parents:
        raise ValueError("Report must not overlap a backend or backup directory")
    if resolved.suffix.lower() in (".db", ".sqlite", ".bak", ".exe"):
        raise ValueError("Use a new JSON report filename, not a backend/database/backup filename")


def write_report(path, report):
    # Exclusive creation closes the validation/write race and never truncates files.
    with path.expanduser().open("x", encoding="utf-8") as output:
        output.write(json.dumps(report, indent=2) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Auto-locate (via Go pclntab) and patch Antigravity 1M context & rules budgets.")
    ap.add_argument("--target", type=Path, action="append", help="Path to agy / language_server binary (repeatable). Defaults to auto-discovered installations.")
    ap.add_argument("--check", "--dry-run", dest="dry_run", action="store_true", help="Read-only check: locate symbols, verify patterns, and print patch plan without modifying files.")
    ap.add_argument("--status", action="store_true", help="Read-only binary compatibility and recorded session context check (same as --check).")
    ap.add_argument("--conversation-id", help="Inspect this conversation instead of the newest database.")
    ap.add_argument("--db", type=Path, help="Inspect an explicit conversation database (read-only).")
    ap.add_argument("--restore", action="store_true", help="Restore original unpatched binary from backup.")
    ap.add_argument("--kill", action="store_true", help="Terminate running agy.exe / language_server.exe processes before patching.")
    ap.add_argument("--backup-dir", type=Path, default=Path.home() / ".gemini" / "agy-patches", help="Directory to store original backups and manifests.")
    ap.add_argument("--json-out", type=Path, help="Optional path to write full analysis/patch report as JSON.")
    args = ap.parse_args()
    args.dry_run = args.dry_run or args.status
    if args.restore and args.dry_run:
        ap.error("--restore cannot be combined with --check/--dry-run")
    if args.db and args.conversation_id:
        ap.error("Choose --db or --conversation-id, not both")

    targets = unique_targets(args.target) if args.target else discover_default_targets()
    args.backup_dir = args.backup_dir.expanduser().resolve()
    try:
        validate_report_path(args.json_out, targets, args.backup_dir)
    except ValueError as exc:
        ap.error(str(exc))
    report = preflight(targets, args.conversation_id, args.db)
    if args.dry_run:
        if args.json_out:
            write_report(args.json_out, report)
        raise SystemExit(0 if report["compatible"] else 2)
    if not report["compatible"] and not (args.restore and targets):
        sys.exit("Preflight failed: no files modified. Specify --target to select supported backends or re-locate unsupported builds.")
    actions = targets if args.restore else [Path(b["path"]) for b in report["binaries"] if b["status"] == "UNPATCHED"]
    if not actions:
        print("All selected backends are already patched; nothing to modify.")
        if args.json_out:
            write_report(args.json_out, report)
        return
    if args.restore:
        for target in actions:
            print(f"Restore backup: {find_restore_backup(target, args.backup_dir)}")
    confirm_actions(actions, args.backup_dir, args.restore)

    if args.kill and not args.dry_run:
        print("Stopping running backend processes (agy / language_server)...")
        kill_running_backends(actions)

    wait_for_backends(actions)

    results = []
    for t in actions:
        t = t.expanduser().resolve()
        if not t.exists():
            sys.exit(f"Target does not exist: {t}")
        if args.restore:
            results.append(restore_target(t, args.backup_dir))
        else:
            res = patch_target(t, args.backup_dir, dry_run=args.dry_run)
            results.append(res)

    if args.json_out and results:
        write_report(args.json_out, results)
        print(f"\nWrote JSON report to {args.json_out}")


if __name__ == "__main__":
    main()

