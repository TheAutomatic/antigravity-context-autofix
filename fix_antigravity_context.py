#!/usr/bin/env python3
"""
Automatic Go pclntab locator and context/rules patcher for Antigravity:
- Supports Windows x86_64 PE (agy.exe for Antigravity IDE + CLI, language_server.exe for Antigravity Desktop)
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
            e_phoff, _, _, _, e_phentsize, e_phnum = struct.unpack_from("<QQQIHH", self.data, 32)
            for i in range(e_phnum):
                ph = self.data[e_phoff + i * e_phentsize : e_phoff + (i + 1) * e_phentsize]
                p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<IIQQQQQQ", ph, 0)
                if p_type == 1:  # PT_LOAD
                    is_exec = bool(p_flags & 1)
                    self.segments.append((f"LOAD_{i}", p_vaddr, max(p_memsz, p_filesz), p_offset, p_filesz, is_exec))
        else:
            raise ValueError("Unsupported binary format (neither PE nor ELF)")

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
    plan_model_off = find_ldr_imm(fbytes("GetPlanModel"), 0xFFC003FF, 0xB9400000, 4, "GetPlanModel")
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
    str_x1_x0 = 0xF9000001 | ((checkpoint_off // 8) << 10)
    for off in range(0, len(b_apply) - 3, 4):
        insn = struct.unpack_from("<I", b_apply, off)[0]
        va = f_apply["va_start"] + off
        b_to_tramp = 0x14000000 | (((tramp_va - va) >> 2) & 0x03FFFFFF)
        if insn in (str_x1_x0, b_to_tramp):
            exit_candidates.append(off)
    if len(exit_candidates) != 1:
        raise RuntimeError(f"Expected 1 exit store in ARM64 applyOverride, found {len(exit_candidates)}")
    exit_rel = exit_candidates[0]
    exit_va = f_apply["va_start"] + exit_rel
    exit_foff = f_apply["file_start"] + exit_rel

    word_diff = (tramp_va - exit_va) >> 2
    if not (-0x2000000 <= word_diff <= 0x1FFFFFF):
        raise RuntimeError("ARM64 trampoline out of 26-bit B range")

    exit_before = struct.pack("<I", str_x1_x0)
    exit_after = struct.pack("<I", 0x14000000 | (word_diff & 0x03FFFFFF))

    chk_entry_after = struct.pack("<4I", 0xD2800000, 0xD2800001, 0xD2800002, 0xD65F03C0)
    tramp_insns = [
        0xB4000141,                                              # cbz x1, .done (+40)
        0xF9400003 | ((planner_off // 8) << 10),                 # ldr x3, [x0, #planner_off]
        0xB4000103,                                              # cbz x3, .done (+32)
        0xB9400063 | ((plan_model_off // 4) << 10),              # ldr w3, [x3, #plan_model_off]
        0x51162463,                                              # sub w3, w3, #1417
        0x7100087F,                                              # cmp w3, #2
        0x54000088,                                              # b.hi .done (+16)
        0x52884803,                                              # mov w3, #0x4240
        0x72A001E3,                                              # movk w3, #0xf, lsl #16
        0xB9000023 | ((max_limit_off // 4) << 10),               # str w3, [x1, #max_limit_off]
        str_x1_x0,                                               # .done: str x1, [x0, #checkpoint_off]
        0x14000000 | ((((exit_va + 4) - (tramp_va + 44)) >> 2) & 0x03FFFFFF),  # b (exit_va + 4)
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
        status = "UNPATCHED"
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


def discover_default_targets() -> list[Path]:
    home = Path.home()
    candidates = []
    if os.name == "nt":
        candidates.append(home / ".gemini" / "bin" / "agy.exe")
        local_app = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
        candidates.append(local_app / "Programs" / "antigravity" / "resources" / "bin" / "language_server.exe")
    else:
        candidates.append(home / ".local" / "bin" / "agy")
        candidates.append(home / ".gemini" / "bin" / "agy")
    return [c for c in candidates if c.exists()]


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
    if backup_file.exists():
        bak_sha = hashlib.sha256(backup_file.read_bytes()).hexdigest()
        if bak_sha != info["sha256"]:
            raise RuntimeError(f"Backup file {backup_file} exists with different SHA256!")
    else:
        backup_file.write_bytes(raw_bytes)
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
    patched_sha256 = hashlib.sha256(out).hexdigest()
    info["patched_sha256"] = patched_sha256
    info["backup_path"] = str(backup_file)
    info["version"] = ver

    manifest_file = backup_dir / f"{target.name}-{ver}-manifest-{info['sha256'][:16]}.json"
    manifest_file.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")

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
        os.replace(tmp_path, target)
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
    print(f"  [patched] Successfully patched {target}")
    print(f"  [patched] New SHA256: {patched_sha256}")
    print(f"  [manifest] Saved to {manifest_file}")
    return info


def restore_target(target: Path, backup_dir: Path):
    info = analyze_binary(target)
    print(f"\nTarget : {info['path']} (Status: {info['status']}, SHA256: {info['sha256']})")
    for mf in sorted(backup_dir.glob(f"{target.name}-*-manifest-*.json"), reverse=True):
        mdata = json.loads(mf.read_text(encoding="utf-8"))
        if mdata.get("patched_sha256") == info["sha256"] or mdata.get("sha256") == info["sha256"]:
            bak = Path(mdata["backup_path"])
            if bak.exists():
                bak_bytes = bak.read_bytes()
                assert hashlib.sha256(bak_bytes).hexdigest() == mdata["sha256"]
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
                    os.replace(tmp_p, target)
                finally:
                    if tmp_p.exists():
                        try:
                            tmp_p.unlink()
                        except Exception:
                            pass
                update_agy_sidecar_if_present(target)
                print(f"  [restored] Restored original {mdata['sha256']} from {bak}")
                return
    raise RuntimeError(f"No matching backup/manifest found in {backup_dir} for {target}")


def kill_running_backends():
    if os.name == "nt":
        for proc in ("agy.exe", "language_server.exe"):
            subprocess.run(["taskkill", "/F", "/IM", proc], capture_output=True)
        time.sleep(1.0)
    else:
        subprocess.run(["pkill", "-f", "agy"], capture_output=True)
        time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser(description="Auto-locate (via Go pclntab) and patch Antigravity 1M context & rules budgets.")
    ap.add_argument("--target", type=Path, action="append", help="Path to agy / language_server binary (repeatable). Defaults to auto-discovered installations.")
    ap.add_argument("--check", "--dry-run", dest="dry_run", action="store_true", help="Read-only check: locate symbols, verify patterns, and print patch plan without modifying files.")
    ap.add_argument("--restore", action="store_true", help="Restore original unpatched binary from backup.")
    ap.add_argument("--kill", action="store_true", help="Terminate running agy.exe / language_server.exe processes before patching.")
    ap.add_argument("--backup-dir", type=Path, default=Path.home() / ".gemini" / "agy-patches", help="Directory to store original backups and manifests.")
    ap.add_argument("--json-out", type=Path, help="Optional path to write full analysis/patch report as JSON.")
    args = ap.parse_args()

    targets = args.target if args.target else discover_default_targets()
    if not targets:
        sys.exit("No Antigravity binary found automatically. Specify --target <path>.")

    if args.kill and not args.dry_run:
        print("Stopping running backend processes (agy / language_server)...")
        kill_running_backends()

    results = []
    for t in targets:
        t = t.expanduser().resolve()
        if not t.exists():
            sys.exit(f"Target does not exist: {t}")
        if args.restore:
            restore_target(t, args.backup_dir)
        else:
            res = patch_target(t, args.backup_dir, dry_run=args.dry_run)
            results.append(res)

    if args.json_out and results:
        args.json_out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote JSON report to {args.json_out}")


if __name__ == "__main__":
    main()

