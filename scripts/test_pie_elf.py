"""Synthetic PIE ELF fixtures for the .rela.dyn text-base resolution path.

On PIE (ET_DYN) Go builds moduledata.text/etext are zero in the file; only the
R_*_RELATIVE addends carry the link-time VAs. These tests build a minimal but
structurally valid ELF + pclntab so the relocation fallback is covered without
shipping a proprietary binary.
"""
import struct
import unittest

import fix_antigravity_context as f


def _build_pie_elf(*, machine=62, text=0x1000, total_len=0x8000,
                   with_pcheader=True, extra_pair=False, ambiguous=False):
    """Return (elf_bytes, expected_text_va).

    Layout (file offsets == VAs, single RWX PT_LOAD at 0):
      0x0000 ELF header + 1 program header
      0x0100 section headers (null, .rela.dyn, .shstrtab)
      0x0200 .shstrtab
      0x0300 .rela.dyn
      0x1000 text (executable region; content irrelevant)
      0x9000 pclntab (magic, header, ftab, funcnametab, one _func)
    moduledata lives in the data region; its pointer slots are zero in-file and
    described purely by relocations, exactly like a real PIE build.
    """
    size = 0x20000
    data = bytearray(size)
    # ELF header
    data[:16] = bytes.fromhex('7f454c46020101000000000000000000')
    e_shoff = 0x100
    struct.pack_into('<HHIQQQIHHHHHH', data, 16,
                     3, machine, 1, 0, 64, e_shoff, 0, 64, 56, 1, 64, 3, 2)
    # PT_LOAD covering the whole file, RWX so text VAs count as executable
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 7, 0, 0, 0, size, size, 0x1000)

    # pclntab
    pcln = 0x9000
    magic = b'\xf1\xff\xff\xff\x00\x00\x01\x08' if machine == 62 else b'\xf1\xff\xff\xff\x00\x00\x04\x08'
    data[pcln:pcln + 8] = magic
    nfunc = 1001
    funcname_off = 0x6000
    cu_off = 0x7000
    pcln_off = 0x100
    # header: nfunc, nfiles, textStart(0 for PIE), funcname, cu, filetab, pctab, pcln
    struct.pack_into('<8Q', data, pcln + 8,
                     nfunc, 1, 0, funcname_off, cu_off, 0, 0, pcln_off)
    ftab = pcln + pcln_off
    # ftab entries: (func_off_in_text, funcrec_off). Make total_len = etext-text.
    for i in range(nfunc):
        struct.pack_into('<II', data, ftab + i * 8, i * 8, 0x8000 + i * 16)
    struct.pack_into('<I', data, ftab + nfunc * 8, total_len)
    # funcrec for every function so name lookup resolves all 9 targets
    names = pcln + funcname_off
    cursor = names + 1
    for idx, sym in enumerate(f.TARGET_FUNCS.values()):
        name_off = cursor - names
        data[cursor:cursor + len(sym) + 1] = sym.encode() + b'\x00'
        cursor += len(sym) + 1
        rec = ftab + 0x8000 + idx * 16
        struct.pack_into('<I', data, rec, idx * 8)
        struct.pack_into('<i', data, rec + 4, name_off)

    # relocations
    rel_off = 0x300
    rel_type = 8 if machine == 62 else 1027
    md_text_slot = 0xC000
    rels = []
    if with_pcheader:
        rels.append((md_text_slot - 160, pcln))  # moduledata.pcHeader -> pclntab
    rels.append((md_text_slot, text))
    rels.append((md_text_slot + 8, text + total_len))
    if extra_pair:
        # a second valid pair WITHOUT a pcHeader cross-check
        rels.append((0xC800, text))
        rels.append((0xC808, text + total_len))
    if ambiguous:
        # a second pair WITH its own pcHeader -> two strong hits, must refuse
        rels.append((0xC800 - 160, pcln))
        rels.append((0xC800, text + 0x100))
        rels.append((0xC808, text + 0x100 + total_len))
    for i, (slot, addend) in enumerate(rels):
        struct.pack_into('<QQq', data, rel_off + i * 24, slot, rel_type, addend)
    rel_size = len(rels) * 24

    # section headers: null, .rela.dyn, .shstrtab
    shstr = 0x200
    names_blob = b'\x00.rela.dyn\x00.shstrtab\x00'
    data[shstr:shstr + len(names_blob)] = names_blob
    rela_name = 1
    shstr_name = 11
    struct.pack_into('<IIQQQQIIQQ', data, e_shoff + 64,
                     rela_name, 4, 0, 0, rel_off, rel_size, 0, 0, 8, 24)
    struct.pack_into('<IIQQQQIIQQ', data, e_shoff + 128,
                     shstr_name, 3, 0, 0, shstr, len(names_blob), 0, 0, 1, 0)
    return bytes(data), text


class PieElfTextBaseTests(unittest.TestCase):
    def test_pie_text_base_from_relocations_x86_64(self):
        elf, text = _build_pie_elf(machine=62)
        img = f.BinaryImage(elf)
        self.assertEqual(img.fmt, 'ELF')
        self.assertIn('.rela.dyn', img.sections)
        _, go_text_va, funcs, _ = f.locate_go_functions(img)
        self.assertEqual(go_text_va, text)
        self.assertIn('GetMaxTokenLimit', funcs)

    def test_pie_text_base_from_relocations_arm64(self):
        elf, text = _build_pie_elf(machine=183)
        img = f.BinaryImage(elf)
        _, go_text_va, _, _ = f.locate_go_functions(img)
        self.assertEqual(go_text_va, text)

    def test_pie_refuses_ambiguous_strong_candidates(self):
        elf, _ = _build_pie_elf(ambiguous=True)
        img = f.BinaryImage(elf)
        with self.assertRaises(RuntimeError):
            f.locate_go_functions(img)

    def test_pie_unique_weak_pair_still_resolves(self):
        # extra_pair adds a second pair, but only one has the pcHeader
        # cross-check, so the strong hit wins.
        elf, text = _build_pie_elf(extra_pair=True)
        img = f.BinaryImage(elf)
        _, go_text_va, _, _ = f.locate_go_functions(img)
        self.assertEqual(go_text_va, text)


if __name__ == '__main__':
    unittest.main()
