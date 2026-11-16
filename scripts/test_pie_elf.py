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
                   with_pcheader=True, extra_pair=False, ambiguous=False,
                   ambiguous_weak=False, pad_relocations=0, use_pt_dynamic=False,
                   extra_rels=(), raw_data_trap=None, rela_in_load=True):
    """Return (elf_bytes, expected_text_va).

    Layout (file offsets == VAs):
      0x0000 ELF header + program headers
      0x0180 section headers (null, .rela.dyn, .shstrtab) unless stripped
      0x0280 .shstrtab + optional PT_DYNAMIC table
      0x1000 text (executable region; content irrelevant)
      0x9000 pclntab (magic, header, ftab, funcnametab, _func records)
      0x19000 non-exec data segment (optional raw_data_trap)
      0x20000 .rela.dyn (supports >64 KiB tables)
    """
    rel_off = 0x20000
    rel_type = 8 if machine == 62 else 1027
    md_text_slot = 0xC000
    rels = []
    for slot, addend in extra_rels:
        rels.append((slot, addend))
    for i in range(pad_relocations):
        rels.append((0xD0000 + i * 8, 0x500 + (i % 64)))
    if with_pcheader:
        rels.append((md_text_slot - 160, 0x9000))  # moduledata.pcHeader -> pclntab
    rels.append((md_text_slot, text))
    rels.append((md_text_slot + 8, text + total_len))
    if extra_pair:
        # a second valid pair WITHOUT a pcHeader cross-check
        rels.append((0xC800, text))
        rels.append((0xC808, text + total_len))
    if ambiguous_weak:
        rels.append((0xC800, text + 0x100))
        rels.append((0xC808, text + 0x100 + total_len))
    if ambiguous:
        # a second pair WITH its own pcHeader -> two strong hits, must refuse
        rels.append((0xC800 - 160, 0x9000))
        rels.append((0xC800, text + 0x100))
        rels.append((0xC808, text + 0x100 + total_len))
    rel_size = len(rels) * 24

    load0_end = (rel_off + rel_size + 0xFFF) & ~0xFFF if rela_in_load else 0x19000
    size = max(load0_end, rel_off + rel_size + 0x100)
    data = bytearray(size)

    # ELF header
    data[:16] = bytes.fromhex('7f454c46020101000000000000000000')
    e_shoff = 0 if use_pt_dynamic else 0x180
    shnum = 0 if use_pt_dynamic else 3
    shstrndx = 0 if use_pt_dynamic else 2
    phnum = 3 if use_pt_dynamic else 2
    struct.pack_into('<HHIQQQIHHHHHH', data, 16,
                     3, machine, 1, 0, 64, e_shoff, 0, 64, 56, phnum, 64, shnum, shstrndx)
    # PT_LOAD 0: RX covering headers, text, pclntab (and optionally .rela.dyn)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, load0_end, load0_end, 0x1000)
    # PT_LOAD 1: RW non-executable data segment at 0x19000..0x20000
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 6, 0x19000, 0x19000, 0x19000, 0x7000, 0x7000, 0x1000)
    if raw_data_trap is not None:
        trap_va = raw_data_trap
        struct.pack_into('<QQ', data, 0x19100, trap_va, trap_va + total_len)

    if use_pt_dynamic:
        dyn_off = 0x280
        dyn_entries = [
            (7, rel_off),   # DT_RELA
            (8, rel_size),  # DT_RELASZ
            (9, 24),        # DT_RELAENT
            (0, 0),         # DT_NULL
        ]
        for idx, (d_tag, d_val) in enumerate(dyn_entries):
            struct.pack_into('<qQ', data, dyn_off + idx * 16, d_tag, d_val)
        dyn_size = len(dyn_entries) * 16
        struct.pack_into('<IIQQQQQQ', data, 176, 2, 4, dyn_off, dyn_off, dyn_off, dyn_size, dyn_size, 8)

    # pclntab
    pcln = 0x9000
    magic = b'\xf1\xff\xff\xff\x00\x00\x01\x08' if machine == 62 else b'\xf1\xff\xff\xff\x00\x00\x04\x08'
    data[pcln:pcln + 8] = magic
    nfunc = 1001
    funcname_off = 0x6000
    cu_off = 0x7000
    pcln_off = 0x100
    struct.pack_into('<8Q', data, pcln + 8,
                     nfunc, 1, 0, funcname_off, cu_off, 0, 0, pcln_off)
    ftab = pcln + pcln_off
    for i in range(nfunc):
        struct.pack_into('<II', data, ftab + i * 8, i * 8, 0x8000 + i * 16)
    struct.pack_into('<I', data, ftab + nfunc * 8, total_len)
    names = pcln + funcname_off
    cursor = names + 1
    for idx, sym in enumerate(f.TARGET_FUNCS.values()):
        name_off = cursor - names
        data[cursor:cursor + len(sym) + 1] = sym.encode() + b'\x00'
        cursor += len(sym) + 1
        rec = ftab + 0x8000 + idx * 16
        struct.pack_into('<I', data, rec, idx * 8)
        struct.pack_into('<i', data, rec + 4, name_off)

    for i, (slot, addend) in enumerate(rels):
        struct.pack_into('<QQq', data, rel_off + i * 24, slot, rel_type, addend)

    if not use_pt_dynamic:
        shstr = 0x280
        names_blob = b'\x00.rela.dyn\x00.shstrtab\x00'
        data[shstr:shstr + len(names_blob)] = names_blob
        struct.pack_into('<IIQQQQIIQQ', data, e_shoff + 64,
                         1, 4, 0, 0, rel_off, rel_size, 0, 0, 8, 24)
        struct.pack_into('<IIQQQQIIQQ', data, e_shoff + 128,
                         11, 3, 0, 0, shstr, len(names_blob), 0, 0, 1, 0)
    return bytes(data), text


class PieElfTextBaseTests(unittest.TestCase):
    def test_pie_text_base_from_relocations_x86_64(self):
        elf, text = _build_pie_elf(machine=62)
        img = f.BinaryImage(elf)
        self.assertEqual(img.fmt, 'ELF')
        self.assertTrue(img.is_pie)
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

    def test_pie_weak_only_resolves_and_refuses_ambiguous_weak(self):
        elf, text = _build_pie_elf(with_pcheader=False)
        img = f.BinaryImage(elf)
        _, go_text_va, _, _ = f.locate_go_functions(img)
        self.assertEqual(go_text_va, text)

        amb_elf, _ = _build_pie_elf(with_pcheader=False, ambiguous_weak=True)
        with self.assertRaises(RuntimeError):
            f.locate_go_functions(f.BinaryImage(amb_elf))

    def test_pie_ignores_coincidental_raw_minpc_maxpc_pair_in_data(self):
        # A coincidental (X, X + total_len) pair in a non-exec data segment must
        # never hijack go_text_va ahead of verified .rela.dyn entries on PIE ELF.
        elf, text = _build_pie_elf(raw_data_trap=0x1400)
        img = f.BinaryImage(elf)
        _, go_text_va, _, _ = f.locate_go_functions(img)
        self.assertEqual(go_text_va, text)

    def test_pie_large_rela_fast_path_and_ambiguity(self):
        elf, text = _build_pie_elf(pad_relocations=3000)
        img = f.BinaryImage(elf)
        self.assertGreater(sum(sz for _, sz in img.rela_ranges), 65536)
        _, go_text_va, _, _ = f.locate_go_functions(img)
        self.assertEqual(go_text_va, text)

        amb_elf, _ = _build_pie_elf(pad_relocations=3000, ambiguous=True)
        with self.assertRaises(RuntimeError):
            f.locate_go_functions(f.BinaryImage(amb_elf))

    def test_pie_pt_dynamic_fallback_when_section_headers_stripped(self):
        elf, text = _build_pie_elf(use_pt_dynamic=True, extra_rels=((0x19200, 0x2340),))
        img = f.BinaryImage(elf)
        self.assertEqual(img.sections, {})
        self.assertEqual(len(img.rela_ranges), 1)
        _, go_text_va, _, _ = f.locate_go_functions(img)
        self.assertEqual(go_text_va, text)
        self.assertTrue(f.stored_address_present(img, 0x2340))

    def test_malformed_section_headers_are_ignored_safely(self):
        elf, _ = _build_pie_elf()
        corrupt = bytearray(elf)
        # Set .rela.dyn s_size way past EOF and .shstrtab size past EOF
        struct.pack_into('<Q', corrupt, 0x180 + 64 + 32, len(corrupt) * 4)
        struct.pack_into('<Q', corrupt, 0x180 + 128 + 32, len(corrupt) * 4)
        img = f.BinaryImage(bytes(corrupt))
        self.assertEqual(img.rela_ranges, [])

    def test_stored_address_present_checks_rela_addends_without_unaligned_false_positives(self):
        # 1) .rela.dyn outside PT_LOAD: function pointer is 0 in data, carried only by r_addend.
        elf_unmapped_rela, _ = _build_pie_elf(
            rela_in_load=False,
            extra_rels=((0x19300, 0x3456),),
        )
        img_unmapped = f.BinaryImage(elf_unmapped_rela)
        self.assertTrue(f.stored_address_present(img_unmapped, 0x3456))
        self.assertFalse(f.stored_address_present(img_unmapped, 0x3458))

        # 2) Unaligned 8-byte windows straddling (r_offset, r_info=8) inside .rela.dyn
        # (mapped in PT_LOAD 0) must NOT falsely trigger stored_address_present.
        unaligned_va = 0x0000000800001234  # bytes [4..12] of r_offset=0x123400019500, r_info=8
        elf_in_load, _ = _build_pie_elf(
            rela_in_load=True,
            extra_rels=((0x123400019500, 0x2222),),
        )
        img_in_load = f.BinaryImage(elf_in_load)
        self.assertEqual(img_in_load.data.count(struct.pack('<Q', unaligned_va)), 1)
        self.assertFalse(f.stored_address_present(img_in_load, unaligned_va))

        with_real_ptr = bytearray(elf_in_load)
        struct.pack_into('<Q', with_real_ptr, 0x19400, unaligned_va)
        self.assertTrue(f.stored_address_present(f.BinaryImage(bytes(with_real_ptr)), unaligned_va))


if __name__ == '__main__':
    unittest.main()
