import hashlib
import json
import io
import contextlib
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import patch

import fix_antigravity_context as f
import verify_session as v
from test_status import field, varint


class _FakeImage:
    """Minimal BinaryImage stand-in for synthetic instruction encodings."""

    def __init__(self, arch, data, segments):
        self.arch, self.data, self.segments = arch, data, segments

    def va_to_file(self, va):
        for _, sva, _, raw_ptr, raw_size, _ in self.segments:
            if sva <= va < sva + raw_size:
                return raw_ptr + (va - sva)
        raise ValueError(f"unmapped VA {hex(va)}")

class RegressionTests(unittest.TestCase):
    def test_inplace_replacement_restores_target_on_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target, source = root / 'agy', root / 'patched'
            target.write_bytes(b'original-bytes')
            source.write_bytes(b'patched-bytes')
            rollback = target.read_bytes()
            real_write = f._overwrite_file
            calls = []

            def flaky(dest, payload):
                calls.append(payload)
                if len(calls) == 1:
                    dest.write_bytes(b'truncated')
                    raise OSError(28, 'No space left on device')
                real_write(dest, payload)

            with patch.object(f, '_overwrite_file', side_effect=flaky):
                with self.assertRaises(OSError):
                    f.overwrite_in_place(source, target, rollback)
            self.assertEqual(target.read_bytes(), b'original-bytes')
            self.assertTrue(source.exists())

            f.overwrite_in_place(source, target, rollback)
            self.assertEqual(target.read_bytes(), b'patched-bytes')
            self.assertFalse(source.exists())

    def test_upgrade_rollback_restores_pre_upgrade_binary(self):
        class WinError6(OSError):
            winerror = 6

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target, backup_dir = root / 'agy.exe', root / 'backups'
            backup_dir.mkdir()
            current = b'legacy-patched-bytes'
            original = b'pristine-bytes-longer'
            bak = backup_dir / 'agy.exe-unknown-original-0000000000000000.bak'
            bak.write_bytes(original)
            target.write_bytes(current)
            plan = {
                'path': str(target), 'format': 'PE', 'arch': 'x86_64', 'size': len(original),
                'sha256': hashlib.sha256(original).hexdigest(),
                'pclntab_offset': '0x0', 'go_text_va': '0x0', 'status': 'UNPATCHED',
                'field_offsets': {}, 'functions': {},
                'changes': [{'name': 'x', 'purpose': 'test', 'va': '0x0', 'offset': '0x0',
                             'before': '70', 'after': '58', 'fixed_before': True}],
                'target_disk_sha256': hashlib.sha256(current).hexdigest(),
                'upgrade_from_backup': str(bak),
            }
            real_write = f._overwrite_file
            writes = []

            def flaky(dest, payload):
                writes.append(payload)
                if len(writes) == 1:
                    dest.write_bytes(b'partial')
                    raise OSError(28, 'No space left on device')
                real_write(dest, payload)

            with patch.object(f, 'analyze_binary', return_value=plan), \
                 patch.object(f, 'wait_for_backends'), \
                 patch.object(f, 'is_windows', return_value=True), \
                 patch.object(f, '_replace_atomic', side_effect=WinError6(6, 'invalid handle')), \
                 patch.object(f, '_overwrite_file', side_effect=flaky), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError):
                    f.patch_target(target, backup_dir)
            # An interrupted upgrade must leave the installed patched build in place,
            # not silently roll back to the pristine original.
            self.assertEqual(target.read_bytes(), current)
            self.assertTrue(writes)
            self.assertEqual(writes[-1], current)

    def test_replace_refuses_truncating_write_without_rollback(self):
        class WinError6(OSError):
            winerror = 6

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target, source = root / 'agy', root / 'patched'
            target.write_bytes(b'original')
            source.write_bytes(b'patched')
            with patch.object(f, 'wait_for_backends'), \
                 patch.object(f, 'is_windows', return_value=True), \
                 patch.object(f, '_replace_atomic', side_effect=WinError6(6, 'invalid handle')):
                with self.assertRaises(RuntimeError):
                    f.replace_with_retry(source, target, hashlib.sha256(b'original').hexdigest())
            self.assertEqual(target.read_bytes(), b'original')

    def test_host_reference_scan_sees_tail_jumps_and_ignores_self_branches(self):
        # A is smaller, so it is considered first; a tail jump from elsewhere must
        # disqualify it even though its body is never CALLed. B is only reached by a
        # jump from inside itself, which leaves it usable.
        def build(arch):
            text_va, text_off, size = 0x1000, 0x400, 0x400
            data = bytearray(0x1000)
            a_va, b_va = 0x1100, 0x1190
            if arch == 'x86_64':
                data[text_off + 0x20] = 0xE9                       # jmp A from outside
                struct.pack_into('<i', data, text_off + 0x21, a_va - (text_va + 0x20 + 5))
                data[text_off + 0x1A0] = 0xE9                      # jmp B from inside B
                struct.pack_into('<i', data, text_off + 0x1A1, b_va - (text_va + 0x1A0 + 5))
            else:
                struct.pack_into('<I', data, text_off + 0x20,
                                 0x14000000 | (((a_va - (text_va + 0x20)) >> 2) & 0x03FFFFFF))
                struct.pack_into('<I', data, text_off + 0x1A0,
                                 0x14000000 | (((b_va - (text_va + 0x1A0)) >> 2) & 0x03FFFFFF))
            return _FakeImage(arch, bytes(data),
                              [('__TEXT', text_va, size, text_off, size, True)])

        for arch in ('x86_64', 'arm64'):
            with self.subTest(arch=arch):
                img = build(arch)
                hosts = {'google3/x.(*CheckpointConfig).SetA': (0x100, 0x190),
                         'google3/x.(*CheckpointConfig).SetB': (0x190, 0x290)}
                chosen, _ = f.choose_trampoline_host(img, {}, hosts, 0x1000)
                self.assertEqual(chosen['symbol'], 'google3/x.(*CheckpointConfig).SetB')
                self.assertEqual(chosen['va_start'], 0x1190)

    def test_arm64_prologue_layouts_are_recognised(self):
        # Real encodings: SP is only addressable in the extended-register form, so
        # CMP SP, X16 is 0xEB3063FF, not the shifted-form 0xEB1003FF.
        def branch(at, target):
            return 0x54000009 | ((((target - at) >> 2) & 0x7FFFF) << 5)

        def image(words):
            code = struct.pack(f"<{len(words)}I", *words) + b"\x1f\x20\x03\xd5" * 32
            func = {'symbol': 'x', 'va_start': 0x1000, 'va_end': 0x1000 + len(code),
                    'file_start': 0, 'file_end': len(code)}
            return _FakeImage('arm64', code, [('__TEXT', 0x1000, len(code), 0, len(code), True)]), func, len(code)

        for words, prologue_words in (([0xF9400B90, 0xD10003F1, 0xEB10023F, branch(12, 0x40)], 3),
                                      ([0xF9400B90, 0xEB3063FF, branch(8, 0x40)], 2),
                                      ([0xF9400B90, 0xEB3063FF, branch(8, 0x40), 0xD503201F], 2)):
            img, func, size = image(words)
            self.assertTrue(f.valid_checkpoint_entry(img, func), [hex(w) for w in words])
            for i in range(prologue_words + 1):
                tampered = list(words)
                tampered[i] = 0xD503201F
                img_bad, func_bad, _ = image(tampered)
                self.assertFalse(f.valid_checkpoint_entry(img_bad, func_bad), i)
            # A NOP past the validated prologue is caught by the entry scan.
            self.assertEqual(f.entry_has_nop_fill('arm64', words and struct.pack(f"<{len(words)}I", *words)),
                             words[-1] == 0xD503201F)

        # B.cond is relative to the branch itself: a self loop is refused, and a
        # jump to the last instruction is accepted.
        self.assertFalse(f.valid_checkpoint_entry(*image([0xF9400B90, 0xEB3063FF, branch(8, 8)])[:2]))
        last = image([0xF9400B90, 0xEB3063FF, branch(8, 8)])[2] - 4
        self.assertTrue(f.valid_checkpoint_entry(*image([0xF9400B90, 0xEB3063FF, branch(8, last)])[:2]))

    def test_subs_zero_accepts_extended_and_shifted_forms(self):
        self.assertTrue(f.is_subs_zero(0xEB3063FF))   # SUBS XZR, SP, X16 (extended)
        self.assertTrue(f.is_subs_zero(0xEB1003FF))   # SUBS XZR, SP, X16 (shifted)
        self.assertTrue(f.is_subs_zero(0xEB10023F))   # SUBS XZR, X17, X16
        self.assertFalse(f.is_subs_zero(0xD10003F1))  # SUB X17, SP, #frame
        self.assertFalse(f.is_subs_zero(0xEB10023E))  # Rd is X30, not XZR

    def test_recorded_hash_role_skips_non_object_manifests(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'agy.exe-1-manifest-a.json').write_text('[]')
            (root / 'agy.exe-2-manifest-b.json').write_text('null')
            (root / 'agy.exe-3-manifest-c.json').write_text('3')
            self.assertIsNone(f.recorded_hash_role(root / 'agy.exe', 'deadbeef', root))
            (root / 'agy.exe-4-manifest-d.json').write_text(json.dumps({'sha256': 'deadbeef'}))
            self.assertEqual(f.recorded_hash_role(root / 'agy.exe', 'deadbeef', root), 'original')

    def test_nop_fill_in_entry_counts_as_rewritten(self):
        self.assertTrue(f.entry_has_nop_fill('arm64', bytes.fromhex('1f2003d5')))
        self.assertFalse(f.entry_has_nop_fill('arm64', bytes.fromhex('900bf940')))
        self.assertTrue(f.entry_has_nop_fill('x86_64', bytes.fromhex('493b66109090')))
        self.assertFalse(f.entry_has_nop_fill('x86_64', bytes.fromhex('493b66100f86')))

    def test_host_reference_scan_sees_backward_branches(self):
        text_va, text_off, size = 0x1000, 0x400, 0x400
        target_va = 0x1100
        for encodings in (('B', 0x14000000), ('BL', 0x94000000)):
            name, opcode = encodings
            with self.subTest(kind=name):
                # Branch placed after the target, so the displacement is negative.
                for site_offset in (0x300, 0x200):
                    data = bytearray(0x1000)
                    site_va = text_va + site_offset
                    imm = (target_va - site_va) >> 2
                    self.assertLess(imm, 0)
                    struct.pack_into('<I', data, text_off + site_offset, opcode | (imm & 0x03FFFFFF))
                    img = _FakeImage('arm64', bytes(data),
                                     [('__TEXT', text_va, size, text_off, size, True)])
                    refs = f.collect_text_references(img, text_va, {target_va})
                    self.assertEqual(refs.get(target_va), [site_va])

    def test_host_reference_scan_ignores_debug_addresses_but_not_data(self):
        text_va, text_off, size = 0x1000, 0x400, 0x400
        func_va = 0x1100
        hosts = {'google3/x.(*CheckpointConfig).SetA': (0x100, 0x200)}
        stored = struct.pack('<Q', func_va)

        debugging = bytearray(0x1000)
        debugging[0x800:0x808] = stored
        img = _FakeImage('x86_64', bytes(debugging),
                         [('__TEXT', text_va, size, text_off, size, True),
                          ('__DWARF', 0x2000, 0x100, 0x800, 0x100, False)])
        self.assertEqual(f.choose_trampoline_host(img, {}, hosts, text_va)[0]['va_start'], func_va)

        data = bytearray(debugging)
        data[0x900:0x908] = stored
        img = _FakeImage('x86_64', bytes(data),
                         [('__TEXT', text_va, size, text_off, size, True),
                          ('__DWARF', 0x2000, 0x100, 0x800, 0x100, False),
                          ('__DATA', 0x2100, 0x100, 0x900, 0x100, False)])
        with self.assertRaises(RuntimeError):
            f.choose_trampoline_host(img, {}, hosts, text_va)

        # An executable segment also carries constants and pointers, so a stored
        # VA inside __TEXT still counts as an indirect reference.
        data = bytearray(debugging)
        data[0x780:0x788] = stored
        img = _FakeImage('x86_64', bytes(data),
                         [('__TEXT', text_va, size, text_off, size, True)])
        with self.assertRaises(RuntimeError):
            f.choose_trampoline_host(img, {}, hosts, text_va)

    @unittest.skipUnless(os.environ.get('AGY_TEST_BINARY'), 'provide an original binary fixture')
    def test_trampoline_host_falls_back_when_preferred_symbols_are_absent(self):
        source = Path(os.environ['AGY_TEST_BINARY'])
        img = f.BinaryImage(source.read_bytes())
        _, text_va, funcs, hosts = f.locate_go_functions(img)
        chosen, ambiguous = f.choose_trampoline_host(img, funcs, hosts, text_va)
        self.assertIn(chosen['symbol'], hosts)
        self.assertGreaterEqual(chosen['file_end'] - chosen['file_start'], f.HOST_SPAN[img.arch])
        if any(n.endswith(f.HOST_PREFERENCE[0]) for n in hosts):
            self.assertTrue(chosen['symbol'].endswith(f.HOST_PREFERENCE[0]))
        reduced = {n: v for n, v in hosts.items() if not n.endswith(f.HOST_PREFERENCE)}
        fallback, _ = f.choose_trampoline_host(img, funcs, reduced, text_va)
        self.assertIn(fallback['symbol'], reduced)
        self.assertGreaterEqual(fallback['file_end'] - fallback['file_start'], f.HOST_SPAN[img.arch])
        # Builds without any CheckpointConfig method must fail, never fall back to
        # hooks.checkpointNeeded, which hosts native auto-compaction.
        with self.assertRaises(RuntimeError):
            f.choose_trampoline_host(img, funcs, {}, text_va)

    def test_backup_sync_uses_writable_handle_without_changing_contents(self):
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                target = root / 'agy'
                original = b'original fixture'
                target.write_bytes(original)
                digest = hashlib.sha256(original).hexdigest()
                backup = root / f'agy-test-original-{digest[:16]}.bak'
                if existing:
                    backup.write_bytes(original)
                info = {'path': str(target), 'format': 'PE', 'arch': 'x86_64',
                        'size': len(original), 'sha256': digest, 'pclntab_offset': '0x0',
                        'go_text_va': '0x0', 'field_offsets': {}, 'status': 'UNPATCHED', 'changes': []}
                def require_writable(fd):
                    # Windows rejects syncing read-only handles. A zero-byte write
                    # enforces that requirement here without modifying the file.
                    os.write(fd, b'')
                with patch.object(f, 'analyze_binary', return_value=info), \
                     patch.object(f, 'get_binary_version', return_value='test'), \
                     patch.object(f.os, 'fsync', side_effect=require_writable) as sync, \
                     patch.object(f, 'sync_directory', side_effect=RuntimeError('stop after backup')), \
                     contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, 'stop after backup'):
                        f.patch_target(target, root)
                sync.assert_called_once()
                self.assertEqual(backup.read_bytes(), original)
                self.assertEqual(target.read_bytes(), original)

    def test_restore_unrecognized_binary_through_cli(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target, backup = root / 'agy', root / 'original.bak'
            target.write_bytes(b'unrecognized patched build')
            backup.write_bytes(b'original build')
            manifest = {'sha256': hashlib.sha256(backup.read_bytes()).hexdigest(),
                        'patched_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                        'backup_path': str(backup)}
            f.write_manifest(root / 'agy-old-manifest-valid.json', manifest)
            with patch('sys.argv', ['fix', '--restore', '--target', str(target), '--backup-dir', str(root)]), \
                 patch('builtins.input', return_value='Y'), \
                 patch.object(f, 'running_backends', return_value=[]), contextlib.redirect_stdout(io.StringIO()):
                f.main()
            self.assertEqual(target.read_bytes(), backup.read_bytes())
            target.write_bytes(b'changed after patch')
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
                f.restore_target(target, root)
            self.assertEqual(target.read_bytes(), b'changed after patch')

    def test_restore_skips_invalid_manifests(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target, backup = root / 'agy', root / 'original.bak'
            target.write_bytes(b'patched')
            backup.write_bytes(b'original')
            manifest = {'sha256': hashlib.sha256(b'original').hexdigest(),
                        'patched_sha256': hashlib.sha256(b'patched').hexdigest(),
                        'backup_path': str(backup)}
            valid = root / 'agy-0-manifest-valid.json'
            f.write_manifest(valid, manifest)
            invalid = ['{', '[]', '{}', json.dumps(dict(manifest, sha256='bad')),
                       json.dumps(dict(manifest, backup_path=str(root / 'missing'))),
                       json.dumps(dict(manifest, backup_path=str(target))),
                       json.dumps(dict(manifest, backup_path=None))]
            for index, contents in enumerate(invalid):
                (root / f'agy-9{index}-manifest-invalid.json').write_text(contents)
            (root / 'agy-99-manifest-encoding.json').write_bytes(b'\xff')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(f.find_restore_backup(target, root), backup)
                self.assertEqual(f.select_restore_backup(target, root), (valid, manifest, backup))
            self.assertIn('backup warning', output.getvalue())
            backup.write_bytes(b'corrupted')
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
                f.find_restore_backup(target, root)

    def test_manifest_failure_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = root / 'manifest.json'
            manifest.write_text('previous')
            with patch.object(f.os, 'replace', side_effect=OSError('replace failed')):
                with self.assertRaises(OSError):
                    f.write_manifest(manifest, {'sha256': 'new'})
            self.assertEqual(manifest.read_text(), 'previous')
            self.assertEqual(list(root.iterdir()), [manifest])

    def test_malformed_protobuf_is_rejected(self):
        chat = field(9, field(10, field(4, 983040)))
        malformed = (varint(10) + varint(len(chat) + 1000) + chat,
                     field(1, chat) + bytes([0x12, 0x80]),
                     field(1, chat) + bytes([0x19, 0x00]),
                     field(1, chat) + bytes([0]),
                     field(1, field(9, field(10, field(4, b'wrong wire')))))
        for data in malformed:
            with self.subTest(data=data), self.assertRaises(ValueError):
                v.parse_gen_row(data)
        for data in (bytes([0x80]), bytes([0xff]) * 10, bytes([0x80]) * 10 + bytes([0])):
            with self.assertRaises(ValueError):
                v.read_varint(data, 0)

    def test_restore_cli_writes_result_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'agy'
            target.write_bytes(b'fixture')
            output = root / 'restore.json'
            result = {'operation': 'restore', 'status': 'RESTORED',
                      'before_sha256': 'before', 'restored_sha256': 'after',
                      'backup_path': str(root / 'original.bak')}
            with patch('sys.argv', ['fix', '--restore', '--target', str(target), '--json-out', str(output)]), \
                 patch.object(f, 'preflight', return_value={'compatible': True}), \
                 patch.object(f, 'find_restore_backup', return_value=root / 'original.bak'), \
                 patch.object(f, 'confirm_actions'), patch.object(f, 'wait_for_backends'), \
                 patch.object(f, 'restore_target', return_value=result), contextlib.redirect_stdout(io.StringIO()):
                f.main()
            self.assertEqual(json.loads(output.read_text()), [result])

    def test_elf_load_mapping_and_bounds(self):
        for machine, arch in ((62, 'x86_64'), (183, 'arm64')):
            data = bytearray(1024)
            data[:16] = bytes.fromhex('7f454c46020101000000000000000000')
            struct.pack_into('<HHIQQQIHHHHHH', data, 16,
                             2, machine, 1, 0x400100, 64, 0, 0, 64, 56, 1, 64, 0, 0)
            struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x400000, 0x400000, 1024, 1024, 4096)
            image = f.BinaryImage(bytes(data))
            self.assertEqual(image.arch, arch)
            self.assertEqual(image.va_to_file(0x400100), 256)
            struct.pack_into('<H', data, 56, 100)
            with self.assertRaises(ValueError):
                f.BinaryImage(bytes(data))

    def test_report_never_overwrites_existing_or_alias(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'agy'
            target.write_bytes(b'original')
            symlink, hardlink = root / 'sym.json', root / 'hard.json'
            symlink.symlink_to(target)
            os.link(target, hardlink)
            for path in (target, symlink, hardlink):
                with self.assertRaises(ValueError):
                    f.validate_report_path(path, [target.resolve()], root / 'backups')
            report = root / 'new.json'
            f.validate_report_path(report, [target.resolve()], root / 'backups')
            # Simulate a file appearing after validation.
            report.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):
                f.write_report(report, {})
            self.assertEqual(report.read_bytes(), b'keep')
            self.assertEqual(target.read_bytes(), b'original')

    def test_linux_process_path_ignores_comm_truncation(self):
        with tempfile.TemporaryDirectory() as folder:
            proc = Path(folder)
            (proc / '1234').mkdir()
            (proc / '1234/exe').symlink_to('/opt/antigravity/language_server_linux_x64')
            with patch('sys.platform', 'linux'), patch.object(Path, 'iterdir', return_value=iter(proc.iterdir())):
                result = f.running_backends([Path('/opt/antigravity/language_server_linux_x64')])
            self.assertEqual(result, [{'pid': 1234, 'name': 'language_server_linux_x64'}])

    def test_wal_activity_selects_active_conversation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            active, inactive = root / 'active.db', root / 'inactive.db'
            connections = []
            try:
                for path, limit in ((active, 256000), (inactive, 983040)):
                    conn = sqlite3.connect(path)
                    connections.append(conn)
                    for table in ('gen_metadata', 'executor_metadata'):
                        conn.execute(f'create table {table} (idx integer, data blob)')
                    conn.execute('insert into gen_metadata values(0,?)', (field(1, field(9, field(10, field(4, limit)))),))
                    conn.execute('insert into executor_metadata values(0,?)', (field(10, field(2, field(5, limit))),))
                    conn.commit()
                conn = connections[0]
                conn.execute('pragma journal_mode=wal')
                conn.execute('pragma wal_autocheckpoint=0')
                os.utime(active, (100, 100))
                os.utime(inactive, (200, 200))
                conn.execute('insert into gen_metadata select 1,data from gen_metadata where idx=0')
                conn.commit()
                with patch.object(v, 'conversation_dirs', return_value=[root]):
                    self.assertEqual(v.find_conversation_db(None), active)
                    self.assertEqual(f.inspect_contexts()[0]['state'], 'LIMITED_256K')
            finally:
                for conn in connections:
                    conn.close()

    @unittest.skipUnless(os.environ.get('AGY_TEST_BINARY'), 'provide an original binary fixture')
    def test_partial_checkpoint_changes_are_rejected(self):
        source = Path(os.environ['AGY_TEST_BINARY'])
        original = source.read_bytes()
        plan = f.analyze_binary(source)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'agy'
            for change in plan['changes']:
                if change['fixed_before']:
                    continue
                data = bytearray(original)
                offset = int(change['offset'], 16)
                after = bytes.fromhex(change['after'])
                data[offset:offset + len(after)] = after
                target.write_bytes(data)
                self.assertEqual(f.analyze_binary(target)['status'], 'UNKNOWN_OR_PARTIAL')
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), plan['sha256'])
            chk_off = int(plan['functions']['checkpointNeeded']['file_start'], 16)
            data = bytearray(original)
            data[chk_off:chk_off + 4] = b'\xc3\x90\x90\x90'
            target.write_bytes(data)
            self.assertEqual(f.analyze_binary(target, backup_dir=False)['status'], 'UNKNOWN_OR_PARTIAL')
            entry = next(c for c in plan['changes'] if c['name'] == 'trampolineHost_entry')
            # NOPing part of the original prologue is neither our patch nor a valid
            # original entry, so it must not be offered as UNPATCHED.
            data = bytearray(original)
            entry_offset = int(entry['offset'], 16)
            data[entry_offset + 4:entry_offset + 8] = b'\x90\x90\x90\x90'
            target.write_bytes(data)
            self.assertEqual(f.analyze_binary(target)['status'], 'UNKNOWN_OR_PARTIAL')
            if plan['arch'] == 'arm64':
                # A changed return-register sequence must not be accepted.
                data = bytearray(original)
                exit_site = next(c for c in plan['changes'] if c['name'] == 'applyOverride_exit')
                exit_offset = int(exit_site['offset'], 16)
                data[exit_offset+4:exit_offset+8] = bytes.fromhex('1f2003d5')
                target.write_bytes(data)
                with self.assertRaises(RuntimeError):
                    f.analyze_binary(target)
                data = bytearray(original)
                offset = int(entry['offset'], 16)
                data[offset+12:offset+16] = bytes.fromhex('1f2003d5')
                target.write_bytes(data)
                self.assertEqual(f.analyze_binary(target)['status'], 'UNKNOWN_OR_PARTIAL')


if __name__ == '__main__':
    unittest.main()
