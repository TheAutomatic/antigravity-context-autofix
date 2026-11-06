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

    def test_replace_refuses_truncating_write_without_rollback(self):
        class WinError6(OSError):
            winerror = 6

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target, source = root / 'agy', root / 'patched'
            target.write_bytes(b'original')
            source.write_bytes(b'patched')
            with patch.object(f, 'wait_for_backends'), \
                 patch.object(f.os, 'name', 'nt'), \
                 patch.object(f, '_replace_atomic', side_effect=WinError6(6, 'invalid handle')):
                with self.assertRaises(RuntimeError):
                    f.replace_with_retry(source, target, hashlib.sha256(b'original').hexdigest())
            self.assertEqual(target.read_bytes(), b'original')

    @unittest.skipUnless(os.environ.get('AGY_TEST_BINARY'), 'provide an original binary fixture')
    def test_trampoline_host_falls_back_when_preferred_symbols_are_absent(self):
        source = Path(os.environ['AGY_TEST_BINARY'])
        img = f.BinaryImage(source.read_bytes())
        _, text_va, funcs, hosts = f.locate_go_functions(img)
        preferred = f.choose_trampoline_host(img, funcs, hosts, text_va)
        self.assertTrue(preferred['symbol'].endswith(f.HOST_PREFERENCE[0]))
        reduced = {n: v for n, v in hosts.items() if not n.endswith(f.HOST_PREFERENCE)}
        fallback = f.choose_trampoline_host(img, funcs, reduced, text_va)
        self.assertNotEqual(fallback['symbol'], preferred['symbol'])
        self.assertGreaterEqual(fallback['file_end'] - fallback['file_start'], f.HOST_MIN_BYTES)
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
