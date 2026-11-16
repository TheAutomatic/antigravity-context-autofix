import contextlib
import io
import sqlite3
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fix_antigravity_context as f
import verify_session as v


def varint(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def field(k, value):
    if isinstance(value, int):
        return varint(k << 3) + varint(value)
    return varint((k << 3) | 2) + varint(len(value)) + value


class StatusTests(unittest.TestCase):
    def test_confirm_before_any_mutation(self):
        target = Path('agy').resolve()
        report = {'compatible': True, 'binaries': [{'path': str(target), 'status': 'UNPATCHED'}]}
        for answer in ('', 'n'):
            with patch('sys.argv', ['fix', '--target', str(target), '--kill', '--context-limit', '512000']), \
                 patch.object(f, 'preflight', return_value=report), patch('builtins.input', return_value=answer), \
                 patch.object(f, 'kill_running_backends') as kill, patch.object(f, 'patch_target') as modify, \
                 self.assertRaises(SystemExit):
                f.main()
            kill.assert_not_called()
            modify.assert_not_called()
        with patch('sys.argv', ['fix', '--target', str(target), '--context-limit', '512000']), \
             patch.object(f, 'preflight', return_value=report), patch('builtins.input', return_value='Y'), \
             patch.object(f, 'wait_for_backends'), patch.object(f, 'patch_target') as modify, \
             patch.object(Path, 'exists', return_value=True):
            f.main()
        modify.assert_called_once()

    def test_retention_choice_controls_pruning(self):
        target = Path('agy').resolve()
        report = {'compatible': True, 'binaries': [{'path': str(target), 'status': 'UNPATCHED'}]}
        for answer, expected in (('', True), ('2', False)):
            with patch('sys.argv', ['fix', '--target', str(target), '--context-limit', '512000']), \
                 patch.object(f, 'preflight', return_value=report), \
                 patch('builtins.input', side_effect=['Y', answer]), \
                 patch.object(f, 'wait_for_backends'), \
                 patch.object(f, 'patch_target', return_value={'path': str(target)}), \
                 patch.object(f, 'prune_old_backups', return_value=[]) as prune, \
                 patch.object(Path, 'exists', return_value=True), \
                 contextlib.redirect_stdout(io.StringIO()):
                f.main()
            self.assertEqual(prune.called, expected, answer)

    def test_read_only_and_already_patched_never_prompt(self):
        target = Path('agy').resolve()
        report = {'compatible': True, 'binaries': [{'path': str(target), 'status': 'ALREADY_PATCHED'}]}
        for flags in ([], ['--status']):
            with patch('sys.argv', ['fix', '--target', str(target), '--context-limit', '512000'] + flags), \
                 patch.object(f, 'preflight', return_value=report), patch('builtins.input') as prompt, \
                 patch.object(f, 'patch_target') as modify:
                try:
                    f.main()
                except SystemExit as exc:
                    self.assertEqual(exc.code, 0)
            prompt.assert_not_called()
            modify.assert_not_called()

    def test_restore_confirmation_and_incompatible_stop(self):
        target = Path('agy').resolve()
        report = {'compatible': True, 'binaries': [{'path': str(target), 'status': 'ALREADY_PATCHED'}]}
        with patch('sys.argv', ['fix', '--target', str(target), '--restore']), \
             patch.object(f, 'preflight', return_value=report), \
             patch.object(f, 'find_restore_backup', return_value=Path('original.bak')), \
             patch('builtins.input', return_value='N'), patch.object(f, 'restore_target') as restore, \
             self.assertRaises(SystemExit):
            f.main()
        restore.assert_not_called()
        with patch('sys.argv', ['fix', '--target', str(target), '--context-limit', '512000']), \
             patch.object(f, 'preflight', return_value={'compatible': False}), \
             patch('builtins.input') as prompt, patch.object(f, 'patch_target') as modify, \
             self.assertRaises(SystemExit):
            f.main()
        prompt.assert_not_called()
        modify.assert_not_called()

    def test_discovery_defaults_path_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            original = home / '.gemini/bin/agy'
            original.parent.mkdir(parents=True)
            original.write_bytes(b'test')
            bindir = home / 'bin'
            bindir.mkdir()
            (bindir / 'agy').symlink_to(original)
            with patch.object(Path, 'home', return_value=home), \
                 patch.dict(os.environ, {'PATH': str(bindir)}), patch('sys.platform', 'linux'):
                found = f.discover_default_targets()
            self.assertEqual(found.count(original.resolve()), 1)

    def test_discovery_windows_and_macos_layouts(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            windows = home / 'Local/Programs/Antigravity/resources/bin/language_server.exe'
            mac = home / 'Applications/Antigravity.app/Contents/Resources/bin/language_server_macos_arm'
            for path in (windows, mac):
                path.parent.mkdir(parents=True)
                path.write_bytes(b'test')
            with patch.object(Path, 'home', return_value=home), patch.dict(os.environ, {'PATH': '', 'LOCALAPPDATA': str(home / 'Local')}):
                with patch('sys.platform', 'win32'):
                    self.assertIn(windows.resolve(), f.discover_default_targets())
                with patch('sys.platform', 'darwin'):
                    self.assertIn(mac.resolve(), f.discover_default_targets())

    def test_process_retry_and_cancel(self):
        process = {'pid': 1234, 'name': 'agy'}
        with patch.object(f, 'running_backends', side_effect=[[process], [process], []]), \
             patch('builtins.input', return_value='Y') as prompt:
            f.wait_for_backends([Path('agy')])
            self.assertEqual(prompt.call_count, 2)
        with patch.object(f, 'running_backends', return_value=[process]), \
             patch('builtins.input', return_value='N'), self.assertRaises(SystemExit):
            f.wait_for_backends([Path('agy')])

    def test_context_states(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'session.db'
            conn = sqlite3.connect(path)
            for table in ('gen_metadata', 'executor_metadata'):
                conn.execute(f'create table {table} (idx integer, data blob)')
            for gen, executor, state in ((256000, 256000, 'LIMITED_256K'),
                                         (512000, 512000, 'EXPECTED_WINDOW'),
                                         (734000, 734000, 'EXPECTED_WINDOW'),
                                         (734000, 900000, 'EXPECTED_WINDOW'),
                                         (900000, 900000, 'EXPECTED_WINDOW'),
                                         (900000, 983040, 'EXPECTED_WINDOW'),
                                         (983040, 983040, 'EXPECTED_WINDOW'),
                                         (734000, 256000, 'MIXED_LIMITS'),
                                         (900000, 256000, 'MIXED_LIMITS'),
                                         (128000, 128000, 'OTHER_WINDOW')):
                for table in ('gen_metadata', 'executor_metadata'):
                    conn.execute(f'delete from {table}')
                g = field(1, field(9, field(10, field(4, gen))))
                e = field(10, field(2, field(5, executor)))
                conn.execute('insert into gen_metadata values (0, ?)', (g,))
                conn.execute('insert into executor_metadata values (0, ?)', (e,))
                conn.commit()
                self.assertEqual(f.inspect_context(db_path=path)['state'], state)
                if gen == 256000 and executor == 256000:
                    from verify_session import inspect_session
                    self.assertTrue(inspect_session(db_path=path, expected_limit=256000)['latest_limit_ok'])
                    self.assertFalse(inspect_session(db_path=path, expected_limit=734000)['latest_limit_ok'])
                if gen == 734000 and executor == 900000:
                    from verify_session import inspect_session
                    self.assertTrue(inspect_session(db_path=path, expected_limit=None)['latest_limit_ok'])
                    self.assertFalse(inspect_session(db_path=path, expected_limit=734000)['latest_limit_ok'])
            # Also support live sessions where gen_metadata is populated and executor_metadata is empty.
            for gen, state in ((512000, 'EXPECTED_WINDOW'), (734000, 'EXPECTED_WINDOW'), (900000, 'EXPECTED_WINDOW'), (256000, 'LIMITED_256K')):
                conn.execute('delete from gen_metadata')
                conn.execute('delete from executor_metadata')
                g = field(1, field(3, 1419) + field(9, field(10, field(4, gen))) + field(19, b'gemini-4-argon'))
                conn.execute('insert into gen_metadata values (0, ?)', (g,))
                conn.commit()
                ctx = f.inspect_context(db_path=path)
                self.assertEqual(ctx['state'], state)
                self.assertEqual(ctx['latest_turn'].get('model_id'), 1419)
                self.assertEqual(ctx['latest_turn'].get('model_name'), 'gemini-4-argon')
                self.assertNotIn('executor_idx', ctx['latest_turn'])
                self.assertNotIn('executor_max_token_limit', ctx['latest_turn'])
                self.assertNotIn('executor_idx', ctx['first_turn'])
                self.assertNotIn('executor_max_token_limit', ctx['first_turn'])
            conn.execute('delete from gen_metadata')
            conn.commit()
            self.assertEqual(f.inspect_context(db_path=path)['state'], 'UNKNOWN')
            conn.close()

    def test_unsupported_does_not_hide_context(self):
        with patch.object(f, 'analyze_binary', side_effect=ValueError('new format')), \
             patch.object(f, 'inspect_context', return_value={'state': 'UNKNOWN', 'error': 'no DB'}):
            result = f.preflight([Path('missing')])
        self.assertFalse(result['compatible'])
        self.assertEqual(result['session']['state'], 'UNKNOWN')

    def test_recent_session_with_empty_wal_and_read_only_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            ping = directory / 'ping.db'
            older = directory / 'old.db'
            unreadable = directory / 'unreadable.db'
            for path, timestamp in ((ping, 300), (older, 100), (unreadable, 400)):
                with contextlib.closing(sqlite3.connect(path)) as conn:
                    conn.execute('pragma journal_mode=wal')
                    conn.execute('create table gen_metadata (idx integer, data blob)')
                    conn.execute('create table executor_metadata (idx integer, data blob)')
                    if path != unreadable:
                        gen = field(1, field(9, field(10, field(4, 512000) + field(1, 100))))
                        exe = field(10, field(2, field(5, 512000)))
                        conn.execute('insert into gen_metadata values (0, ?)', (gen,))
                        conn.execute('insert into executor_metadata values (0, ?)', (exe,))
                    conn.commit()
                os.utime(path, (timestamp, timestamp))
                wal = path.with_name(path.name + '-wal')
                wal.touch()
                os.utime(wal, (500, 500))
                path.with_name(path.name + '-shm').touch()

            connect = sqlite3.connect

            def read_only_connect(database, **kwargs):
                if database.startswith(directory.resolve().as_uri() + '/'):
                    raise sqlite3.OperationalError('unable to open database file')
                return connect(database, **kwargs)

            output = io.StringIO()
            with patch.object(v, 'conversation_dirs', return_value=[directory]), \
                 patch.object(sqlite3, 'connect', side_effect=read_only_connect), \
                 contextlib.redirect_stdout(output):
                f.preflight([])
                self.assertEqual(v.inspect_session(db_path=ping)['read_mode'], 'stable_standalone_copy')
                ping.with_name(ping.name + '-wal').write_bytes(b'nonempty')
                self.assertEqual(f.inspect_context(db_path=ping)['state'], 'UNKNOWN')
            display = output.getvalue()
            self.assertLess(display.index('unreadable'), display.index('ping'))
            self.assertLess(display.index('ping'), display.index('old'))
            self.assertIn('Session has no request metadata yet', display)
            self.assertIn('[i 当前上下文 / CURRENT CONTEXT]', display)
            self.assertIn('Executor=512,000', display)


if __name__ == '__main__':
    unittest.main()
