import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import fix_antigravity_context as f
from test_regressions import _FakeImage


def fixture(arch, newer=False):
    data = bytearray(0x2000)
    funcs = {}

    def body(name, code):
        start = 0x100 + len(funcs) * 0x180
        data[start:start + len(code)] = code
        funcs[name] = dict(symbol=name, file_start=start, file_end=start + 0x180,
                           va_start=0x400000 + start, va_end=0x400000 + start + 0x180,
                           pc_start=start, pc_end=start + 0x180)

    def words(*values):
        return struct.pack(f'<{len(values)}I', *values)

    if arch == 'x86_64':
        body('GetPlannerConfig', bytes.fromhex('4885c07405488b4020c3'))
        body('GetPlanModel', bytes.fromhex('4885c074048b4010c3'))
        body('GetMaxTokenLimit', bytes.fromhex('4885c074048b400cc3'))
        body('applyOverride', b'\x90' * 16 + bytes.fromhex(
            '488942104889d031db31c9c9c3' if newer else '4889481031db31c9c9c3'))
        body('trampolineHost', bytes.fromhex('493b66107640') + b'\xcc' * 100)
        for name in ('readGlobalRules', 'parseRuleFile', 'convertSkillPath'):
            body(name, bytes.fromhex('b9c05d0000'))
        code = bytearray(0x100)
        code[:17] = bytes.fromhex('41b900000000eb094885d241b9204e0000')
        code[32:41] = bytes.fromhex('31d2eb05ba204e0000')
        if newer:
            code[20:25] = bytes.fromhex('44894c2420')
            code[44:48] = bytes.fromhex('89542424')
        else:
            code[20:28] = bytes.fromhex('44898c2420010000')
            code[44:51] = bytes.fromhex('89942424010000')
            code[64:82] = bytes.fromhex('8b9c24240100004889c18b842420010000e8')
        body('computeTruncated', code)
        body('checkpointNeeded', bytes.fromhex('493b66107640'))
    else:
        body('GetPlannerConfig', words(0xF9401000))
        body('GetPlanModel', words(0xB9401000))
        body('GetMaxTokenLimit', words(0xB9400C00))
        body('applyOverride', words(0xD503201F) * 4 + words(
            *([0xF9000860, 0xAA0303E0] if newer else [0xF9000801]),
            0xAA1F03E1, 0xAA1F03E2))
        entry = words(0xF9400B90, 0xEB3063FF, 0x54000209)
        body('trampolineHost', entry + b'\xcc' * 100)
        for name in ('readGlobalRules', 'parseRuleFile', 'convertSkillPath'):
            body(name, words(0xD28BB802))
        code = bytearray(0x100)
        for off, rd in ((0, 3), (32, 4)):
            code[off:off + 4] = words(0xB9800000 | rd << 5 | rd)
            code[off + 16:off + 20] = words(0xD289C400 | rd)
        body('computeTruncated', code)
        body('checkpointNeeded', entry)
    img = _FakeImage(arch, bytes(data), [('.text', 0x400000, len(data), 0, len(data), True)])
    img.fmt = 'ELF'
    return img, funcs


class ThresholdTests(unittest.TestCase):
    def test_failed_threshold_switch_keeps_installed_patch_restorable(self):
        img, funcs = fixture('x86_64')

        def image(data):
            result = _FakeImage('x86_64', data, img.segments)
            result.fmt = 'ELF'
            return result

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target, backups = root / 'agy', root / 'backups'
            target.write_bytes(img.data)
            with patch.object(f, 'BinaryImage', side_effect=image), \
                 patch.object(f, 'locate_go_functions', return_value=(0, 0x400000, funcs, {})), \
                 patch.object(f, 'choose_trampoline_host', return_value=(funcs['trampolineHost'], False)), \
                 patch.object(f, 'get_binary_version', return_value='test'), \
                 patch.object(f, 'wait_for_backends'), contextlib.redirect_stdout(io.StringIO()):
                f.patch_target(target, backups, context_limit=734000)
                installed = target.read_bytes()
                old_manifest = f.select_restore_backup(target, backups)[0]
                old_record = old_manifest.read_bytes()
                calls = []
                real_sync = f.sync_directory

                def fail_manifest_sync(directory):
                    calls.append(directory)
                    if len(calls) == 2:
                        raise OSError('manifest directory sync failed')
                    real_sync(directory)

                with patch.object(f, 'sync_directory', side_effect=fail_manifest_sync):
                    with self.assertRaises(OSError):
                        f.patch_target(target, backups, context_limit=512000)
                self.assertEqual(target.read_bytes(), installed)
                self.assertEqual(old_manifest.read_bytes(), old_record)
                self.assertEqual(f.select_restore_backup(target, backups)[0], old_manifest)
                self.assertEqual(f.analyze_binary(
                    target, backup_dir=backups, context_limit=512000)['status'], 'UNPATCHED')
                f.patch_target(target, backups, context_limit=512000)
                f.prune_old_backups(backups, [target])
                self.assertEqual(f.analyze_binary(target)['context_limit'], 512000)
                f.restore_target(target, backups)
                self.assertEqual(target.read_bytes(), img.data)

    def test_menu_and_parameter_validation(self):
        for answer, expected in (('', 512000), ('1', 512000), ('2', 734000)):
            with patch('builtins.input', return_value=answer), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(f.choose_context_limit(), expected)
        with patch('builtins.input', side_effect=['bad', '2']), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(f.choose_context_limit(), 734000)
        with patch('builtins.input', side_effect=EOFError), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                f.choose_context_limit()
        for value in ('256000', '1048577', '512k', '-1'):
            with self.assertRaises(argparse.ArgumentTypeError):
                f.parse_context_limit(value)
        self.assertEqual(f.parse_context_limit('600000'), 600000)

    def test_both_architectures_encode_detect_and_switch_thresholds(self):
        for arch in ('x86_64', 'arm64'):
            for newer in (False, True):
                img, funcs = fixture(arch, newer)
                builder = f.build_x86_64_plan if arch == 'x86_64' else f.build_arm64_plan
                for limit in (512000, 734000, 600123):
                    with self.subTest(arch=arch, newer=newer, limit=limit):
                        plan = builder(img, funcs, limit)
                        out = bytearray(img.data)
                        for change in plan['changes']:
                            off = int(change['offset'], 16)
                            payload = bytes.fromhex(change['after'])
                            out[off:off + len(payload)] = payload
                        trampoline = bytes.fromhex(plan['changes'][2]['after'])
                        if arch == 'x86_64':
                            encoded = struct.unpack_from('<I', trampoline, 31)[0]
                        else:
                            low, high = struct.unpack_from('<II', trampoline, 28)
                            encoded = (low >> 5 & 0xFFFF) | (high >> 5 & 0xFFFF) << 16
                        self.assertEqual(encoded, limit)
                        with tempfile.TemporaryDirectory() as folder:
                            root = Path(folder)
                            target, backup = root / 'agy', root / 'original.bak'
                            target.write_bytes(out)
                            backup.write_bytes(img.data)
                            original_sha = hashlib.sha256(img.data).hexdigest()
                            patched_sha = hashlib.sha256(out).hexdigest()
                            (root / 'agy-test-manifest-a.json').write_text(json.dumps(dict(
                                sha256=original_sha, patched_sha256=patched_sha, backup_path=str(backup))))

                            def image(data):
                                result = _FakeImage(arch, data, img.segments)
                                result.fmt = 'ELF'
                                return result

                            with patch.object(f, 'BinaryImage', side_effect=image), \
                                 patch.object(f, 'locate_go_functions', return_value=(0, 0x400000, funcs, {})), \
                                 patch.object(f, 'choose_trampoline_host', return_value=(funcs['trampolineHost'], False)):
                                detected = f.analyze_binary(target, backup_dir=root)
                                self.assertEqual(detected['status'], 'ALREADY_PATCHED')
                                self.assertEqual(detected['context_limit'], limit)
                                switched = f.analyze_binary(target, backup_dir=root, context_limit=650000)
                                self.assertEqual(switched['status'], 'UNPATCHED')
                                self.assertEqual(switched['context_limit'], 650000)
                                self.assertEqual(switched['upgrade_from_backup'], str(backup))
                                self.assertEqual(switched['target_disk_sha256'], patched_sha)
                                with patch.object(f, 'get_binary_version', return_value='test'), \
                                     patch.object(f, 'wait_for_backends'), contextlib.redirect_stdout(io.StringIO()):
                                    f.patch_target(target, root, context_limit=650000)
                                self.assertEqual(f.analyze_binary(target)['context_limit'], 650000)
                                with patch.object(f, 'wait_for_backends'), contextlib.redirect_stdout(io.StringIO()):
                                    f.restore_target(target, root)
                                self.assertEqual(target.read_bytes(), img.data)

    def test_cli_menu_selection_reaches_patch(self):
        target = Path('agy').resolve()
        report = {'compatible': True, 'binaries': [{'path': str(target), 'status': 'UNPATCHED'}]}
        for answer, expected in (('', 512000), ('2', 734000)):
            with patch('sys.argv', ['fix', '--target', str(target)]), \
                 patch('builtins.input', side_effect=[answer, 'Y', '2']), \
                 patch.object(f, 'preflight', return_value=report) as preflight, \
                 patch.object(f, 'wait_for_backends'), patch.object(Path, 'exists', return_value=True), \
                 patch.object(f, 'patch_target') as modify, contextlib.redirect_stdout(io.StringIO()):
                f.main()
            self.assertEqual(preflight.call_args.kwargs['context_limit'], expected)
            self.assertEqual(modify.call_args.kwargs['context_limit'], expected)

    def test_cli_custom_limit_skips_menu_and_status_detects_without_prompt(self):
        target = Path('agy').resolve()
        report = {'compatible': True, 'binaries': [{'path': str(target), 'status': 'UNPATCHED'}]}
        with patch('sys.argv', ['fix', '--target', str(target), '--context-limit', '600000']), \
             patch('builtins.input', side_effect=['Y', '2']) as prompt, \
             patch.object(f, 'preflight', return_value=report) as preflight, \
             patch.object(f, 'wait_for_backends'), patch.object(Path, 'exists', return_value=True), \
             patch.object(f, 'patch_target') as modify, contextlib.redirect_stdout(io.StringIO()):
            f.main()
        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(preflight.call_args.kwargs['context_limit'], 600000)
        self.assertEqual(modify.call_args.kwargs['context_limit'], 600000)
        with patch('sys.argv', ['fix', '--target', str(target), '--status']), \
             patch('builtins.input') as prompt, \
             patch.object(f, 'preflight', return_value=report) as preflight, \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
            f.main()
        self.assertEqual(result.exception.code, 0)
        prompt.assert_not_called()
        self.assertIsNone(preflight.call_args.kwargs['context_limit'])
