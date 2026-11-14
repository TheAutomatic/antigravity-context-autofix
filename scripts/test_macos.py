"""Run AGY_TEST_BINARY=~/.gemini/bin/agy python3 -m unittest -v test_macos.

The optional integration test modifies only a temporary copy.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import fix_antigravity_context as f


class MachOTests(unittest.TestCase):
    def image(self):
        header = struct.pack('<8I', 0xFEEDFACF, 0x0100000C, 0, 2, 1, 72, 0, 0)
        segment = struct.pack('<II16sQQQQiiII', 0x19, 72, b'__TEXT',
                              0x100000000, 108, 0, 108, 7, 5, 0, 0)
        return header + segment + bytes(4)

    def test_mapping(self):
        image = f.BinaryImage(self.image())
        self.assertEqual((image.fmt, image.arch), ('Mach-O', 'arm64'))
        self.assertEqual(image.va_to_file(0x100000068), 104)
        with self.assertRaises(ValueError):
            image.va_to_file(0x10000006C)

    def test_x86_64_mapping(self):
        header = struct.pack('<8I', 0xFEEDFACF, 0x01000007, 0, 2, 1, 72, 0, 0)
        segment = struct.pack('<II16sQQQQiiII', 0x19, 72, b'__TEXT',
                              0x100000000, 108, 0, 108, 7, 5, 0, 0)
        image = f.BinaryImage(header + segment + bytes(4))
        self.assertEqual((image.fmt, image.arch), ('Mach-O', 'x86_64'))
        self.assertEqual(image.va_to_file(0x100000068), 104)

    def test_invalid_commands(self):
        for offset, value in ((20, 1000), (36, 0), (36, 200)):
            data = bytearray(self.image())
            struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                f.BinaryImage(bytes(data))

    @unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('AGY_TEST_BINARY'),
                         'set AGY_TEST_BINARY on macOS for copy-only integration test')
    def test_signed_patch_and_exact_restore(self):
        source = Path(os.environ['AGY_TEST_BINARY']).expanduser()
        if f.analyze_binary(source)['status'] != 'UNPATCHED':
            self.skipTest('Integration fixture must be an original unpatched binary')
        original = hashlib.sha256(source.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix='agy-patch-test-') as folder:
            root = Path(folder)
            target = root / 'agy'
            shutil.copy2(source, target)
            sidecar = root / 'agy.version.json'
            sidecar.write_text(json.dumps({'version': 'test'}))
            with patch.object(f, 'get_binary_version', return_value='test'), patch.object(f, 'running_backends', return_value=[]), contextlib.redirect_stdout(io.StringIO()):
                # Failure to persist the original must prevent replacement.
                with patch.object(f, 'sync_directory', side_effect=OSError('sync failed')), \
                     patch.object(f, 'replace_with_retry') as replace:
                    with self.assertRaises(OSError):
                        f.patch_target(target, root / 'backups')
                    replace.assert_not_called()
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), original)
                info = f.patch_target(target, root / 'backups')
                self.assertEqual(f.analyze_binary(target)['status'], 'ALREADY_PATCHED')
                self.assertEqual(info['patched_sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
                self.assertEqual(json.loads(sidecar.read_text())['size'], target.stat().st_size)
                f.patch_target(target, root / 'backups')
                (root / 'backups' / 'agy-zzz-manifest-invalid.json').write_text('{')
                self.assertTrue(f.find_restore_backup(target, root / 'backups').is_file())
                restored = f.restore_target(target, root / 'backups')
                self.assertEqual(restored['status'], 'RESTORED')
                self.assertEqual(restored['restored_sha256'], original)
                self.assertEqual(restored['before_sha256'], info['patched_sha256'])
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), original)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)


if __name__ == '__main__':
    unittest.main()
