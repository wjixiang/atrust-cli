"""Select the native 2.5.16.30 runtime from an unpacked official package."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys

source, dest = map(Path, sys.argv[1:3])
architecture = sys.argv[3] if len(sys.argv) > 3 else None
if architecture not in (None, 'amd64', 'arm64'):
    raise ValueError('supported package architectures: amd64, arm64')
base = Path('usr/share/sangfor/aTrust')
if architecture:
    expected_machine = {'amd64': 62, 'arm64': 183}[architecture]
    for name in ('aTrustAgent', 'aTrustXtunnel-64'):
        with (source/base/'resources/bin'/name).open('rb') as stream:
            header = stream.read(20)
        if (len(header) != 20 or header[:6] != b'\x7fELF\x02\x01'
                or struct.unpack('<H', header[18:20])[0] != expected_machine):
            raise ValueError(f'{name} ELF architecture does not match {architecture}')
# Keep native plugins and environment modules intact: they are dynamically loaded.
# No Electron, Chromium resources, bundled web app, desktop hooks or unit files.
paths = ['resources/bin', 'resources/lib', 'resources/shell', 'resources/version',
         'resources/sangfor2024.crt', 'resources/app/package.json', 'version', 'uem', 'LICENSE']
for name in paths:
    src, dst = source / base / name, dest / base / name
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst)
root = dest / base
for name in ('resources/lib/libstdc++.so.6', 'uem/lib/libstdc++.so.6'):
    (root / name).unlink(missing_ok=True)
link = root / 'resources/bin/libcurl.so.4'
link.unlink(missing_ok=True)
link.symlink_to('libcurl.so')
manifest = []
for path in sorted(root.rglob('*')):
    if path.is_file() and not path.is_symlink():
        manifest.append({'path': str(path.relative_to(dest)), 'size': path.stat().st_size,
                         'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
(dest / 'native-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(f'Selected {len(manifest)} native files, {sum(p["size"] for p in manifest)} bytes')
