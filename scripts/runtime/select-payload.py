"""Select the native 2.5.16.30 runtime from an unpacked official package."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

source, dest = map(Path, sys.argv[1:])
base = Path('usr/share/sangfor/aTrust')
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
