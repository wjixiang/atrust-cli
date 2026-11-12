import importlib.util
import json
from pathlib import Path
import runpy
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_payload_excludes_desktop_and_records_native_files(tmp_path, monkeypatch):
    source, dest = tmp_path/'package', tmp_path/'selected'
    base = source/'usr/share/sangfor/aTrust'
    for name in ('resources/bin', 'resources/lib', 'resources/shell', 'uem'):
        (base/name).mkdir(parents=True)
        (base/name/'native.so').write_bytes(b'native')
    for name in ('resources/version', 'resources/sangfor2024.crt', 'resources/app/package.json', 'version', 'LICENSE'):
        p = base/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('metadata')
    (base/'aTrustTray').write_bytes(b'electron')
    (base/'resources/app/desktop.js').write_text('desktop')
    (base/'resources/lib/libstdc++.so.6').write_bytes(b'old')
    monkeypatch.setattr(sys, 'argv', ['select-payload.py', str(source), str(dest)])
    runpy.run_path(str(ROOT/'scripts/runtime/select-payload.py'), run_name='__main__')
    target = dest/'usr/share/sangfor/aTrust'
    assert not (target/'aTrustTray').exists()
    assert not (target/'resources/app/desktop.js').exists()
    assert not (target/'resources/lib/libstdc++.so.6').exists()
    assert (target/'resources/bin/libcurl.so.4').readlink() == Path('libcurl.so')
    manifest = json.loads((dest/'native-manifest.json').read_text())
    assert len(manifest) == 9
    assert all(len(row['sha256']) == 64 for row in manifest)
    assert all(row['size'] > 0 for row in manifest)


def test_runtime_refuses_host_network_before_starting_native_processes(monkeypatch):
    spec = importlib.util.spec_from_file_location('supervise', ROOT/'scripts/runtime/supervise.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.os, 'geteuid', lambda: 0)
    monkeypatch.setenv('ATRUST_HOST_NETNS', module.os.readlink('/proc/self/ns/net'))
    with pytest.raises(RuntimeError, match='separate network namespace'):
        module.validate()
    monkeypatch.delenv('ATRUST_HOST_NETNS')
    with pytest.raises(RuntimeError, match='separate network namespace'):
        module.validate()
