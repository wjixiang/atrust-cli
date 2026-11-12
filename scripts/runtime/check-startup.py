#!/usr/bin/env python3
"""Native-image startup acceptance for ephemeral CI; never authenticates."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--engine', choices=('docker', 'podman'), default='docker')
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    def engine(*argv):
        return subprocess.check_output([args.engine, *argv], text=True, timeout=15)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic()+100
    while time.monotonic() < deadline:
        container = json.loads(engine('inspect', args.name))[0]
        if not container['State']['Running']:
            raise RuntimeError('native container stopped before readiness')
        try:
            with opener.open('http://127.0.0.1:8788/api/state', timeout=3) as response:
                state = json.load(response)
            if state['isolated'] and container['State'].get('Health', {}).get('Status') == 'healthy':
                break
        except (OSError, ValueError):
            pass
        time.sleep(2)
    else:
        raise RuntimeError('native runtime did not become healthy')
    assert state['stage'] == 'idle' and state['tunnel'] == 'offline'
    assert state['proxy_address'] == '127.0.0.1:10809'
    image = json.loads(engine('image', 'inspect', container['Image']))[0]
    assert image['Architecture'] == args.architecture
    probe = """from pathlib import Path
import os, struct
from atrust_cli.rpc import SdpCoreClient
from atrust_cli.agent import AgentClient
base=Path('/usr/share/sangfor/aTrust')
for name in ('aTrustAgent','aTrustXtunnel-64'):
    with (base/'resources/bin'/name).open('rb') as f: header=f.read(20)
    assert header[:6]==b'\\x7fELF\\x02\\x01'
    assert struct.unpack('<H',header[18:20])[0]==MACHINE
assert not (base/'aTrustTray').exists()
assert os.readlink('/proc/self/ns/net') != os.environ['ATRUST_HOST_NETNS']
assert SdpCoreClient(timeout=3).is_rpc_status_normal()
assert AgentClient(os.environ['ATRUST_SERVER'],timeout=3).status()['status']=='logout'
print('Native ELF, isolation, core RPC and HTTP status: PASS')
""".replace('MACHINE', str({'arm64':183, 'amd64':62}[args.architecture]))
    print(engine('exec', '--user', '1000:1000', args.name, 'python3', '-c', probe).strip())
    with socket.create_connection(('127.0.0.1',10809),timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(b'\x05\x01\x00')
        response = sock.makefile('rb').read(2)
        assert response == b'\x05\x00'
    print(f'{args.architecture} native services and SOCKS5 greeting: PASS; VPN login NOT TESTED')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f'Startup acceptance failed: {exc}', file=sys.stderr)
        sys.exit(1)
