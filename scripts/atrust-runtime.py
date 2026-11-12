#!/usr/bin/env python3
"""Build and run the native headless aTrust runtime in rootless Podman."""
import argparse
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.runtime'


def podman(*args, **kwargs):
    STATE.mkdir(mode=0o700, exist_ok=True)
    saved_storage = STATE / 'storage-path'
    configured = os.environ.get('ATRUST_RUNTIME_STORAGE')
    storage = Path(configured or (saved_storage.read_text().strip() if saved_storage.exists() else str(STATE/'containers'))).expanduser().resolve()
    if configured:
        saved_storage.write_text(str(storage) + '\n')
        saved_storage.chmod(0o600)
    runtime = Path(os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}'))
    return subprocess.run(['podman', '--root', str(storage),
                           '--runroot', str(runtime/'atrust-native-podman'),
                           '--volumepath', str(STATE/'volumes'), '--storage-driver', 'vfs',
                           *map(str, args)], **kwargs)


IMAGE = 'localhost/atrust-native:latest'
NAME = 'atrust-native'


def build(deb, image):
    if not deb.is_file():
        raise ValueError('provide an official 2.5.16.30 amd64 .deb via --deb')
    # A fresh, explicit context prevents copying credentials, .git or VM disks.
    with tempfile.TemporaryDirectory(prefix='atrust-native-build-') as tmp:
        context = Path(tmp)
        shutil.copy2(deb, context/'official.deb')
        shutil.copytree(ROOT/'src/atrust_cli', context/'src/atrust_cli',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copytree(ROOT/'scripts/runtime', context/'runtime')
        podman('build', '--format=docker', '-t', image, '-f', context/'runtime/Containerfile', context, check=True)


def run(args):
    if not os.access('/dev/net/tun', os.R_OK | os.W_OK):
        raise ValueError('read/write access to /dev/net/tun is required')
    if not args.server.startswith('https://'):
        raise ValueError('--server must be an HTTPS controller URL')
    podman('run', '-d', '--name', NAME, '--network=pasta',
              '--cap-drop=all', '--cap-add=NET_ADMIN,NET_BIND_SERVICE,FOWNER,SETUID,SETGID,CHOWN,DAC_OVERRIDE,KILL',
              '--device=/dev/net/tun', '--dns=127.0.0.1', '--dns-search=.', '--security-opt=no-new-privileges',
              '--pids-limit=256', '--stop-timeout=15',
              '--env', 'ATRUST_HOST_NETNS='+os.readlink('/proc/self/ns/net'),
              '--env', 'ATRUST_SERVER='+args.server,
              '--env', f'ATRUST_SOCKS_ADDRESS=127.0.0.1:{args.socks_port}',
              '--publish', f'127.0.0.1:{args.web_port}:8080',
              '--publish', f'127.0.0.1:{args.socks_port}:1080',
              '--volume', 'atrust-native-state:/var/lib/atrust', args.image, check=True)
    print(f'Web: http://127.0.0.1:{args.web_port}; SOCKS5: 127.0.0.1:{args.socks_port}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default=IMAGE)
    commands = parser.add_subparsers(dest='action', required=True)
    b = commands.add_parser('build')
    b.add_argument('--deb', type=Path, required=True)
    load = commands.add_parser('load')
    load.add_argument('--archive', type=Path, required=True)
    r = commands.add_parser('run')
    r.add_argument('--server', required=True)
    r.add_argument('--web-port', type=int, default=8788)
    r.add_argument('--socks-port', type=int, default=10809)
    commands.add_parser('status')
    commands.add_parser('logs')
    commands.add_parser('stop')
    commands.add_parser('start')
    commands.add_parser('remove')
    args = parser.parse_args()
    try:
        if args.action in ('build', 'run') and platform.machine().lower() not in ('x86_64', 'amd64'):
            raise ValueError('this official native runtime supports Linux x86_64 only')
        if args.action == 'build': build(args.deb, args.image)
        elif args.action == 'load': podman('load', '-i', args.archive, check=True)
        elif args.action == 'run': run(args)
        elif args.action == 'status': podman('ps', '-a', '--filter', 'name='+NAME, check=True)
        else: podman('rm' if args.action == 'remove' else args.action, NAME, check=True)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
