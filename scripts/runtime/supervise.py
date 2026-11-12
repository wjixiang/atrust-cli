"""Supervise native services in a dedicated container network/PID namespace."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request

BASE = Path('/usr/share/sangfor/aTrust')
BIN = BASE / 'resources/bin'
STATE = Path('/var/lib/atrust')
USER = STATE / 'user'
ROOT = STATE / 'root'
MARKER = Path('/etc/atrust-runtime-isolated')


def health():
    try:
        with urllib.request.urlopen('http://127.0.0.1:8080/api/state', timeout=3) as r:
            data = json.load(r)
        return 0 if data.get('isolated') else 1
    except Exception:
        return 1


def validate():
    if os.geteuid() != 0:
        raise RuntimeError('run as container root; native daemon requires network administration')
    parent_net = os.environ.get('ATRUST_HOST_NETNS')
    if not parent_net or parent_net == os.readlink('/proc/self/ns/net'):
        raise RuntimeError('a separate network namespace is required; use scripts/atrust-runtime.py run')
    if not Path('/dev/net/tun').exists():
        raise RuntimeError('/dev/net/tun is required')
    status = Path('/proc/self/status').read_text()
    caps = int(next(l.split()[1] for l in status.splitlines() if l.startswith('CapEff:')), 16)
    if not caps & (1 << 12):
        raise RuntimeError('NET_ADMIN capability is required')
    if os.environ.get('ATRUST_SERVER', '').startswith('https://') is False:
        raise RuntimeError('set ATRUST_SERVER to your HTTPS controller URL')


def main():
    validate()
    os.umask(0o077)
    for home, uid in ((ROOT, 0), (USER, 1000)):
        home.mkdir(parents=True, exist_ok=True)
        os.chown(home, uid, uid)
        os.chmod(home, 0o700)
        logs = home / '.aTrust/logs'
        logs.mkdir(parents=True, exist_ok=True)
        os.chown(home / '.aTrust', uid, uid)
        os.chown(logs, uid, uid)
    # Native code uses getpwuid as well as HOME. Persist both users' homes.
    if not Path('/root').is_symlink():
        import shutil
        shutil.rmtree('/root')
        Path('/root').symlink_to(ROOT)
    shared = Path('/usr/share/sangfor/.aTrust')
    shared.mkdir(parents=True, exist_ok=True)
    shared.chmod(0o777)  # Official root daemon / user core IPC directory contract.
    shared_var = shared / 'var'
    shared_var.mkdir(exist_ok=True)
    shared_var.chmod(0o755)
    MARKER.write_text('Dedicated native runtime network namespace\n')
    env = dict(os.environ, LD_LIBRARY_PATH=':'.join(map(str, [BIN, BASE/'resources/lib', BASE/'uem/bin', BASE/'uem/lib'])))
    user_env = dict(env, HOME=str(USER), USER='atrust', LOGNAME='atrust', XDG_STATE_HOME=str(USER/'.local/state'))
    server = os.environ['ATRUST_SERVER']
    children = []
    streams = []
    def spawn(name, argv, user=False):
        log = (USER if user else ROOT) / '.aTrust/logs' / f'runtime-{name}.log'
        stream = log.open('ab', buffering=0)
        streams.append(stream)
        if user:
            os.chown(log, 1000, 1000)
        proc = subprocess.Popen(argv, cwd=BIN, env=user_env if user else dict(env, HOME=str(ROOT)),
                                stdout=stream, stderr=stream, start_new_session=True,
                                user=1000 if user else 0, group=1000 if user else 0,
                                extra_groups=[], umask=0o022 if name in ('daemon', 'core') else 0o077)
        children.append((name, proc))
        print(f'{name}: started', flush=True)
    stopped = False
    def stop(signum, frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        spawn('dns', ['/usr/sbin/unbound', '-d', '-c', '/etc/atrust-runtime-unbound.conf'])
        spawn('daemon', [str(BIN/'aTrustAgent'), '--plugin', 'plugin-daemon', '--plugin-cmd', '|'])
        # Allow the daemon IPC listener to initialize before the user core.
        time.sleep(2)
        spawn('core', [str(BIN/'aTrustAgent'), '--plugin', 'plugins/aTrustCore', '--enable-http', '--enable-event-center'], True)
        ready = False
        for _ in range(40):
            probe = subprocess.run([sys.executable, '-c',
                'from atrust_cli.rpc import SdpCoreClient; import sys; sys.exit(0 if SdpCoreClient(timeout=1).is_rpc_status_normal() else 1)'],
                env=user_env, user=1000, group=1000, extra_groups=[],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            if probe.returncode == 0:
                ready = True
                break
            if stopped or any(p.poll() is not None for _, p in children):
                break
            time.sleep(0.5)
        if not ready:
            raise RuntimeError('native user core RPC did not become ready')
        web_args = [sys.executable, '-m', 'atrust_cli.web', '--listen', '0.0.0.0', '--port', '8080', '--server', server, '--allow-tunnel']
        if os.environ.get('ATRUST_ALLOW_REMOTE') == '1':
            web_args.append('--allow-remote')
        spawn('web', web_args, True)
        spawn('socks', [sys.executable, '-m', 'atrust_cli.socks', '--listen', '0.0.0.0', '--port', '1080'], True)
        while not stopped:
            for name, proc in children:
                if proc.poll() is not None:
                    raise RuntimeError(f'{name} exited ({proc.returncode}); inspect the persistent logs')
            time.sleep(0.5)
    finally:
        MARKER.unlink(missing_ok=True)
        for _, proc in reversed(children):
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 8
        for _, proc in children:
            try:
                proc.wait(timeout=max(0.1, deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
        for stream in streams:
            stream.close()


if __name__ == '__main__':
    if '--health' in sys.argv:
        sys.exit(health())
    try:
        main()
    except Exception as exc:
        print(f'Runtime failed: {exc}', file=sys.stderr, flush=True)
        sys.exit(1)
