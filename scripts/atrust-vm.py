#!/usr/bin/env python3
"""Rootless QEMU/KVM appliance. The container runs QEMU, aTrust runs in its VM."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".vm"
IMAGE = "localhost/atrust-manager:latest"
NAME = "atrust-vm"
SSH_PORT = 22220
WEB_PORT = 8787
SOCKS_PORT = 10808
BASE_NAME = "jammy-server-cloudimg-amd64.img"
BASE_URL = "https://cloud-images.ubuntu.com/jammy/current/"


def podman(*args, **kwargs):
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    return subprocess.run([
        "podman", "--root", str(STATE / "containers"),
        "--runroot", str(runtime / "atrust-podman"),
        "--volumepath", str(STATE / "volumes"), "--storage-driver", "vfs",
        *map(str, args)], **kwargs)


def tools(*command):
    return podman("run", "--rm", "--network=none", "--cap-drop=all",
                  "--userns=keep-id", "--user", f"{os.getuid()}:{os.getgid()}",
                  "-v", f"{STATE}:/vm", IMAGE, *command, check=True)


def ssh_args():
    return ["ssh", "-i", str(STATE / "id_ed25519"), "-p", str(SSH_PORT),
            "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=4",
            "-o", f"UserKnownHostsFile={STATE / 'known_hosts'}"]


def ssh(command=None, **kwargs):
    return subprocess.run([*ssh_args(), "atrust@127.0.0.1",
                           *([command] if command else [])], **kwargs)


def prepare():
    STATE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE, 0o700)
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("/dev/kvm is not available to this user")
    podman("build", "-t", IMAGE, "-f", ROOT / "scripts/vm/Containerfile",
           ROOT, check=True)
    with urllib.request.urlopen(BASE_URL + "SHA256SUMS", timeout=30) as r:
        sums = r.read().decode()
    expected = next(line.split()[0] for line in sums.splitlines()
                    if line.split()[-1].lstrip("*") == BASE_NAME)
    base = STATE / BASE_NAME
    if not base.exists():
        partial = base.with_suffix(".part")
        with urllib.request.urlopen(BASE_URL + BASE_NAME, timeout=90) as r, partial.open("wb") as f:
            while chunk := r.read(4 * 1024 * 1024):
                f.write(chunk)
        partial.replace(base)
    with base.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    if digest != expected:
        raise RuntimeError("Ubuntu cloud image SHA256 verification failed")
    if not (STATE / "id_ed25519").exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(STATE / "id_ed25519"), "-C", "atrust-vm-local"], check=True)
    public = (STATE / "id_ed25519.pub").read_text().strip()
    config = {
        "hostname": "atrust-vm", "ssh_pwauth": False,
        "users": [{"name": "atrust", "shell": "/bin/bash", "lock_passwd": True,
                   "sudo": "ALL=(ALL) NOPASSWD:ALL", "ssh_authorized_keys": [public]}],
        "package_update": False, "package_upgrade": False,
        "write_files": [
            {"path": "/etc/atrust-vm-isolated", "permissions": "0644", "content": "QEMU KVM guest\n"},
            {"path": "/etc/systemd/resolved.conf.d/20-atrust-vm.conf", "content":
             "[Resolve]\nDNS=223.5.5.5#dns.alidns.com 223.6.6.6#dns.alidns.com\nDNSOverTLS=yes\nFallbackDNS=\n"},
            {"path": "/etc/ssh/sshd_config.d/60-atrust-vm.conf", "content":
             "PasswordAuthentication no\nPermitRootLogin no\nAllowUsers atrust\nGatewayPorts no\n"}],
        # bootcmd precedes write_files; write the resolver configuration here
        # too, so the first package operation never uses the router's Fake-IP.
        "bootcmd": [["sh", "-c", "mkdir -p /etc/systemd/resolved.conf.d\n"
                     "printf '%s\\n' '[Resolve]' 'DNS=223.5.5.5#dns.alidns.com 223.6.6.6#dns.alidns.com' "
                     "'DNSOverTLS=yes' 'FallbackDNS=' > /etc/systemd/resolved.conf.d/20-atrust-vm.conf\n"
                     "systemctl restart systemd-resolved"]],
    }
    (STATE / "user-data").write_text("#cloud-config\n" + json.dumps(config))
    (STATE / "meta-data").write_text("instance-id: atrust-vm-001\nlocal-hostname: atrust-vm\n")
    network = {"version": 2, "ethernets": {"vmnet": {
        "match": {"macaddress": "52:54:00:73:80:01"}, "set-name": "ens3",
        "dhcp4": True, "dhcp6": False, "accept-ra": False,
        "dhcp4-overrides": {"use-dns": False, "use-domains": False}}}}
    (STATE / "network-config").write_text(json.dumps(network))
    tools("genisoimage", "-quiet", "-output", "/vm/seed.iso", "-volid", "cidata",
          "-joliet", "-rock", "/vm/user-data", "/vm/meta-data", "/vm/network-config")
    if not (STATE / "guest.qcow2").exists():
        tools("qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
              "-b", f"/vm/{BASE_NAME}", "/vm/guest.qcow2", "24G")
    print("VM prepared (2 vCPU, 3 GiB RAM, 24 GiB sparse disk)")


def start():
    running = podman("inspect", "--format", "{{.State.Running}}", NAME,
                     capture_output=True, text=True)
    if running.returncode == 0 and running.stdout.strip() == "true":
        print("VM is already running")
        return
    if running.returncode == 0:
        podman("rm", NAME, check=True)
    if not (STATE / "guest.qcow2").exists():
        raise RuntimeError("run prepare first")
    podman("run", "-d", "--name", NAME, "--network=host", "--device=/dev/kvm",
           "--cap-drop=all", "--security-opt=no-new-privileges", "--userns=keep-id",
           "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{STATE}:/vm", IMAGE,
           "qemu-system-x86_64", "-enable-kvm", "-machine", "q35", "-cpu", "host",
           "-smp", "2", "-m", "3072", "-display", "none", "-monitor", "none",
           "-serial", "file:/vm/serial.log", "-rtc", "base=utc",
           "-drive", "file=/vm/guest.qcow2,if=virtio,format=qcow2",
           "-drive", "file=/vm/seed.iso,media=cdrom,readonly=on",
           "-netdev", f"user,id=vmnet,net=10.77.0.0/24,"
           f"hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22,hostfwd=tcp:127.0.0.1:{WEB_PORT}-:8080",
           "-device", "virtio-net-pci,netdev=vmnet,mac=52:54:00:73:80:01", check=True)
    print(f"VM started; management: http://127.0.0.1:{WEB_PORT}")


def wait_ssh():
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        result = ssh("true", capture_output=True)
        if result.returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError("SSH not ready; inspect .vm/serial.log")


def install(deb: Path):
    if not deb.is_file():
        raise RuntimeError("provide the official aTrust .deb file via --deb")
    wait_ssh()
    ssh("sudo cloud-init status --wait", check=False)
    # Send only selected source/assets: never copy .git, host passwords or VM disks.
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(ROOT / "src/atrust_cli", arcname="atrust_cli",
               filter=lambda member: None if "__pycache__" in member.name else member)
    ssh("sudo mkdir -p /opt/atrust-cli/src && sudo tar xzf - -C /opt/atrust-cli/src",
        input=buf.getvalue(), check=True)
    with deb.open("rb") as f:
        ssh("cat > /tmp/atrust.deb", stdin=f, check=True)
    bootstrap = (ROOT / "scripts/vm/install-guest.sh").read_bytes()
    ssh("sudo bash -s", input=bootstrap, check=True)
    print(f"Management ready: http://127.0.0.1:{WEB_PORT}")


def sync():
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(ROOT / "src/atrust_cli", arcname="atrust_cli",
               filter=lambda m: None if "__pycache__" in m.name else m)
    ssh("sudo tar xzf - -C /opt/atrust-cli/src && sudo systemctl restart atrust-web", input=buf.getvalue(), check=True)


def proxy():
    check = subprocess.run([*ssh_args(), "-S", str(STATE / "proxy.control"),
                            "-O", "check", "atrust@127.0.0.1"], capture_output=True)
    if check.returncode == 0:
        print(f"SOCKS5 is already running at 127.0.0.1:{SOCKS_PORT}")
        return
    wait_ssh()
    subprocess.run([*ssh_args(), "-M", "-S", str(STATE / "proxy.control"),
                    "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=20",
                    "-fN", "-D", f"127.0.0.1:{SOCKS_PORT}", "atrust@127.0.0.1"], check=True)
    print(f"SOCKS5: 127.0.0.1:{SOCKS_PORT} (use socks5h for guest DNS)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "start", "stop", "status", "install", "sync", "ssh", "proxy"])
    parser.add_argument("--deb", type=Path, default=ROOT.parent / "atrust-bin/atrust-2.5.16.30.deb")
    args = parser.parse_args()
    try:
        if args.action == "prepare": prepare()
        elif args.action == "start": start()
        elif args.action == "install": install(args.deb)
        elif args.action == "sync": sync()
        elif args.action == "ssh": ssh()
        elif args.action == "proxy": proxy()
        elif args.action == "stop":
            subprocess.run([*ssh_args(), "-S", str(STATE / "proxy.control"),
                            "-O", "exit", "atrust@127.0.0.1"], capture_output=True)
            ssh("sudo systemctl poweroff", capture_output=True)
            for _ in range(15):
                result = podman("inspect", "--format", "{{.State.Running}}", NAME,
                                capture_output=True, text=True)
                if result.returncode != 0 or result.stdout.strip() != "true":
                    break
                time.sleep(2)
            else:
                podman("stop", "--time", "45", NAME, check=True)
        elif args.action == "status": podman("ps", "-a", "--filter", f"name={NAME}", check=True)
    except (RuntimeError, subprocess.CalledProcessError, OSError) as exc:
        print(f"VM operation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
