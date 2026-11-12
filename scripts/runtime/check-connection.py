#!/usr/bin/env python3
"""Verify an isolated runtime and optionally an authorized internal SSH endpoint.

Only reads the SSH identification string. No login, command or key is sent.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import socket
import struct
import sys
from urllib.parse import urlsplit
import urllib.request


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size-len(data))
        if not chunk:
            raise ValueError('SOCKS connection closed unexpectedly')
        data.extend(chunk)
    return bytes(data)


def ssh_probe(proxy_port, hostname, port):
    encoded = hostname.encode('idna')
    try:
        ip = ipaddress.ip_address(hostname)
        address = bytes([1 if ip.version == 4 else 4]) + ip.packed
    except ValueError:
        if not 0 < len(encoded) <= 255:
            raise ValueError('invalid target hostname')
        address = bytes([3, len(encoded)]) + encoded
    with socket.create_connection(('127.0.0.1', proxy_port), timeout=15) as sock:
        sock.settimeout(15)
        sock.sendall(b'\x05\x01\x00')
        if read_exact(sock, 2) != b'\x05\x00':
            raise ValueError('SOCKS5 server rejected the unauthenticated CONNECT method')
        sock.sendall(b'\x05\x01\x00'+address+struct.pack('!H', port))
        version, result, reserved, kind = read_exact(sock, 4)
        if version != 5 or result != 0 or reserved != 0:
            raise ValueError(f'SOCKS5 CONNECT rejected (code {result})')
        length = {1: 4, 4: 16}.get(kind)
        if kind == 3:
            length = read_exact(sock, 1)[0]
        if length is None:
            raise ValueError('invalid SOCKS5 response address')
        read_exact(sock, length+2)
        # SSH permits preliminary lines before its protocol identification.
        data = bytearray()
        while len(data) < 8192:
            chunk = sock.recv(min(1024, 8192-len(data)))
            if not chunk:
                break
            data.extend(chunk)
            lines = bytes(data).splitlines(keepends=True)
            for line in lines:
                if line.endswith(b'\n') and line.startswith((b'SSH-2.0-', b'SSH-1.99-')):
                    return True
        raise ValueError('no SSH protocol identification received')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--web-port', type=int, default=8788)
    parser.add_argument('--socks-port', type=int, default=10809)
    parser.add_argument('--ssh', metavar='HOST:PORT', help='an internal SSH endpoint you are authorized to test')
    args = parser.parse_args(argv)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f'http://127.0.0.1:{args.web_port}/api/state', timeout=5) as response:
            state = json.load(response)
        if not state.get('isolated') or state.get('tunnel') != 'online':
            raise ValueError('the isolated VPN tunnel is not online')
        print('Isolated VPN: online')
        if not args.ssh:
            print('Internal data transfer: NOT TESTED (provide --ssh HOST:PORT)')
            return 2
        target = urlsplit('ssh://'+args.ssh)
        if target.username or target.password or target.path or target.query or target.fragment or not target.hostname:
            raise ValueError('provide only HOST:PORT, without credentials or paths')
        port = target.port or 22
        ssh_probe(args.socks_port, target.hostname, port)
        print('SOCKS5 internal SSH identification: received; no authentication attempted')
        return 0
    except (OSError, ValueError) as exc:
        print(f'Check failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
