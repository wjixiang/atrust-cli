#!/usr/bin/env bash
# Snapshot everything aTrust touches in the network stack.
# Usage: sudo bash net-snapshot.sh /tmp/atrust-net-<state>.txt
set -u
out="${1:-/tmp/atrust-net-snapshot.txt}"
exec > >(tee "$out") 2>&1

sec() { echo; echo "===== $* ====="; }

sec "time"; date

sec "aTrust status (RPC, best effort)"
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
A="$PROJECT_ROOT/.venv/bin/python"
[ -x "$A" ] && timeout 5 "$A" -m atrust_cli status -a 2>&1 || echo "(cli unavailable)"

sec "ip rule"
ip rule show

sec "routes: main + all tables"
ip route show
ip route show table all | grep -v "table local"

sec "interfaces"
ip -br addr

sec "iptables (nat)"
iptables-save -t nat 2>&1

sec "iptables (filter)"
iptables-save -t filter 2>&1

sec "iptables (mangle)"
iptables-save -t mangle 2>&1

sec "ip6tables (nat+mangle)"
ip6tables-save -t nat 2>&1
ip6tables-save -t mangle 2>&1

sec "nftables ruleset"
nft list ruleset 2>&1

sec "resolv.conf + resolved"
cat /etc/resolv.conf
resolvectl status 2>&1

sec "DNS behaviour tests"
echo "-- resolvectl query archlinux.org:"
timeout 5 resolvectl query archlinux.org 2>&1 | head -2
echo "-- direct UDP 9.9.9.9:"
timeout 4 python3 - <<'PY'
import socket
q = bytes.fromhex('123401000001000000000000') + b'archlinux' + b'\x03org\x00' + bytes.fromhex('00010001')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(q, ('9.9.9.9', 53)); print('reply tail:', s.recvfrom(512)[0][-8:].hex())
except Exception as e:
    print('FAILED:', e)
PY

sec "fake-ip path test (curl through whatever DNS gives)"
timeout 6 curl -sv -o /dev/null https://archlinux.org 2>&1 | grep -E "Trying|HTTP/|error|Failed" | head -4

sec "raw IP path test (no DNS)"
timeout 6 curl -s -o /dev/null -w "%{http_code}\n" "https://1.1.1.1" 2>&1 || echo "raw-IP dead too"

sec "listeners on :53/:5353/:5335"
ss -lnup 2>/dev/null | grep -E ":(53|5353|5335)\b"

echo
echo "===== snapshot complete: $out ====="
