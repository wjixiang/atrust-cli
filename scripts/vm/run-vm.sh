#!/bin/sh
set -eu
if [ "$#" -gt 0 ]; then
    exec "$@"
fi
if [ ! -r /vm/guest.qcow2 ] || [ ! -r /vm/seed.iso ]; then
    echo "Prepare /vm first with scripts/atrust-vm.py prepare, then install the guest." >&2
    exit 1
fi
exec qemu-system-x86_64 -enable-kvm -machine q35 -cpu host \
    -smp 2 -m 3072 -display none -monitor none -serial file:/vm/serial.log \
    -rtc base=utc -drive file=/vm/guest.qcow2,if=virtio,format=qcow2 \
    -drive file=/vm/seed.iso,media=cdrom,readonly=on \
    -netdev user,id=vmnet,net=10.77.0.0/24,hostfwd=tcp:127.0.0.1:22220-:22,hostfwd=tcp:127.0.0.1:8787-:8080 \
    -device virtio-net-pci,netdev=vmnet,mac=52:54:00:73:80:01
