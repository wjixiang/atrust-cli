#!/bin/bash
set -euo pipefail
test -f /etc/atrust-vm-isolated
export DEBIAN_FRONTEND=noninteractive
# Recover a previous interrupted desktop installation before apt configures it.
if dpkg-query -W cn.com.sangfor.atrust >/dev/null 2>&1; then
    dpkg --remove --force-remove-reinstreq cn.com.sangfor.atrust || true
fi
apt-get update
apt-get install -y --no-install-recommends python3 ca-certificates iptables \
    libgtk-3-0 libnss3 libxss1 libasound2 libnotify4 libgconf-2-4 libatomic1 \
    libcurl4 libx11-xcb1 libxtst6 libqt5core5a libqt5dbus5 libqt5network5 libqt5widgets5
# The desktop installer hooks kill browsers and require installer-name metadata.
# As with the Arch package, unpack the official payload and register only its
# background service. Authentication remains the controller's normal flow.
dpkg-deb -x /tmp/atrust.deb /
rm -f /usr/share/sangfor/aTrust/resources/lib/libstdc++.so.6 \
    /usr/share/sangfor/aTrust/uem/lib/libstdc++.so.6
ln -sf libcurl.so /usr/share/sangfor/aTrust/resources/bin/libcurl.so.4
install -d -m 777 /usr/share/sangfor/.aTrust
mkdir -p /etc/systemd/system/aTrustDaemon.service.d
cat > /etc/systemd/system/aTrustDaemon.service.d/10-libs.conf <<'EOF'
[Service]
Environment=LD_LIBRARY_PATH=/usr/share/sangfor/aTrust/resources/bin:/usr/share/sangfor/aTrust/resources/lib:/usr/share/sangfor/aTrust/uem/bin:/usr/share/sangfor/aTrust/uem/lib
EOF
cat > /usr/local/bin/atrust-cli <<'EOF'
#!/bin/sh
export PYTHONPATH=/opt/atrust-cli/src
exec python3 -m atrust_cli "$@"
EOF
chmod 755 /usr/local/bin/atrust-cli
cat > /etc/systemd/system/atrust-core.service <<'EOF'
[Unit]
Description=aTrust headless user core (isolated VM)
After=aTrustDaemon.service network-online.target
Requires=aTrustDaemon.service
[Service]
Type=simple
User=atrust
WorkingDirectory=/usr/share/sangfor/aTrust/resources/bin
Environment=LD_LIBRARY_PATH=/usr/share/sangfor/aTrust/resources/bin:/usr/share/sangfor/aTrust/resources/lib:/usr/share/sangfor/aTrust/uem/bin:/usr/share/sangfor/aTrust/uem/lib
ExecStart=/usr/share/sangfor/aTrust/resources/bin/aTrustAgent --plugin plugins/aTrustCore --enable-http --enable-event-center
Restart=on-failure
RestartSec=3
UMask=0022
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/atrust-web.service <<'EOF'
[Unit]
Description=aTrust isolated VM management
After=network-online.target atrust-core.service
Wants=atrust-core.service
Wants=network-online.target
[Service]
Type=simple
User=atrust
Environment=PYTHONPATH=/opt/atrust-cli/src
Environment=XDG_STATE_HOME=/home/atrust/.local/state
ExecStart=/usr/bin/python3 -m atrust_cli.web --listen 0.0.0.0 --port 8080 --allow-tunnel
Restart=on-failure
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/home/atrust/.local/state
[Install]
WantedBy=multi-user.target
EOF
install -d -m 700 -o atrust -g atrust /home/atrust/.local/state
systemctl daemon-reload
systemctl enable --now aTrustDaemon atrust-core atrust-web
rm -f /tmp/atrust.deb
