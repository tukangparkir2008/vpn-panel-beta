#!/bin/bash
# =================================================================
# VPN Auto Installer - Full (No Xray)
# Stunnel(443)+WS(80/8080)+OpenVPN
# Usage: sudo bash vpn_installer_ws_ovpn_full.sh
# =================================================================
set -e
msg_info(){ echo -e "\n\e[1;33m[*] $1\e[0m"; }
msg_ok(){ echo -e "\n\e[1;32m[+] $1\e[0m"; }
msg_err(){ echo -e "\n\e[1;31m[!] $1\e[0m"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then msg_err "This script must be run as root."; fi

clear
echo -e "\n\e[1;35m==============================================\e[0m"
echo -e "  \e[1;36mVPN Auto Installer - WS + OVPN (No Xray)\e[0m"
echo -e "\e[1;35m==============================================\e[0m"

read -p "➡️  Enter domain/subdomain (server_name): " DOMAIN
read -p "➡️  Enter email for Let's Encrypt: " LETSENCRYPT_EMAIL
[ -z "$DOMAIN" ] && msg_err "Domain required."
[ -z "$LETSENCRYPT_EMAIL" ] && msg_err "Email required."

echo "$DOMAIN" > /root/domain

export DEBIAN_FRONTEND=noninteractive

msg_info "Updating system and installing packages..."
#apt-get update -y && apt-get upgrade -y
apt-get install -y sudo curl ca-certificates lsb-release gnupg \
  software-properties-common build-essential cmake make gcc git net-tools iproute2 iptables ufw \
  nginx stunnel4 dropbear certbot cron easy-rsa openvpn

# If node not present or old, install Node.js 20.x
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | cut -d. -f1 | tr -d v)" -lt 16 ]; then
  msg_info "Installing Node.js v20..."
  # FIX: Remove existing nodejs and libnode-dev to prevent conflict before installing from Nodesource.
  apt-get remove -y nodejs libnode-dev || true
  apt-get autoremove -y || true

  apt-get install -y ca-certificates curl gnupg
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
  apt-get update
  apt-get install -y nodejs
fi

# Remove xray if exists (best-effort)
if systemctl list-units --full -all | grep -q "xray"; then
  msg_info "Disabling and removing xray to avoid conflicts..."
  systemctl stop xray || true
  systemctl disable xray || true
  rm -f /usr/local/etc/xray/config.json || true
fi

# UFW rules
msg_info "Configuring firewall (ufw)..."
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 8080/tcp
ufw allow 443/tcp
ufw allow 1194/udp
ufw allow 1194/tcp
ufw allow 7300/udp
ufw --force enable
ufw reload

# Dropbear config (local SSH for stunnel/WS)
DROPBEAR_PORT=2253
msg_info "Configuring Dropbear on port ${DROPBEAR_PORT}..."
apt-get install -y dropbear
cat > /etc/default/dropbear <<EOF
NO_START=0
DROPBEAR_PORT=${DROPBEAR_PORT}
DROPBEAR_EXTRA_ARGS=""
EOF
systemctl restart dropbear && systemctl enable dropbear

# Obtain Letsencrypt certificate (standalone)
msg_info "Obtaining Let's Encrypt certificate for ${DOMAIN}..."
systemctl stop nginx || true
systemctl stop stunnel4 || true
certbot certonly --standalone --agree-tos --no-eff-email --email "$LETSENCRYPT_EMAIL" -d "$DOMAIN"
CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

# Build BadVPN udpgw
msg_info "Building BadVPN (udpgw)..."
cd /root
if [ ! -d "badvpn" ]; then git clone https://github.com/ambrop72/badvpn.git || git clone https://github.com/XTLS/badvpn.git; fi
cd badvpn || true
mkdir -p build
cd build || true
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j"$(nproc)" || true
make install || true

cat > /etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target
[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 512
User=root
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now badvpn.service || true

# Install ws2tcp (Node.js) - WebSocket <-> TCP + HTTP CONNECT support
msg_info "Installing WebSocket-to-TCP proxy (ws2tcp)..."
mkdir -p /opt/ws2tcp
cat > /opt/ws2tcp/package.json <<'EOF'
{
  "name": "ws2tcp",
  "version": "1.0.0",
  "dependencies": { "ws": "*" }
}
EOF

cat > /opt/ws2tcp/ws2tcp.js <<'EOF'
#!/usr/bin/env node
const http = require('http');
const WebSocket = require('ws');
const net = require('net');

const LISTEN_HOST = '127.0.0.1';
const LISTEN_PORT = 10005;
const DEFAULT_TARGET_HOST = '127.0.0.1';
const DEFAULT_TARGET_PORT = Number(process.env.TARGET_PORT) || 2253;

// HTTP server: support CONNECT tunneling + respond to plain GET/POST (so injectors that send GET/POST won't hang)
const server = http.createServer((req, res) => {
  if (req.method === 'GET' || req.method === 'POST' || req.method === 'PUT') {
    // Many injectors send a fake HTTP then upgrade to WS; we reply 200 OK to avoid timeout (some clients expect 200 then switch)
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('OK');
    return;
  }
  res.writeHead(405);
  res.end();
});

server.on('connect', (req, clientSocket, head) => {
  // req.url is host:port
  const hostport = req.url.split(':');
  const host = hostport[0] || DEFAULT_TARGET_HOST;
  const port = parseInt(hostport[1],10) || DEFAULT_TARGET_PORT;
  const srv = net.connect(port, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) srv.write(head);
    srv.pipe(clientSocket);
    clientSocket.pipe(srv);
  });
  srv.on('error', () => clientSocket.end());
});

const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws, req) => {
  const socket = net.connect(DEFAULT_TARGET_PORT, DEFAULT_TARGET_HOST, () => {});
  socket.on('data', (d) => { if (ws.readyState === WebSocket.OPEN) ws.send(d); });
  socket.on('close', () => { try{ ws.close(); }catch(e){} });
  socket.on('error', () => { try{ ws.terminate(); }catch(e){} });

  ws.on('message', (msg) => {
    if (socket.writable) socket.write(msg);
  });
  ws.on('close', () => socket.end());
  ws.on('error', () => socket.end());
});

server.on('upgrade', (req, socket, head) => {
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(`ws2tcp listening ${LISTEN_HOST}:${LISTEN_PORT} -> ${DEFAULT_TARGET_HOST}:${DEFAULT_TARGET_PORT}`);
});
EOF

cd /opt/ws2tcp
npm install --production --silent || true
chmod +x ws2tcp.js

cat > /etc/systemd/system/ws2tcp.service <<EOF
[Unit]
Description=WebSocket to TCP proxy (ws2tcp)
After=network.target
[Service]
Environment="TARGET_HOST=127.0.0.1"
Environment="TARGET_PORT=${DROPBEAR_PORT}"
ExecStart=/usr/bin/node /opt/ws2tcp/ws2tcp.js
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ws2tcp.service || true

# Nginx config (80 + 8080) tuned to accept large headers and proxy to ws2tcp
msg_info "Configuring nginx (80,8080) for WS and long headers..."
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/*.conf || true

cat > /etc/nginx/conf.d/main_config.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    client_max_body_size 50M;
    client_body_buffer_size 128k;
    large_client_header_buffers 8 32k;
    proxy_buffer_size 128k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;

    # Universal location for both WebSocket upgrade and standard proxying
    location / {
        proxy_pass http://127.0.0.1:10005;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade"; # FIX: Use "upgrade" directly for reliability
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}

server {
    listen 8080;
    listen [::]:8080;
    server_name ${DOMAIN};

    client_max_body_size 50M;
    client_body_buffer_size 128k;
    large_client_header_buffers 8 32k;
    proxy_buffer_size 128k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;

    location / {
        proxy_pass http://127.0.0.1:10005;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade"; # FIX: Use "upgrade" directly for reliability
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

nginx -t && systemctl restart nginx || true

# Stunnel config (443 -> Dropbear)
msg_info "Configuring stunnel (443 -> ${DROPBEAR_PORT})..."
cat > /etc/stunnel/stunnel.conf <<EOF
pid = /var/run/stunnel4/stunnel.pid
cert = $CERT_PATH
key = $KEY_PATH
client = no
[ssh_ssl]
accept = 443
connect = 127.0.0.1:${DROPBEAR_PORT}
EOF
sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 || true
systemctl enable stunnel4
systemctl restart stunnel4 || true

# OpenVPN basic setup (TCP 8080 and UDP 1194)
msg_info "Setting up OpenVPN (basic) - TCP 8080 and UDP 1194..."
EASYRSA_DIR="/etc/openvpn/easy-rsa"
make-cadir $EASYRSA_DIR
cd $EASYRSA_DIR
EASYRSA_BATCH=1 ./easyrsa init-pki
EASYRSA_BATCH=1 ./easyrsa build-ca nopass
EASYRSA_BATCH=1 ./easyrsa gen-req server nopass
EASYRSA_BATCH=1 ./easyrsa sign-req server server
EASYRSA_BATCH=1 ./easyrsa gen-dh
mkdir -p /etc/openvpn
cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem /etc/openvpn || true

cat > /etc/openvpn/server-8080.conf <<EOF
port 8080
proto tcp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
cipher AES-128-CBC
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
EOF

cat > /etc/openvpn/server-1194.conf <<EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
server 10.9.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
cipher AES-128-CBC
persist-key
persist-tun
status /var/log/openvpn-status-udp.log
verb 3
EOF

systemctl enable openvpn@server-8080 || true
systemctl enable openvpn@server-1194 || true
systemctl start openvpn@server-8080 || true
systemctl start openvpn@server-1194 || true

# Create a simple menu (no xray)
msg_info "Creating simple menu at /usr/local/bin/menu ..."
cat > /usr/local/bin/menu <<'EOF'
#!/bin/bash
DOMAIN=$(cat /root/domain 2>/dev/null || echo "unknown")
echo "======================================="
echo " Simple VPN Menu (No Xray)"
echo " Domain: $DOMAIN"
echo "======================================="
echo "1) Create local SSH user"
echo "2) Create OpenVPN client (.ovpn) (basic)"
echo "3) Renew SSL cert (certbot)"
echo "4) Restart services (nginx, stunnel4, ws2tcp, dropbear, openvpn)"
echo "0) Exit"
read -p "Choose: " opt
case $opt in
  1)
    read -p "Username: " u
    read -p "Days valid: " d
    if [ -z "$u" ]; then echo 'Username empty'; exit 1; fi
    useradd -m -s /bin/bash "$u"
    passwd "$u"
    exp=$(date -d "+$d days" +%Y-%m-%d 2>/dev/null)
    chage -E "$exp" "$u"
    echo "User $u created, expires: $exp"
    ;;
  2)
    read -p "Client name: " cname
    if [ -z "$cname" ]; then echo 'Name empty'; exit 1; fi
    # Generate a client cert/key (quick & insecure: nopass)
    EASYRSA_DIR="/etc/openvpn/easy-rsa"
    cd "$EASYRSA_DIR"
    EASYRSA_BATCH=1 ./easyrsa gen-req "$cname" nopass
    EASYRSA_BATCH=1 ./easyrsa sign-req client "$cname"
    mkdir -p /root/ovpn
    cat > /root/ovpn/${cname}.ovpn <<OV
client
dev tun
proto tcp
remote ${DOMAIN} 8080
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
remote-cert-tls server
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/pki/issued/${cname}.crt 2>/dev/null || echo "NO_CERT")
</cert>
<key>
$(cat /etc/openvpn/pki/private/${cname}.key 2>/dev/null || echo "NO_KEY")
</key>
key-direction 1
auth SHA256
OV
    echo "OVPN client saved: /root/ovpn/${cname}.ovpn"
    ;;
  3)
    systemctl stop nginx; systemctl stop stunnel4
    certbot renew --force-renewal
    systemctl start nginx; systemctl start stunnel4
    echo "Cert renewed."
    ;;
  4)
    systemctl restart nginx stunnel4 ws2tcp dropbear openvpn@server-8080 openvpn@server-1194
    echo "Services restarted."
    ;;
  0) exit 0 ;;
  *) echo "Invalid" ;;
esac
EOF

chmod +x /usr/local/bin/menu

# Auto-run menu on SSH login (if not already)
BASHRC_FILE="/root/.bashrc"
if ! grep -q "/usr/local/bin/menu" "$BASHRC_FILE"; then
  echo -e '\nif [ -n "$SSH_TTY" ]; then\n  /usr/local/bin/menu\nfi' >> "$BASHRC_FILE"
fi

# Cron clear-expired placeholder (optional)
cat > /usr/local/bin/clear-expired <<'EOF'
#!/bin/bash
# placeholder: remove expired local users (example)
today=$(date +%s)
awk -F: '($3>=1000){print $1}' /etc/passwd | while read u; do
  exp=$(chage -l "$u" 2>/dev/null | grep "Account expires" | cut -d: -f2-)
  if [[ "$exp" == " never" || -z "$exp" ]]; then continue; fi
  if date -d "$exp" +%s >/dev/null 2>&1; then
    if [ $(date -d "$exp" +%s) -lt $today ]; then
      userdel -r "$u" 2>/dev/null || true
    fi
  fi
done
EOF
chmod +x /usr/local/bin/clear-expired
(crontab -l 2>/dev/null | grep -v "clear-expired"; echo "0 4 * * * /usr/local/bin/clear-expired") | crontab -

msg_ok "INSTALLATION COMPLETE"

cat <<EOF
=====================================================
CONFIG SUMMARY:
 - 443 (SSL) : stunnel -> dropbear (SSH)
 - 80  (WS)  : nginx -> ws2tcp -> dropbear (supports GET/POST/PUT/CONNECT as proxy)
 - 8080 (WS/TCP): nginx -> ws2tcp OR OpenVPN TCP (8080)
 - 1194 (UDP): OpenVPN UDP
 - 7300 (UDP): BadVPN UDPGW
Menu: /usr/local/bin/menu
OpenVPN client .ovpn files stored in /root/ovpn/
=====================================================
EOF

exit 0
