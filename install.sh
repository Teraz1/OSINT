#!/bin/bash
# ============================================================
# OSINT & VULNERABILITY SYSTEM v3 — Rocky Linux Installer
# ============================================================
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
error()  { echo -e "${RED}[-]${NC} $1"; exit 1; }
hdr()    { echo -e "\n${CYAN}══════ $1 ══════${NC}"; }

[ "$EUID" -ne 0 ] && error "Run as root: sudo bash install.sh"

hdr "System Update"
dnf update -y
dnf install -y epel-release
dnf install -y \
    python3 python3-pip python3-devel \
    nmap git curl wget unzip tar jq \
    gcc gcc-c++ make ruby ruby-devel \
    golang sqlite redis

hdr "Python Dependencies"
pip3 install --break-system-packages \
    fastapi uvicorn[standard] aiofiles python-multipart \
    aiohttp dnspython python-whois sqlalchemy aiosqlite \
    pydantic pyyaml reportlab

log "Python packages installed."

hdr "Subfinder"
cd /tmp
SF_VER=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | jq -r .tag_name)
wget -q "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_${SF_VER#v}_linux_amd64.zip" -O subfinder.zip
unzip -o subfinder.zip subfinder -d /usr/local/bin/ && chmod +x /usr/local/bin/subfinder
log "Subfinder installed."

hdr "Nuclei"
cd /tmp
N_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name)
wget -q "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${N_VER#v}_linux_amd64.zip" -O nuclei.zip
unzip -o nuclei.zip nuclei -d /usr/local/bin/ && chmod +x /usr/local/bin/nuclei
nuclei -update-templates -silent && log "Nuclei + templates installed."

hdr "Amass"
cd /tmp
wget -q "https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip" -O amass.zip
unzip -o amass.zip -d amass_dir
find amass_dir -name amass -type f -exec cp {} /usr/local/bin/ \;
chmod +x /usr/local/bin/amass
log "Amass installed."

hdr "theHarvester"
[ ! -d "/opt/theHarvester" ] && git clone https://github.com/laramies/theHarvester.git /opt/theHarvester
pip3 install --break-system-packages -r /opt/theHarvester/requirements/base.txt
log "theHarvester installed."

hdr "WhatWeb"
gem install whatweb 2>/dev/null && log "WhatWeb installed." || warn "WhatWeb failed — skip."

hdr "Redis"
systemctl enable redis --now
log "Redis running."

hdr "Firewall"
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=8080/tcp
    firewall-cmd --reload && log "Port 8080 opened."
fi

hdr "Deploy Files"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p /opt/osint-system
cp -r "$SRC_DIR"/* /opt/osint-system/
chown -R root:root /opt/osint-system
log "Files deployed to /opt/osint-system"

hdr "Systemd Service"
cat > /etc/systemd/system/osint-system.service << 'EOF'
[Unit]
Description=OSINT & Vulnerability System v3
After=network.target redis.service

[Service]
Type=simple
WorkingDirectory=/opt/osint-system
ExecStart=/usr/bin/python3 /opt/osint-system/backend.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
log "Service created."

hdr "Done!"
echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   OSINT System v3 — Installation Done   ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Start:  ${CYAN}systemctl start osint-system${NC}"
echo -e "  Open:   ${CYAN}http://$(hostname -I | awk '{print $1}'):8080${NC}"
echo -e "  Login:  ${CYAN}admin / admin123${NC}  ${RED}← CHANGE THIS!${NC}"
echo ""
echo -e "  Config: ${CYAN}/opt/osint-system/config.yaml${NC}"
echo -e "  Logs:   ${CYAN}journalctl -u osint-system -f${NC}"
echo ""
