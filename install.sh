#!/usr/bin/env bash
set -euo pipefail

REPO="n0nam4ik/wirm-tunnel"
PORT="${WINRM_PORT:-5986}"
WEB_PORT="${WINRM_WEB_PORT:-49777}"
BIN_PATH="/usr/local/bin/winrm-vpn-server"
CFG_DIR="/etc/winrm-vpn"
ENV_FILE="${CFG_DIR}/config.env"
SERVICE_FILE="/etc/systemd/system/winrm-vpn.service"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}=== WinRM-VPN Server v0.4.5 — Автоустановка (Debian 12 / 13) ===${NC}"
[[ "${EUID}" -ne 0 ]] && echo -e "${RED}[ОШИБКА] Запустите от root.${NC}" && exit 1
[[ ! -f /etc/os-release ]] && echo -e "${RED}[ОШИБКА] Нет /etc/os-release.${NC}" && exit 1
source /etc/os-release
OS_VER_MAJOR="${VERSION_ID%%.*}"
if [[ "${ID:-}" != "debian" ]] || [[ "${OS_VER_MAJOR}" != "12" && "${OS_VER_MAJOR}" != "13" ]]; then
    echo -e "${RED}[ОШИБКА] Поддерживаются только Debian 12 и Debian 13.${NC}"; exit 1
fi
[[ "$(uname -m)" != "x86_64" ]] && echo -e "${RED}[ОШИБКА] Нужен x86_64.${NC}" && exit 1

apt-get update -qq && apt-get install -y -qq curl openssl ca-certificates iputils-ping iproute2 >/dev/null
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/winrm-vpn-server"
systemctl stop winrm-vpn 2>/dev/null || true

CURL_AUTH_ARGS=()
[[ -n "${GITHUB_TOKEN:-}" ]] && CURL_AUTH_ARGS=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
curl -fSL --retry 3 "${CURL_AUTH_ARGS[@]}" "${DOWNLOAD_URL}" -o "${BIN_PATH}.tmp"
mv -f "${BIN_PATH}.tmp" "${BIN_PATH}" && chmod 755 "${BIN_PATH}"

mkdir -p "${CFG_DIR}" && chmod 700 "${CFG_DIR}"
PSK="$(openssl rand -hex 24)"
printf 'WINRM_PSK="%s"\nWINRM_LISTEN="0.0.0.0:%s"\n' "${PSK}" "${PORT}" > "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

cat << 'EOF' > /etc/sysctl.d/99-winrm-vpn.conf
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rmem = 4096 131072 12582912
EOF
sysctl -q -p /etc/sysctl.d/99-winrm-vpn.conf || true

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "${PORT}/tcp" >/dev/null
    ufw allow "${WEB_PORT}/tcp" >/dev/null
fi

cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=WinRM-VPN Server v0.4.5
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${CFG_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH} -listen \${WINRM_LISTEN} -psk \${WINRM_PSK}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload && systemctl enable winrm-vpn >/dev/null 2>&1 && systemctl restart winrm-vpn
for _ in $(seq 1 15); do
    [[ -f "${CFG_DIR}/winrm_cert.pem" ]] && systemctl is-active --quiet winrm-vpn && break
    sleep 1
done
systemctl is-active --quiet winrm-vpn || { journalctl -u winrm-vpn -n 30 --no-pager; exit 1; }

curl -sk --max-time 5 --tlsv1.3 --tls13-ciphers TLS_AES_256_GCM_SHA384 -X POST "https://127.0.0.1:${PORT}/wsman" \
    -H "Content-Type: application/soap+xml;charset=UTF-8" \
    -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>' | grep -q "Microsoft Corporation"
curl -fsS --max-time 5 "http://127.0.0.1:${WEB_PORT}/api/stats" | grep -q "0.4.5"

CERT_PIN="$(openssl x509 -in "${CFG_DIR}/winrm_cert.pem" -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
SERVER_IP="$(curl -4 -fsS --max-time 5 https://ifconfig.io/ip 2>/dev/null || hostname -I | awk '{print $1}')"

echo -e "\n${GREEN}УСТАНОВКА WINRM-VPN SERVER v0.4.5 ЗАВЕРШЕНА!${NC}"
echo -e "  Веб-панель : ${CYAN}http://${SERVER_IP}:${WEB_PORT}${NC}"
echo -e "  Server IP  : ${GREEN}${SERVER_IP}:${PORT}${NC}"
echo -e "  PSK        : ${GREEN}${PSK}${NC}"
echo -e "  Cert Pin   : ${GREEN}${CERT_PIN}${NC}"
echo -e "  CLI-меню   : ${CYAN}winrm-vpn-server${NC}"
