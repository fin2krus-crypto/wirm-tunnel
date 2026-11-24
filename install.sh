#!/usr/bin/env bash
set -euo pipefail

REPO_DEFAULT="n0nam4ik/wirm-tunnel"
REPO="${WINRM_REPO:-$REPO_DEFAULT}"
PORT="${WINRM_PORT:-5986}"
WEB_PORT="${WINRM_WEB_PORT:-49777}"

BIN_PATH="/usr/local/bin/winrm-vpn-server"
CFG_DIR="/etc/winrm-vpn"
ENV_FILE="${CFG_DIR}/config.env"
SERVICE_FILE="/etc/systemd/system/winrm-vpn.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  WinRM-VPN Server v0.3.0 — Автоустановка (Debian 12 / 13)  ${NC}"
echo -e "${CYAN}============================================================${NC}"

if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}[ОШИБКА] Запустите скрипт от имени root (sudo bash).${NC}"
    exit 1
fi

if [[ ! -f /etc/os-release ]]; then
    echo -e "${RED}[ОШИБКА] Файл /etc/os-release не найден. Невозможно определить ОС.${NC}"
    exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
OS_ID="${ID:-unknown}"
OS_VER_MAJOR="${VERSION_ID%%.*}"

if [[ "${OS_ID}" != "debian" ]] || [[ "${OS_VER_MAJOR}" != "12" && "${OS_VER_MAJOR}" != "13" ]]; then
    echo -e "${RED}[ОШИБКА] Неподдерживаемая ОС: ${PRETTY_NAME:-$OS_ID $VERSION_ID}.${NC}"
    echo -e "${RED}         Скрипт поддерживает только Debian 12 (Bookworm) и Debian 13 (Trixie).${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Обнаружена поддерживаемая ОС: ${PRETTY_NAME}${NC}"

ARCH="$(uname -m)"
if [[ "${ARCH}" != "x86_64" ]]; then
    echo -e "${RED}[ОШИБКА] Требуется архитектура x86_64, обнаружена: ${ARCH}.${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Проверка зависимостей (curl, openssl, ca-certificates, iputils-ping)...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl openssl ca-certificates iputils-ping >/dev/null

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/winrm-vpn-server"
echo -e "${YELLOW}[*] Скачивание winrm-vpn-server из ${DOWNLOAD_URL}...${NC}"

systemctl stop winrm-vpn 2>/dev/null || true

CURL_AUTH_ARGS=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    CURL_AUTH_ARGS=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

if ! curl -fSL --retry 3 "${CURL_AUTH_ARGS[@]}" "${DOWNLOAD_URL}" -o "${BIN_PATH}.tmp"; then
    rm -f "${BIN_PATH}.tmp"
    echo -e "${RED}[ОШИБКА] Не удалось скачать бинарник по адресу ${DOWNLOAD_URL}.${NC}"
    exit 1
fi

mv -f "${BIN_PATH}.tmp" "${BIN_PATH}"
chmod 755 "${BIN_PATH}"
echo -e "${GREEN}[OK] Установлен исполняемый файл: ${BIN_PATH}${NC}"

mkdir -p "${CFG_DIR}"
chmod 700 "${CFG_DIR}"

PSK="$(openssl rand -hex 24)"
cat << EOF > "${ENV_FILE}"
WINRM_PSK="${PSK}"
WINRM_LISTEN="0.0.0.0:${PORT}"
EOF
chmod 600 "${ENV_FILE}"

echo "net.ipv4.tcp_timestamps = 0" > /etc/sysctl.d/99-winrm-vpn.conf
sysctl -q -p /etc/sysctl.d/99-winrm-vpn.conf || true

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "${PORT}/tcp" >/dev/null
    ufw allow "${WEB_PORT}/tcp" >/dev/null
    echo -e "${GREEN}[OK] Открыты порты ${PORT}/tcp (VPN) и ${WEB_PORT}/tcp (Веб-панель) в UFW${NC}"
fi

cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=WinRM-VPN Server v0.3.0
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

systemctl daemon-reload
systemctl enable winrm-vpn >/dev/null 2>&1
systemctl restart winrm-vpn

echo -e "${YELLOW}[*] Проверка запуска службы и веб-панели...${NC}"
for _ in $(seq 1 15); do
    if [[ -f "${CFG_DIR}/winrm_cert.pem" ]] && systemctl is-active --quiet winrm-vpn; then
        break
    fi
    sleep 1
done

if ! systemctl is-active --quiet winrm-vpn; then
    echo -e "${RED}[ОШИБКА] Служба winrm-vpn не запустилась! Логи:${NC}"
    journalctl -u winrm-vpn -n 30 --no-pager
    exit 1
fi

IDENT_RESP="$(curl -sk --max-time 5 --tlsv1.3 --tls13-ciphers TLS_AES_256_GCM_SHA384 -X POST "https://127.0.0.1:${PORT}/wsman" \
    -H "Content-Type: application/soap+xml;charset=UTF-8" \
    -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>' || true)"

if ! echo "${IDENT_RESP}" | grep -q "Microsoft Corporation"; then
    echo -e "${RED}[ОШИБКА] Проверка WS-Man Identify не пройдена!${NC}"
    exit 1
fi

if ! curl -fsS --max-time 5 "http://127.0.0.1:${WEB_PORT}/api/stats" | grep -q "0.3.0"; then
    echo -e "${RED}[ОШИБКА] Веб-панель на порту ${WEB_PORT} не отвечает!${NC}"
    exit 1
fi

CERT_PIN="$(openssl x509 -in "${CFG_DIR}/winrm_cert.pem" -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
SERVER_IP="$(curl -4 -fsS --max-time 5 https://ifconfig.io/ip 2>/dev/null || curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}  УСТАНОВКА WINRM-VPN SERVER v0.3.0 УСПЕШНО ЗАВЕРШЕНА!          ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "  Веб-панель : ${CYAN}http://${SERVER_IP}:${WEB_PORT}${NC}"
echo -e "  Server IP  : ${GREEN}${SERVER_IP}:${PORT}${NC}"
echo -e "  PSK        : ${GREEN}${PSK}${NC}"
echo -e "  Cert Pin   : ${GREEN}${CERT_PIN}${NC}"
echo ""
echo -e "  CLI-меню   : ${CYAN}winrm-vpn-server${NC}"
echo -e "${GREEN}================================================================${NC}"
