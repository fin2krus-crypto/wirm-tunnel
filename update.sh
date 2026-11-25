#!/usr/bin/env bash
set -euo pipefail

REPO="n0nam4ik/wirm-tunnel"
BIN_PATH="/usr/local/bin/winrm-vpn-server"
SERVICE_NAME="winrm-vpn"

[[ "${EUID}" -ne 0 ]] && echo "[ОШИБКА] Запустите от root." && exit 1
[[ "$(uname -m)" != "x86_64" ]] && echo "[ОШИБКА] Нужен x86_64." && exit 1
[[ ! -f "${BIN_PATH}" && -f "/root/winrm-vpn-server" ]] && BIN_PATH="/root/winrm-vpn-server"

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/winrm-vpn-server"
CURL_AUTH_ARGS=()
[[ -n "${GITHUB_TOKEN:-}" ]] && CURL_AUTH_ARGS=(-H "Authorization: Bearer ${GITHUB_TOKEN}")

TMP_BIN="$(mktemp)"
curl -fSL --retry 3 "${CURL_AUTH_ARGS[@]}" "${DOWNLOAD_URL}" -o "${TMP_BIN}"
chmod 755 "${TMP_BIN}"

systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
mv -f "${TMP_BIN}" "${BIN_PATH}"
systemctl daemon-reload && systemctl start "${SERVICE_NAME}"
sleep 2
systemctl is-active --quiet "${SERVICE_NAME}" || { journalctl -u "${SERVICE_NAME}" -n 25 --no-pager; exit 1; }
echo "[OK] WinRM-VPN Server обновлён до последней версии!"
