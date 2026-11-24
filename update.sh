#!/usr/bin/env bash
set -euo pipefail

REPO_DEFAULT="n0nam4ik/wirm-tunnel"
REPO="${WINRM_REPO:-$REPO_DEFAULT}"
BIN_PATH="/usr/local/bin/winrm-vpn-server"
SERVICE_NAME="winrm-vpn"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}        WinRM-VPN Server — Скрипт обновления               ${NC}"
echo -e "${CYAN}============================================================${NC}"

# 1. Проверка прав root
if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}[ОШИБКА] Запустите скрипт от имени root (sudo bash).${NC}"
    exit 1
fi

# 2. Проверка архитектуры
ARCH="$(uname -m)"
if [[ "${ARCH}" != "x86_64" ]]; then
    echo -e "${RED}[ОШИБКА] Требуется архитектура x86_64, обнаружена: ${ARCH}.${NC}"
    exit 1
fi

# 3. Определение пути к установленному бинарнику
if [[ ! -f "${BIN_PATH}" ]]; then
    if [[ -f "/root/winrm-vpn-server" ]]; then
        BIN_PATH="/root/winrm-vpn-server"
    else
        echo -e "${YELLOW}[!] Бинарник не найден в ${BIN_PATH}. Будет произведена установка в ${BIN_PATH}.${NC}"
    fi
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/winrm-vpn-server"
echo -e "${YELLOW}[*] Скачивание последнего релиза из ${DOWNLOAD_URL}...${NC}"

CURL_AUTH_ARGS=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    CURL_AUTH_ARGS=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

TMP_BIN="$(mktemp)"
if ! curl -fSL --retry 3 "${CURL_AUTH_ARGS[@]}" "${DOWNLOAD_URL}" -o "${TMP_BIN}"; then
    rm -f "${TMP_BIN}"
    echo -e "${RED}[ОШИБКА] Не удалось скачать обновление по адресу ${DOWNLOAD_URL}.${NC}"
    echo -e "${YELLOW}Подсказка: если репозиторий приватный, передайте токен: GITHUB_TOKEN=ghp_...${NC}"
    exit 1
fi

chmod 755 "${TMP_BIN}"

# 4. Остановка службы перед заменой файла
echo -e "${YELLOW}[*] Остановка службы ${SERVICE_NAME}...${NC}"
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true

# 5. Замена бинарника
mv -f "${TMP_BIN}" "${BIN_PATH}"
echo -e "${GREEN}[OK] Бинарник успешно обновлён: ${BIN_PATH}${NC}"

# 6. Запуск службы и проверка
echo -e "${YELLOW}[*] Перезапуск службы ${SERVICE_NAME}...${NC}"
systemctl daemon-reload
systemctl start "${SERVICE_NAME}"

sleep 2
if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo -e "${RED}[ОШИБКА] Служба не запустилась после обновления! Логи:${NC}"
    journalctl -u "${SERVICE_NAME}" -n 25 --no-pager
    exit 1
fi

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}  ОБНОВЛЕНИЕ УСПЕШНО ЗАВЕРШЕНО!                                 ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "  Статус:       ${GREEN}active (running)${NC}"
echo -e "  Программа:    ${CYAN}${BIN_PATH}${NC}"
echo -e "  Конфигурация: ${CYAN}сохранена (PSK и сертификаты не затронуты)${NC}"
echo ""
echo -e "Полезные команды:"
echo -e "  Статус: ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
echo -e "  Логи:   ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
echo -e "${GREEN}================================================================${NC}"
