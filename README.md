# WinRM-VPN (Server v0.4.4 / Clients v0.4.4)

Стелс-VPN для тестирования DPI-систем с мимикрией под **Ansible (`pywinrm` / OpenSSL 3.x)** и **Windows Server 2022/2025 WinRM over HTTPS (`5986/TCP`)**.

## Быстрая установка и обновление сервера (Debian 12 / 13)

Установка:

    curl -fsSL https://raw.githubusercontent.com/n0nam4ik/wirm-tunnel/main/install.sh | sudo bash

Обновление без потери пользователей и сертификата:

    curl -fsSL https://raw.githubusercontent.com/n0nam4ik/wirm-tunnel/main/update.sh | sudo bash

## Ключевые технологии (v0.4.4 / v0.4.4)

- **2-канальный WinRM HTTP/1.1 (Send + Receive):** канонический полудуплекс `POST /wsman -> 200 OK` на отправку + `Transfer-Encoding: chunked` с ротацией 55-85 сек на приём и плановой ротацией сокетов каждые 10-15 мин.
- **Коалесирующий батчинг 3 мс и выравнивание под MSS:** склейка мелких пакетов/ACK и естественный SOAP-паддинг без лишних PSH,ACK.
- **Фронтенд OpenSSL 3 (tokio-openssl):** поддержка TLS 1.2 CBC (как Schannel), отключение ChaCha20 и ALPN h2.
- **eBPF SYN,ACK фильтр (tc):** на порту 5986 выравнивает порядок TCP-опций и `WScale = 8` под Windows Server 2022 (не затрагивает другие сервисы).
- **Штатный TLS close_notify**, пассивный WinRM Watchdog (без фонового ICMP ping) и встроенная мобильно-адаптированная **веб-панель** (`:49777`) + интерактивное CLI-меню (`winrm-vpn-server`).
- **Клиенты:** Android APK (плитка быстрых настроек, автоскролл логов), macOS Universal `.app` (Apple Silicon + Intel), Linux `x86_64` GUI (Fyne).
