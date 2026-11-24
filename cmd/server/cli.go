package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultGitHubRepo = "n0nam4ik/wirm-tunnel"

const serverAsciiLogo = `   __        ___       ____  __  __    __     ______  _   _
   \ \      / (_)_ __ |  _ \|  \/  |   \ \   / /  _ \| \ | |
    \ \ /\ / /| | '_ \| |_) | |\/| |____\ \ / /| |_) |  \| |
     \ V  V / | | | | |  _ <| |  | |_____\ V / |  __/| |\  |
      \_/\_/  |_|_| |_|_| \_\_|  |_|      \_/  |_|   |_| \_|`

func runInteractiveCLI() {
	dataDir := resolveDataDir("")
	scanner := bufio.NewScanner(os.Stdin)
	cachedExtIP := fetchExternalIP()

	for {
		snap := getDashboardSnapshot(dataDir)
		printDashboard(snap, cachedExtIP, dataDir)

		fmt.Print("Выберите пункт [0-9]: ")
		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			menuHelp(scanner)
		case "2":
			menuListUsers(scanner, dataDir)
		case "3":
			menuAddUser(scanner, dataDir)
		case "4":
			menuDeleteUser(scanner, dataDir)
		case "5":
			menuUpdateServer(scanner)
		case "6":
			menuStartServer(scanner, dataDir)
		case "7":
			menuStopServer(scanner, dataDir)
		case "8":
			if menuUninstallServer(scanner, dataDir) {
				return
			}
		case "9":
			menuSpeedtest(scanner)
		case "0":
			fmt.Println("Выход.")
			return
		default:
			fmt.Println("\n[!] Неверный выбор. Введите число от 0 до 9.")
			time.Sleep(800 * time.Millisecond)
		}
	}
}

func getDashboardSnapshot(dataDir string) ServerStatsSnapshot {
	if snap, err := fetchLiveStats(dataDir); err == nil {
		return *snap
	}
	return loadOfflineUsersSnapshot(dataDir)
}

func printDashboard(snap ServerStatsSnapshot, extIP, dataDir string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println("================================================================")
	fmt.Println(serverAsciiLogo)
	fmt.Printf("\n  Версия: %s  —  Панель управления сервером\n", AppVersion)
	fmt.Println("================================================================")

	statusStr := "ОСТАНОВЛЕН"
	uptimeStr := "0с (сервис не запущен)"
	if snap.PID > 0 {
		if snap.VPNEngineRunning {
			statusStr = fmt.Sprintf("VPN АКТИВЕН (PID %d)", snap.PID)
			uptimeStr = formatDuration(time.Duration(snap.UptimeSec) * time.Second)
		} else {
			statusStr = fmt.Sprintf("VPN ОСТАНОВЛЕН (Веб-панель активна, PID %d)", snap.PID)
		}
	} else if isSystemdActive() {
		statusStr = "АКТИВЕН (systemd)"
	}

	webPort := snap.WebPort
	if webPort <= 0 {
		webPort = loadPanelConfig(dataDir).Port
	}

	fmt.Printf("  Статус сервиса     : %s\n", statusStr)
	fmt.Printf("  Внешний IP         : %s\n", extIP)
	fmt.Printf("  Веб-панель         : http://%s:%d\n", extIP, webPort)
	fmt.Printf("  Время работы       : %s\n", uptimeStr)
	fmt.Printf("  Пользователей      : всего %d  |  онлайн %d\n", snap.TotalUsers, snap.OnlineUsers)
	fmt.Printf("  Трафик (с запуска) : Вх %s  |  Исх %s\n", formatBytes(snap.TotalRx), formatBytes(snap.TotalTx))
	fmt.Printf("  Директория данных  : %s\n", dataDir)
	fmt.Println("================================================================")
	fmt.Println("  1. Справка")
	fmt.Println("  2. Список пользователей")
	fmt.Println("  3. Добавить пользователя")
	fmt.Println("  4. Удалить пользователя")
	fmt.Println("  5. Обновление сервера (через скрипт с GitHub)")
	fmt.Println("  6. Запуск сервера")
	fmt.Println("  7. Остановка сервера")
	fmt.Println("  8. Удаление сервера")
	fmt.Println("  9. Проверка скорости (speedtest.net)")
	fmt.Println("  0. Выход")
	fmt.Println("================================================================")
}

func waitForZero(scanner *bufio.Scanner) {
	for {
		fmt.Print("\nВведите 0 для возврата в предыдущее меню: ")
		if !scanner.Scan() {
			return
		}
		if strings.TrimSpace(scanner.Text()) == "0" {
			return
		}
		fmt.Println("Для возврата введите именно 0.")
	}
}

func menuHelp(scanner *bufio.Scanner) {
	fmt.Println("\n================================================================")
	printQuickGuide()
	fmt.Println("================================================================")
	waitForZero(scanner)
}

func menuListUsers(scanner *bufio.Scanner, dataDir string) {
	snap := getDashboardSnapshot(dataDir)
	fmt.Println("\n==================== СПИСОК ПОЛЬЗОВАТЕЛЕЙ =====================")
	if len(snap.Users) == 0 {
		fmt.Println("Пользователи не найдены.")
	} else {
		for i, u := range snap.Users {
			status := "оффлайн"
			if u.Online {
				status = fmt.Sprintf("ОНЛАЙН (подключений: %d)", u.OnlineConns)
			}
			lastConn := u.LastConnected
			if lastConn == "" {
				lastConn = "Никогда"
			}
			lbl := ""
			if u.Label != "" {
				lbl = fmt.Sprintf(" (%s)", u.Label)
			}
			fmt.Printf("\n[%d]%s PSK: %s\n", i+1, lbl, u.PSK)
			fmt.Printf("    Статус                 : %s\n", status)
			fmt.Printf("    Трафик с запуска       : Вх %s | Исх %s (Всего %s)\n",
				formatBytes(u.SessionRx), formatBytes(u.SessionTx), formatBytes(u.SessionRx+u.SessionTx))
			fmt.Printf("    Трафик за сегодня      : Вх %s | Исх %s (Всего %s)\n",
				formatBytes(u.TodayRx), formatBytes(u.TodayTx), formatBytes(u.TodayRx+u.TodayTx))
			fmt.Printf("    Последнее подключение  : %s\n", lastConn)
		}
	}
	fmt.Println("\n================================================================")
	waitForZero(scanner)
}

func menuAddUser(scanner *bufio.Scanner, dataDir string) {
	for {
		fmt.Println("\n==================== ДОБАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯ ===================")
		fmt.Println("  1. Сгенерировать новый PSK автоматически")
		fmt.Println("  2. Ввести PSK вручную")
		fmt.Println("  0. Назад в главное меню")
		fmt.Print("Ваш выбор: ")
		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())
		switch choice {
		case "0":
			return
		case "1":
			psk := generateRandomPSK()
			if err := addUserToStorage(dataDir, psk); err != nil {
				fmt.Printf("\n[ОШИБКА] %v\n", err)
			} else {
				fmt.Println("\n[OK] Пользователь успешно добавлен!")
				fmt.Printf("  Новый PSK      : %s\n", psk)
				if pin := readCertPin(dataDir); pin != "" {
					fmt.Printf("  Cert SHA-256   : %s\n", pin)
				}
				fmt.Println("  (Если сервер запущен — ключ применён автоматически без перезапуска)")
			}
			waitForZero(scanner)
			return
		case "2":
			fmt.Print("Введите новый PSK (или 0 для отмены): ")
			if !scanner.Scan() {
				return
			}
			psk := strings.TrimSpace(scanner.Text())
			if psk == "0" {
				continue
			}
			if err := addUserToStorage(dataDir, psk); err != nil {
				fmt.Printf("\n[ОШИБКА] %v\n", err)
			} else {
				fmt.Printf("\n[OK] Пользователь с PSK '%s' добавлен!\n", psk)
				if pin := readCertPin(dataDir); pin != "" {
					fmt.Printf("  Cert SHA-256 : %s\n", pin)
				}
			}
			waitForZero(scanner)
			return
		default:
			fmt.Println("Неверный выбор. Введите 1, 2 или 0.")
		}
	}
}

func menuDeleteUser(scanner *bufio.Scanner, dataDir string) {
	for {
		snap := getDashboardSnapshot(dataDir)
		fmt.Println("\n==================== УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ =====================")
		if len(snap.Users) == 0 {
			fmt.Println("Список пользователей пуст.")
			waitForZero(scanner)
			return
		}

		for i, u := range snap.Users {
			st := "оффлайн"
			if u.Online {
				st = "ОНЛАЙН"
			}
			fmt.Printf("  %d. %s [%s]\n", i+1, u.PSK, st)
		}
		fmt.Println("  0. Назад в главное меню")
		fmt.Print("Введите номер пользователя для удаления: ")
		if !scanner.Scan() {
			return
		}
		raw := strings.TrimSpace(scanner.Text())
		if raw == "0" {
			return
		}
		idx, err := strconv.Atoi(raw)
		if err != nil || idx < 1 || idx > len(snap.Users) {
			fmt.Println("[!] Некорректный номер.")
			continue
		}

		target := snap.Users[idx-1].PSK
		fmt.Printf("\nУдалить пользователя %s? (1 - Да, 0 - Назад): ", target)
		if !scanner.Scan() {
			return
		}
		confirm := strings.TrimSpace(scanner.Text())
		if confirm == "0" {
			continue
		}
		if confirm == "1" {
			if err := deleteUserFromStorage(dataDir, target); err != nil {
				fmt.Printf("[ОШИБКА] %v\n", err)
			} else {
				fmt.Println("[OK] Пользователь удалён (активные сессии этого ключа закрыты).")
			}
			waitForZero(scanner)
			return
		}
	}
}

func menuUpdateServer(scanner *bufio.Scanner) {
	for {
		fmt.Println("\n==================== ОБНОВЛЕНИЕ СЕРВЕРА ========================")
		fmt.Printf("  Текущая версия: v%s\n", AppVersion)
		fmt.Printf("  Репозиторий   : https://github.com/%s\n", defaultGitHubRepo)
		fmt.Println("  1. Запустить обновление с GitHub (update.sh)")
		fmt.Println("  0. Назад в главное меню")
		fmt.Print("Ваш выбор: ")
		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())
		switch choice {
		case "0":
			return
		case "1":
			fmt.Print("Если репозиторий приватный, введите GITHUB_TOKEN (или Enter для публичного, 0 - отмена): ")
			if !scanner.Scan() {
				return
			}
			token := strings.TrimSpace(scanner.Text())
			if token == "0" {
				continue
			}

			url := fmt.Sprintf("https://raw.githubusercontent.com/%s/main/update.sh", defaultGitHubRepo)
			fmt.Printf("\n[*] Загрузка и запуск %s...\n", url)

			var cmd *exec.Cmd
			if token != "" {
				scriptCmd := fmt.Sprintf(`curl -fsSL -H "Authorization: Bearer %s" %s | GITHUB_TOKEN="%s" bash`,
					token, url, token)
				cmd = exec.Command("bash", "-c", scriptCmd)
			} else {
				scriptCmd := fmt.Sprintf(`curl -fsSL %s | bash`, url)
				cmd = exec.Command("bash", "-c", scriptCmd)
			}
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin

			if err := cmd.Run(); err != nil {
				fmt.Printf("\n[ОШИБКА] Обновление завершилось с ошибкой: %v\n", err)
			} else {
				fmt.Println("\n[OK] Обновление выполнено. Для работы с новой версией CLI перезапустите winrm-vpn-server.")
			}
			waitForZero(scanner)
			return
		default:
			fmt.Println("Неверный выбор.")
		}
	}
}

func menuStartServer(scanner *bufio.Scanner, dataDir string) {
	fmt.Println("\n==================== ЗАПУСК СЕРВЕРА ============================")
	if snap, err := fetchLiveStats(dataDir); err == nil {
		if snap.VPNEngineRunning {
			fmt.Println("[!] Сервер уже запущен и работает.")
			waitForZero(scanner)
			return
		}
		if err := sendControlCommand(dataDir, "/vpn/start"); err == nil {
			fmt.Println("[OK] VPN-движок запущен через управляющий сокет!")
		} else {
			fmt.Printf("[ОШИБКА] %v\n", err)
		}
		waitForZero(scanner)
		return
	}

	if hasSystemdService() {
		fmt.Println("[*] Запуск службы systemd (winrm-vpn)...")
		out, err := exec.Command("systemctl", "start", "winrm-vpn").CombinedOutput()
		if err != nil {
			fmt.Printf("[ОШИБКА] Не удалось запустить systemd-службу: %v\n%s\n", err, string(out))
		} else {
			time.Sleep(1500 * time.Millisecond)
			if isSystemdActive() {
				fmt.Println("[OK] Служба winrm-vpn успешно запущена!")
				if pin := readCertPin(dataDir); pin != "" {
					fmt.Printf("  Cert SHA-256 Pin: %s\n", pin)
				}
			} else {
				fmt.Println("[ОШИБКА] Служба остановилась после запуска. Проверьте: journalctl -u winrm-vpn -n 20")
			}
		}
		waitForZero(scanner)
		return
	}

	snap := loadOfflineUsersSnapshot(dataDir)
	if len(snap.Users) == 0 {
		psk := generateRandomPSK()
		if err := addUserToStorage(dataDir, psk); err != nil {
			fmt.Printf("[ОШИБКА] Не удалось создать ключ пользователя: %v\n", err)
			waitForZero(scanner)
			return
		}
		fmt.Printf("[*] Создан первый пользователь, PSK: %s\n", psk)
	}

	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("[ОШИБКА] Не удалось определить путь к бинарнику: %v\n", err)
		waitForZero(scanner)
		return
	}

	logPath := filepath.Join(dataDir, "server.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Printf("[ОШИБКА] Не удалось открыть лог-файл %s: %v\n", logPath, err)
		waitForZero(scanner)
		return
	}

	cmd := exec.Command(exePath, "-daemon", "-data-dir", dataDir, "-listen", "0.0.0.0:5986")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		fmt.Printf("[ОШИБКА] Ошибка запуска фона: %v\n", err)
		waitForZero(scanner)
		return
	}
	_ = cmd.Process.Release()
	_ = logFile.Close()

	time.Sleep(1500 * time.Millisecond)
	if _, err := fetchLiveStats(dataDir); err == nil {
		fmt.Printf("[OK] Сервер запущен в фоне! Логи: %s\n", logPath)
		if pin := readCertPin(dataDir); pin != "" {
			fmt.Printf("  Cert SHA-256 Pin: %s\n", pin)
		}
	} else {
		fmt.Printf("[!] Команда запуска выполнена, проверьте логи: %s\n", logPath)
	}
	waitForZero(scanner)
}

func menuStopServer(scanner *bufio.Scanner, dataDir string) {
	fmt.Println("\n==================== ОСТАНОВКА СЕРВЕРА =========================")
	stoppedSomething := false

	if isSystemdActive() {
		fmt.Println("[*] Остановка systemd-службы winrm-vpn...")
		if out, err := exec.Command("systemctl", "stop", "winrm-vpn").CombinedOutput(); err != nil {
			fmt.Printf("[ОШИБКА] systemctl stop: %v\n%s\n", err, string(out))
		} else {
			stoppedSomething = true
		}
	}

	if err := sendControlCommand(dataDir, "/stop"); err == nil {
		stoppedSomething = true
		time.Sleep(500 * time.Millisecond)
	}

	if stoppedSomething {
		fmt.Println("[OK] Сервер остановлен.")
	} else {
		fmt.Println("[!] Сервер не был запущен.")
	}
	waitForZero(scanner)
}

func menuUninstallServer(scanner *bufio.Scanner, dataDir string) bool {
	for {
		fmt.Println("\n==================== УДАЛЕНИЕ СЕРВЕРА ==========================")
		fmt.Println("  Вы действительно хотите удалить WinRM-VPN Server?")
		fmt.Println("  1. Удалить сервер и СОХРАНИТЬ данные пользователей")
		fmt.Println("  2. Удалить сервер и УДАЛИТЬ ВСЕ данные (пользователи, PSK, сертификаты)")
		fmt.Println("  0. Назад в главное меню")
		fmt.Print("Ваш выбор: ")
		if !scanner.Scan() {
			return false
		}
		choice := strings.TrimSpace(scanner.Text())
		if choice == "0" {
			return false
		}
		if choice != "1" && choice != "2" {
			fmt.Println("Неверный выбор.")
			continue
		}

		keepUsers := (choice == "1")

		fmt.Println("\n[*] Остановка и удаление службы...")
		if hasSystemdService() {
			_ = exec.Command("systemctl", "stop", "winrm-vpn").Run()
			_ = exec.Command("systemctl", "disable", "winrm-vpn").Run()
			_ = os.Remove("/etc/systemd/system/winrm-vpn.service")
			_ = exec.Command("systemctl", "daemon-reload").Run()
			fmt.Println("  - Служба systemd удалена.")
		}
		_ = sendControlCommand(dataDir, "/stop")
		time.Sleep(300 * time.Millisecond)

		_ = os.Remove("/etc/sysctl.d/99-winrm-vpn.conf")
		_ = os.Remove(filepath.Join(dataDir, "control.sock"))

		if keepUsers {
			fmt.Printf("  - Данные пользователей сохранены в: %s\n", dataDir)
		} else {
			_ = os.Remove(filepath.Join(dataDir, "users.json"))
			_ = os.Remove(filepath.Join(dataDir, "panel.json"))
			_ = os.Remove(filepath.Join(dataDir, "config.env"))
			_ = os.Remove(filepath.Join(dataDir, "winrm_cert.pem"))
			_ = os.Remove(filepath.Join(dataDir, "winrm_key.pem"))
			_ = os.Remove(filepath.Join(dataDir, "server.log"))
			if dataDir == "/etc/winrm-vpn" {
				_ = os.RemoveAll("/etc/winrm-vpn")
			}
			fmt.Println("  - Все данные пользователей и сертификаты удалены.")
		}

		if exePath, err := os.Executable(); err == nil {
			if err := os.Remove(exePath); err == nil {
				fmt.Printf("  - Бинарник %s удалён.\n", exePath)
			}
		}
		_ = os.Remove("/usr/local/bin/winrm-vpn-server")

		fmt.Println("\n[OK] Удаление завершено.")
		waitForZero(scanner)
		return true
	}
}

func menuSpeedtest(scanner *bufio.Scanner) {
	for {
		fmt.Println("\n================ ПРОВЕРКА СКОРОСТИ (SPEEDTEST.NET) =============")
		fmt.Println("  1. Запустить тест скорости (авто: Ookla CLI или встроенный тест)")
		fmt.Println("  2. Установить и запустить официальный Ookla Speedtest CLI")
		fmt.Println("  0. Назад в главное меню")
		fmt.Print("Ваш выбор: ")
		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())
		switch choice {
		case "0":
			return
		case "1":
			if bin, err := exec.LookPath("speedtest"); err == nil {
				fmt.Printf("\n[*] Запуск %s...\n\n", bin)
				c := exec.Command(bin, "--accept-license", "--accept-gdpr")
				c.Stdout = os.Stdout
				c.Stderr = os.Stderr
				_ = c.Run()
			} else if bin, err := exec.LookPath("speedtest-cli"); err == nil {
				fmt.Printf("\n[*] Запуск %s...\n\n", bin)
				c := exec.Command(bin)
				c.Stdout = os.Stdout
				c.Stderr = os.Stderr
				_ = c.Run()
			} else {
				runNativeSpeedtest()
			}
			waitForZero(scanner)
			return
		case "2":
			installAndRunOoklaCLI()
			waitForZero(scanner)
			return
		default:
			fmt.Println("Неверный выбор.")
		}
	}
}

func installAndRunOoklaCLI() {
	fmt.Println("\n[*] Скачивание официального Ookla Speedtest CLI (x86_64)...")
	url := "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
	cmd := exec.Command("bash", "-c", fmt.Sprintf(
		`TMP=$(mktemp -d) && curl -fsSL "%s" -o "$TMP/st.tgz" && tar -xzf "$TMP/st.tgz" -C "$TMP" && mv "$TMP/speedtest" /usr/local/bin/speedtest && chmod 755 /usr/local/bin/speedtest && rm -rf "$TMP"`,
		url,
	))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("[ОШИБКА] Не удалось установить Ookla CLI: %v\n", err)
		fmt.Println("[*] Выполняется встроенный тест Speedtest.net...")
		runNativeSpeedtest()
		return
	}
	fmt.Println("[OK] Ookla CLI установлен в /usr/local/bin/speedtest. Запуск теста...\n")
	runCmd := exec.Command("/usr/local/bin/speedtest", "--accept-license", "--accept-gdpr")
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr
	_ = runCmd.Run()
}

type speedtestServer struct {
	URL     string `json:"url"`
	Name    string `json:"name"`
	Country string `json:"country"`
	Sponsor string `json:"sponsor"`
	Host    string `json:"host"`
}

func runNativeSpeedtest() {
	fmt.Println("\n[*] Поиск ближайших серверов Speedtest.net...")
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", "https://www.speedtest.net/api/js/servers?engine=js&limit=8", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[ОШИБКА] Не удалось получить список серверов speedtest.net: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var servers []speedtestServer
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil || len(servers) == 0 {
		fmt.Println("[ОШИБКА] Не удалось разобрать список серверов speedtest.net.")
		return
	}

	var best speedtestServer
	bestRTT := time.Hour
	for _, srv := range servers {
		rtt := measureTCPPing(srv.Host)
		if rtt > 0 && rtt < bestRTT {
			bestRTT = rtt
			best = srv
		}
	}
	if best.URL == "" {
		best = servers[0]
		bestRTT = measureTCPPing(best.Host)
	}

	fmt.Printf("  Сервер   : %s (%s, %s)\n", best.Sponsor, best.Name, best.Country)
	if bestRTT > 0 && bestRTT < time.Hour {
		fmt.Printf("  Пинг     : %.2f ms\n", float64(bestRTT.Microseconds())/1000.0)
	}

	fmt.Print("  Скачивание (Download)... ")
	dlMbps := measureSpeedtestDownload(best)
	fmt.Printf("%.2f Mbps\n", dlMbps)

	fmt.Print("  Отдача (Upload)...       ")
	ulMbps := measureSpeedtestUpload(best)
	fmt.Printf("%.2f Mbps\n", ulMbps)
}

func measureTCPPing(hostPort string) time.Duration {
	if !strings.Contains(hostPort, ":") {
		hostPort += ":8080"
	}
	best := time.Duration(0)
	for i := 0; i < 3; i++ {
		start := time.Now()
		c, err := net.DialTimeout("tcp", hostPort, 2*time.Second)
		if err != nil {
			continue
		}
		d := time.Since(start)
		_ = c.Close()
		if best == 0 || d < best {
			best = d
		}
	}
	return best
}

func measureSpeedtestDownload(srv speedtestServer) float64 {
	baseURL := strings.TrimSuffix(srv.URL, "upload.php")
	candidates := []string{
		baseURL + "random4000x4000.jpg",
		baseURL + "random2500x2500.jpg",
		"https://" + srv.Host + "/download?size=25000000",
		"http://" + srv.Host + "/download?size=25000000",
	}

	var workingURL string
	probeClient := &http.Client{Timeout: 4 * time.Second}
	for _, u := range candidates {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := probeClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				workingURL = u
				break
			}
		}
	}
	if workingURL == "" {
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	var totalBytes int64
	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dlClient := &http.Client{Timeout: 7 * time.Second}
			buf := make([]byte, 32*1024)
			for ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, "GET", workingURL, nil)
				req.Header.Set("User-Agent", "Mozilla/5.0")
				resp, err := dlClient.Do(req)
				if err != nil {
					return
				}
				for {
					n, err := resp.Body.Read(buf)
					if n > 0 {
						atomic.AddInt64(&totalBytes, int64(n))
					}
					if err != nil {
						break
					}
				}
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&totalBytes)*8) / elapsed / 1_000_000.0
}

func measureSpeedtestUpload(srv speedtestServer) float64 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload := bytes.Repeat([]byte("0123456789ABCDEF"), 64*1024)
	var totalBytes int64
	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ulClient := &http.Client{Timeout: 6 * time.Second}
			for ctx.Err() == nil {
				cr := &countingReader{r: bytes.NewReader(payload), counter: &totalBytes}
				req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL, cr)
				req.Header.Set("User-Agent", "Mozilla/5.0")
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				resp, err := ulClient.Do(req)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&totalBytes)*8) / elapsed / 1_000_000.0
}

type countingReader struct {
	r       io.Reader
	counter *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		atomic.AddInt64(c.counter, int64(n))
	}
	return n, err
}

func generateRandomPSK() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func readCertPin(dataDir string) string {
	candidates := []string{
		filepath.Join(dataDir, "winrm_cert.pem"),
		"winrm_cert.pem",
	}
	for _, p := range candidates {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(raw)
		if block != nil {
			h := sha256.Sum256(block.Bytes)
			return hex.EncodeToString(h[:])
		}
	}
	return ""
}

func fetchExternalIP() string {
	client := &http.Client{Timeout: 2 * time.Second}
	urls := []string{"https://api.ipify.org", "https://ifconfig.io/ip"}
	for _, u := range urls {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "curl/8.5.0")
		if resp, err := client.Do(req); err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
			_ = resp.Body.Close()
			ip := strings.TrimSpace(string(b))
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	return "не определён"
}

func hasSystemdService() bool {
	_, err := os.Stat("/etc/systemd/system/winrm-vpn.service")
	return err == nil
}

func isSystemdActive() bool {
	err := exec.Command("systemctl", "is-active", "--quiet", "winrm-vpn").Run()
	return err == nil
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	sec := int64(d.Seconds())
	days := sec / 86400
	sec %= 86400
	hours := sec / 3600
	sec %= 3600
	mins := sec / 60
	sec %= 60

	if days > 0 {
		return fmt.Sprintf("%dд %dч %dм %dс", days, hours, mins, sec)
	}
	if hours > 0 {
		return fmt.Sprintf("%dч %dм %dс", hours, mins, sec)
	}
	if mins > 0 {
		return fmt.Sprintf("%dм %dс", mins, sec)
	}
	return fmt.Sprintf("%dс", sec)
}
