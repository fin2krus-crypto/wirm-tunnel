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

		fmt.Print("Выберите пункт [0-11]: ")
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
		case "10":
			menuWebPanel(scanner, dataDir)
		case "11":
			menuRuCheck(scanner, cachedExtIP)
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
	if snap.WebEnabled || (snap.PID == 0 && loadPanelConfig(dataDir).Enabled) {
		fmt.Printf("  Веб-панель         : http://%s:%d (ВКЛ)\n", extIP, webPort)
	} else {
		fmt.Println("  Веб-панель         : ВЫКЛЮЧЕНА")
	}
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
	fmt.Println("  10. Веб-интерфейс (включить / выключить)")
	fmt.Println("  11. Проверка доступности из РФ (ТСПУ / РКН)")
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
				fmt.Println("[OK] Пользователь удалён.")
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
		if !scanner.Scan() { return }
		switch strings.TrimSpace(scanner.Text()) {
		case "0":
			return
		case "1":
			url := fmt.Sprintf("https://raw.githubusercontent.com/%s/main/update.sh", defaultGitHubRepo)
			fmt.Printf("\n[*] Загрузка и запуск %s...\n", url)
			cmd := exec.Command("bash", "-c", fmt.Sprintf("curl -fsSL %s | bash", url))
			cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
			if err := cmd.Run(); err != nil {
				fmt.Printf("\n[ОШИБКА] Обновление не удалось: %v\n", err)
			} else {
				fmt.Println("\n[OK] Сервер обновлён. Перезапустите winrm-vpn-server для обновления меню.")
			}
			waitForZero(scanner)
			return
		}
	}
}

func menuWebPanel(scanner *bufio.Scanner, dataDir string) {
	for {
		cfg := loadPanelConfig(dataDir)
		liveSnap, liveErr := fetchLiveStats(dataDir)
		enabled := cfg.Enabled
		if liveErr == nil { enabled = liveSnap.WebEnabled }
		st := "ВЫКЛЮЧЕН"
		if enabled { st = fmt.Sprintf("ВКЛЮЧЁН (порт :%d)", cfg.Port) }
		fmt.Println("\n==================== ВЕБ-ИНТЕРФЕЙС =============================")
		fmt.Printf("  Текущий статус: %s\n", st)
		fmt.Println("  1. Включить веб-интерфейс")
		fmt.Println("  2. Выключить веб-интерфейс")
		fmt.Println("  0. Назад в главное меню")
		fmt.Print("Ваш выбор: ")
		if !scanner.Scan() { return }
		switch strings.TrimSpace(scanner.Text()) {
		case "0":
			return
		case "1":
			if liveErr == nil {
				if err := sendControlCommand(dataDir, "/web/start"); err != nil {
					fmt.Printf("[ОШИБКА] %v\n", err)
				} else {
					fmt.Printf("[OK] Веб-интерфейс включён на порту :%d\n", cfg.Port)
				}
			} else {
				cfg.Enabled = true
				_ = savePanelConfig(dataDir, cfg)
				openUfwPortIfActive(cfg.Port)
				fmt.Printf("[OK] Веб-интерфейс будет включён при запуске (порт :%d).\n", cfg.Port)
			}
			waitForZero(scanner)
			return
		case "2":
			if liveErr == nil {
				if err := sendControlCommand(dataDir, "/web/stop"); err != nil {
					fmt.Printf("[ОШИБКА] %v\n", err)
				} else {
					fmt.Println("[OK] Веб-интерфейс выключен.")
				}
			} else {
				cfg.Enabled = false
				_ = savePanelConfig(dataDir, cfg)
				fmt.Println("[OK] Веб-интерфейс выключен в конфигурации.")
			}
			waitForZero(scanner)
			return
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
		out, err := exec.Command("systemctl", "start", "winrm-vpn").CombinedOutput()
		if err != nil {
			fmt.Printf("[ОШИБКА] %v\n%s\n", err, string(out))
		} else {
			time.Sleep(1500 * time.Millisecond)
			fmt.Println("[OK] Служба winrm-vpn запущена!")
		}
		waitForZero(scanner)
		return
	}

	snap := loadOfflineUsersSnapshot(dataDir)
	if len(snap.Users) == 0 {
		psk := generateRandomPSK()
		if err := addUserToStorage(dataDir, psk); err != nil {
			fmt.Printf("[ОШИБКА] %v\n", err)
			waitForZero(scanner)
			return
		}
		fmt.Printf("[*] Создан первый пользователь, PSK: %s\n", psk)
	}

	exePath, err := os.Executable()
	if err != nil {
		waitForZero(scanner)
		return
	}
	logPath := filepath.Join(dataDir, "server.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		waitForZero(scanner)
		return
	}
	cmd := exec.Command(exePath, "-daemon", "-data-dir", dataDir, "-listen", "0.0.0.0:5986")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		fmt.Printf("[ОШИБКА] %v\n", err)
		waitForZero(scanner)
		return
	}
	_ = cmd.Process.Release()
	_ = logFile.Close()
	time.Sleep(1500 * time.Millisecond)
	fmt.Printf("[OK] Сервер запущен в фоне. Логи: %s\n", logPath)
	waitForZero(scanner)
}

func menuStopServer(scanner *bufio.Scanner, dataDir string) {
	fmt.Println("\n==================== ОСТАНОВКА СЕРВЕРА =========================")
	stopped := false
	if isSystemdActive() {
		if exec.Command("systemctl", "stop", "winrm-vpn").Run() == nil {
			stopped = true
		}
	}
	if sendControlCommand(dataDir, "/stop") == nil {
		stopped = true
	}
	if stopped {
		fmt.Println("[OK] Сервер остановлен.")
	} else {
		fmt.Println("[!] Сервер не был запущен.")
	}
	waitForZero(scanner)
}

func menuUninstallServer(scanner *bufio.Scanner, dataDir string) bool {
	for {
		fmt.Println("\n==================== УДАЛЕНИЕ СЕРВЕРА ==========================")
		fmt.Println("  1. Удалить сервер и СОХРАНИТЬ данные пользователей")
		fmt.Println("  2. Удалить сервер и УДАЛИТЬ ВСЕ данные")
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
			continue
		}
		keepUsers := (choice == "1")
		if hasSystemdService() {
			_ = exec.Command("systemctl", "stop", "winrm-vpn").Run()
			_ = exec.Command("systemctl", "disable", "winrm-vpn").Run()
			_ = os.Remove("/etc/systemd/system/winrm-vpn.service")
			_ = exec.Command("systemctl", "daemon-reload").Run()
		}
		_ = sendControlCommand(dataDir, "/stop")
		time.Sleep(300 * time.Millisecond)
		_ = os.Remove("/etc/sysctl.d/99-winrm-vpn.conf")
		_ = os.Remove(filepath.Join(dataDir, "control.sock"))
		if !keepUsers {
			_ = os.RemoveAll(dataDir)
		}
		if exePath, err := os.Executable(); err == nil {
			_ = os.Remove(exePath)
		}
		_ = os.Remove("/usr/local/bin/winrm-vpn-server")
		fmt.Println("[OK] Удаление завершено.")
		waitForZero(scanner)
		return true
	}
}

func menuSpeedtest(scanner *bufio.Scanner) {
	for {
		fmt.Println("\n================ ПРОВЕРКА СКОРОСТИ (SPEEDTEST.NET) =============")
		fmt.Println("  1. Запустить тест скорости (авто)")
		fmt.Println("  2. Установить и запустить официальный Ookla Speedtest CLI")
		fmt.Println("  0. Назад в главное меню")
		fmt.Print("Ваш выбор: ")
		if !scanner.Scan() {
			return
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "0":
			return
		case "1":
			if bin, err := exec.LookPath("speedtest"); err == nil {
				c := exec.Command(bin, "--accept-license", "--accept-gdpr")
				c.Stdout, c.Stderr = os.Stdout, os.Stderr
				_ = c.Run()
			} else if bin, err := exec.LookPath("speedtest-cli"); err == nil {
				c := exec.Command(bin)
				c.Stdout, c.Stderr = os.Stdout, os.Stderr
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
		}
	}
}

func installAndRunOoklaCLI() {
	url := "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`TMP=$(mktemp -d) && curl -fsSL "%s" -o "$TMP/st.tgz" && tar -xzf "$TMP/st.tgz" -C "$TMP" && mv "$TMP/speedtest" /usr/local/bin/speedtest && chmod 755 /usr/local/bin/speedtest && rm -rf "$TMP"`, url))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if cmd.Run() != nil {
		runNativeSpeedtest()
		return
	}
	c := exec.Command("/usr/local/bin/speedtest", "--accept-license", "--accept-gdpr")
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	_ = c.Run()
}

type speedtestServer struct {
	URL     string `json:"url"`
	Name    string `json:"name"`
	Country string `json:"country"`
	Sponsor string `json:"sponsor"`
	Host    string `json:"host"`
}

func runNativeSpeedtest() {
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", "https://www.speedtest.net/api/js/servers?engine=js&limit=8", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[ОШИБКА] %v\n", err)
		return
	}
	defer resp.Body.Close()
	var servers []speedtestServer
	if json.NewDecoder(resp.Body).Decode(&servers) != nil || len(servers) == 0 {
		return
	}
	best := servers[0]
	bestRTT := time.Hour
	for _, s := range servers {
		if rtt := measureTCPPing(s.Host); rtt > 0 && rtt < bestRTT {
			bestRTT, best = rtt, s
		}
	}
	fmt.Printf("  Сервер: %s (%s, %s)\n  Пинг  : %.2f ms\n", best.Sponsor, best.Name, best.Country, float64(bestRTT.Microseconds())/1000.0)
	fmt.Printf("  Down  : %.2f Mbps\n", measureSpeedtestDownload(best))
	fmt.Printf("  Up    : %.2f Mbps\n", measureSpeedtestUpload(best))
}

func measureTCPPing(hp string) time.Duration {
	if !strings.Contains(hp, ":") {
		hp += ":8080"
	}
	var best time.Duration
	for i := 0; i < 3; i++ {
		st := time.Now()
		c, err := net.DialTimeout("tcp", hp, 2*time.Second)
		if err == nil {
			d := time.Since(st)
			_ = c.Close()
			if best == 0 || d < best {
				best = d
			}
		}
	}
	return best
}

func measureSpeedtestDownload(srv speedtestServer) float64 {
	base := strings.TrimSuffix(srv.URL, "upload.php")
	cands := []string{base + "random4000x4000.jpg", base + "random2500x2500.jpg", "https://" + srv.Host + "/download?size=25000000", "http://" + srv.Host + "/download?size=25000000"}
	var u string
	pc := &http.Client{Timeout: 4 * time.Second}
	for _, cand := range cands {
		rq, _ := http.NewRequest("GET", cand, nil)
		rq.Header.Set("User-Agent", "Mozilla/5.0")
		if rs, err := pc.Do(rq); err == nil {
			_ = rs.Body.Close()
			if rs.StatusCode == 200 {
				u = cand
				break
			}
		}
	}
	if u == "" {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	var total int64
	var wg sync.WaitGroup
	st := time.Now()
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dc := &http.Client{Timeout: 7 * time.Second}
			buf := make([]byte, 32*1024)
			for ctx.Err() == nil {
				rq, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
				rq.Header.Set("User-Agent", "Mozilla/5.0")
				rs, err := dc.Do(rq)
				if err != nil {
					return
				}
				for {
					n, er := rs.Body.Read(buf)
					if n > 0 {
						atomic.AddInt64(&total, int64(n))
					}
					if er != nil {
						break
					}
				}
				_ = rs.Body.Close()
			}
		}()
	}
	wg.Wait()
	return float64(atomic.LoadInt64(&total)*8) / time.Since(st).Seconds() / 1e6
}

func measureSpeedtestUpload(srv speedtestServer) float64 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte("0123456789ABCDEF"), 64*1024)
	var total int64
	var wg sync.WaitGroup
	st := time.Now()
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			uc := &http.Client{Timeout: 6 * time.Second}
			for ctx.Err() == nil {
				cr := &countingReader{r: bytes.NewReader(payload), counter: &total}
				rq, _ := http.NewRequestWithContext(ctx, "POST", srv.URL, cr)
				rq.Header.Set("User-Agent", "Mozilla/5.0")
				rq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rs, err := uc.Do(rq)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, rs.Body)
				_ = rs.Body.Close()
			}
		}()
	}
	wg.Wait()
	return float64(atomic.LoadInt64(&total)*8) / time.Since(st).Seconds() / 1e6
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
	for _, p := range []string{filepath.Join(dataDir, "winrm_cert.pem"), "winrm_cert.pem"} {
		if raw, err := os.ReadFile(p); err == nil {
			if block, _ := pem.Decode(raw); block != nil {
				h := sha256.Sum256(block.Bytes)
				return hex.EncodeToString(h[:])
			}
		}
	}
	return ""
}

func fetchExternalIP() string {
	client := &http.Client{Timeout: 2 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.io/ip"} {
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
	return exec.Command("systemctl", "is-active", "--quiet", "winrm-vpn").Run() == nil
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

func menuRuCheck(scanner *bufio.Scanner, extIP string) {
	for {
		fmt.Println("\n================= ПРОВЕРКА ДОСТУПНОСТИ ИЗ РФ (ТСПУ / РКН) =================")
		fmt.Printf("  Проверяемый IP сервера: %s (порт 5986)\n", extIP)
		fmt.Println("  1. Friskes/vpn-infra (ru-reach: Check-Host RU + Globalping операторы РФ)")
		fmt.Println("  2. jsdelivr/globalping-cli (MTR трассировка и пинг из сетей РФ)")
		fmt.Println("  3. diasnull/check-host (Проверка доступности TCP 5986 через узлы РФ)")
		fmt.Println("  4. runetfreedom / itdoginfo (Сверка с реестром РКН + тест iperf3 до РФ)")
		fmt.Println("  0. Назад в главное меню")
		fmt.Print("Ваш выбор: ")
		if !scanner.Scan() { return }
		switch strings.TrimSpace(scanner.Text()) {
		case "0":
			return
		case "1":
			runRuReach(scanner, extIP)
		case "2":
			runGlobalping(scanner, extIP)
		case "3":
			runCheckHost(scanner, extIP)
		case "4":
			runRknIperf(scanner, extIP)
		default:
			fmt.Println("Неверный выбор.")
		}
	}
}

func runRuReach(scanner *bufio.Scanner, extIP string) {
	fmt.Printf("\n[*] Запуск ru-reach (Friskes/vpn-infra) для %s:5986...\n", extIP)
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		mkdir -p /tmp/winrm-check && cd /tmp/winrm-check
		curl -fsSL https://raw.githubusercontent.com/Friskes/vpn-infra/main/tools/measure/ru-reach.py -o ru-reach.py 2>/dev/null || true
		if [ -s ru-reach.py ]; then
			python3 ru-reach.py --target "%s" --port 5986 2>&1 || python3 ru-reach.py "%s" 5986 2>&1 || python3 ru-reach.py -h
		else
			echo "[!] Не удалось загрузить ru-reach.py"
		fi
	`, extIP, extIP))
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	_ = cmd.Run()
	waitForZero(scanner)
}

func runGlobalping(scanner *bufio.Scanner, extIP string) {
	fmt.Println("\n[*] Подготовка jsdelivr/globalping-cli...")
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		if ! command -v globalping >/dev/null 2>&1; then
			echo "[*] Установка globalping..."
			curl -fsSL https://github.com/jsdelivr/globalping-cli/releases/latest/download/globalping-linux-x86_64 -o /usr/local/bin/globalping 2>/dev/null && chmod +x /usr/local/bin/globalping || true
		fi
		if command -v globalping >/dev/null 2>&1; then
			echo -e "\n--- 1. Пинг из домашних сетей РФ (eyeball) ---"
			globalping ping "%s" --from Russia --limit 4 || true
			echo -e "\n--- 2. MTR трассировка из РФ к %s:5986 ---"
			globalping traceroute "%s" --from Russia --limit 2 --port 5986 || globalping traceroute "%s" --from Russia --limit 2 || true
		else
			echo "[!] Не удалось установить globalping-cli (проверьте интернет)."
		fi
	`, extIP, extIP, extIP, extIP))
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	_ = cmd.Run()
	waitForZero(scanner)
}

func runCheckHost(scanner *bufio.Scanner, extIP string) {
	fmt.Printf("\n[*] Проверка доступности порта %s:5986 через check-host.net...\n", extIP)
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		python3 - << 'PYEOF'
import urllib.request, json, time, sys

ip = "%s"
port = 5986
headers = {"User-Agent": "curl/8.5.0", "Accept": "application/json"}

print(f"[*] Отправка запроса TCP проверки порта {ip}:{port} в check-host.net...")
req = urllib.request.Request(f"https://check-host.net/check-tcp?host={ip}:{port}&max_nodes=15", headers=headers)
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        init_data = json.loads(r.read().decode())
except Exception as e:
    print(f"[!] Ошибка запроса к check-host: {e}")
    sys.exit(0)

req_id = init_data.get("request_id")
nodes = init_data.get("nodes", {})
ru_nodes = [nid for nid, info in nodes.items() if len(info) > 1 and info[1] == "ru"]

if not req_id or not ru_nodes:
    print("[!] Не найдены российские узлы в текущей выборке check-host. Попробуйте снова.")
    sys.exit(0)

print(f"[*] Ожидание ответов от {len(ru_nodes)} узлов в РФ...")
time.sleep(4)

res_req = urllib.request.Request(f"https://check-host.net/check-result/{req_id}", headers=headers)
try:
    with urllib.request.urlopen(res_req, timeout=10) as r:
        results = json.loads(r.read().decode())
except Exception as e:
    print(f"[!] Ошибка получения результатов: {e}")
    sys.exit(0)

print("\nРезультаты проверки порта 5986 из России:")
for nid in ru_nodes:
    city = nodes[nid][2]
    res = results.get(nid)
    if res and len(res) > 0 and res[0]:
        first = res[0][0]
        if "error" in first:
            print(f"  [X] {city} ({nid}): ТАЙМАУТ / ЗАБЛОКИРОВАН ({first['error']})")
        else:
            time_ms = first.get("time", 0) * 1000
            print(f"  [OK] {city} ({nid}): ДОСТУПЕН (RTT: {time_ms:.1f} ms)")
    else:
        print(f"  [?] {city} ({nid}): узел ещё не ответил")
PYEOF
	`, extIP))
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	_ = cmd.Run()
	waitForZero(scanner)
}

func runRknIperf(scanner *bufio.Scanner, extIP string) {
	fmt.Printf("\n[*] Сверка IP %s с базами блокировок РКН (runetfreedom)...\n", extIP)
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		echo -n "  Проверка в реестре заблокированных IP... "
		TMP_LIST=$(mktemp)
		curl -fsSL --max-time 10 https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/main/blocked-ip.txt -o "$TMP_LIST" 2>/dev/null || true
		if [ -s "$TMP_LIST" ]; then
			if grep -q "^%s$" "$TMP_LIST"; then
				echo -e "[0;31m[!] ВНИМАНИЕ: IP найден в списках блокировок РКН![0m"
			else
				echo -e "[0;32m[OK] IP отсутствует в списках блокировок.[0m"
			fi
		else
			echo "[?] Не удалось скачать базу (таймаут)."
		fi
		rm -f "$TMP_LIST"

		echo -e "\n[*] Замер скорости и шейпинга до серверов в РФ (itdoginfo/russian-iperf3-servers)..."
		which iperf3 >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq iperf3 >/dev/null 2>&1 || true)
		curl -fsSL https://raw.githubusercontent.com/itdoginfo/russian-iperf3-servers/main/speedtest.sh | bash || true
	`, extIP))
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	_ = cmd.Run()
	waitForZero(scanner)
}
