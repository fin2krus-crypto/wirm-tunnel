package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

//go:embed embedded/winrm-vpn-linux-helper
var embeddedHelper []byte

const (
	ctlMetaPath = "/tmp/winrm-vpn-linux-ctl.json"
	helperPath  = "/tmp/winrm-vpn-linux-helper"
)

type CtlMeta struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
	PID   int    `json:"pid"`
}

type StatusResponse struct {
	State     string   `json:"state"`
	CheckConn bool     `json:"check_conn"`
	Logs      []string `json:"logs"`
}

const asciiLogo = ` __        ___       ____  __  __    __     ______  _   _
 \ \      / (_)_ __ |  _ \|  \/  |   \ \   / /  _ \| \ | |
  \ \ /\ / /| | '_ \| |_) | |\/| |____\ \ / /| |_) |  \| |
   \ V  V / | | | | |  _ <| |  | |_____\ V / |  __/| |\  |
    \_/\_/  |_|_| |_|_| \_\_|  |_|      \_/  |_|   |_| \_|`

func main() {
	a := app.NewWithID("com.example.winrmvpn.linux")
	a.Settings().SetTheme(theme.DarkTheme())

	w := a.NewWindow("WinRM-VPN v0.4.2 (Linux GUI)")
	w.Resize(fyne.NewSize(520, 720))

	prefs := a.Preferences()

	logoLabel := widget.NewLabel(asciiLogo)
	logoLabel.TextStyle = fyne.TextStyle{Monospace: true}
	logoLabel.Alignment = fyne.TextAlignCenter

	subTitle := widget.NewLabel("v0.4.2  |  Should looks like Ansible (Linux x86_64)")
	subTitle.TextStyle = fyne.TextStyle{Monospace: true}
	subTitle.Alignment = fyne.TextAlignCenter

	serverEntry := widget.NewEntry()
	serverEntry.SetPlaceHolder("Server IP:Port (e.g. 203.0.113.10:5986)")
	serverEntry.SetText(prefs.String("server"))

	pskEntry := widget.NewPasswordEntry()
	pskEntry.SetPlaceHolder("Pre-Shared Key (PSK)")
	pskEntry.SetText(prefs.String("psk"))

	pinEntry := widget.NewEntry()
	pinEntry.SetPlaceHolder("Cert SHA-256 Pin (64 hex, optional)")
	pinEntry.SetText(prefs.String("pin"))

	checkConn := widget.NewCheck("Проверять соединение", func(checked bool) {
		prefs.SetBool("check_conn", checked)
		_ = pushWatchdog(checked)
	})
	checkConn.SetChecked(prefs.Bool("check_conn"))

	btnInfo := widget.NewButton("(?)", func() {
		dialog.ShowInformation(
			"Проверка соединения (Watchdog)",
			"При включённом переключателе и активном туннеле:\n\n"+
				"1. Пассивный контроль: если за последние 30-60с приходили данные, проверок нет.\n"+
				"2. В простое отправляется WinRM KeepAlive фрейм (размером под SOAP).\n"+
				"3. При отсутствии ответа - повтор через 10-20с, затем перезапуск VPN.",
			w,
		)
	})

	checkRow := container.NewBorder(nil, nil, nil, btnInfo, checkConn)

	errorText := canvas.NewText("", color.NRGBA{R: 255, G: 82, B: 82, A: 255})
	errorText.TextSize = 13
	errorText.Hide()

	statusText := canvas.NewText("Статус: Отключено", color.NRGBA{R: 207, G: 216, B: 220, A: 255})
	statusText.TextSize = 14
	statusText.TextStyle = fyne.TextStyle{Bold: true}

	pingText := canvas.NewText("", color.NRGBA{R: 0, G: 230, B: 118, A: 255})
	pingText.TextSize = 13
	pingText.TextStyle = fyne.TextStyle{Bold: true}

	ipText := canvas.NewText("", color.NRGBA{R: 128, G: 216, B: 255, A: 255})
	ipText.TextSize = 13
	ipText.TextStyle = fyne.TextStyle{Bold: true}

	logLabel := widget.NewLabel("")
	logLabel.TextStyle = fyne.TextStyle{Monospace: true}
	logLabel.Wrapping = fyne.TextWrapWord
	logScroll := container.NewVScroll(logLabel)
	logScroll.SetMinSize(fyne.NewSize(480, 210))

	var btnConnect, btnDisconnect, btnPing, btnCheckIP *widget.Button

	setUIState := func(st string) {
		switch st {
		case "CONNECTING":
			statusText.Text = "Статус: Подключение к серверу..."
			statusText.Color = color.NRGBA{R: 255, G: 213, B: 79, A: 255}
			btnConnect.Disable(); btnDisconnect.Enable(); btnPing.Disable(); btnCheckIP.Disable()
		case "CONNECTED":
			statusText.Text = "Статус: Подключено"
			statusText.Color = color.NRGBA{R: 0, G: 230, B: 118, A: 255}
			btnConnect.Disable(); btnDisconnect.Enable(); btnPing.Enable(); btnCheckIP.Enable()
		case "ERROR":
			statusText.Text = "Статус: Не удалось подключиться — VPN выключен"
			statusText.Color = color.NRGBA{R: 255, G: 82, B: 82, A: 255}
			btnConnect.Enable(); btnDisconnect.Disable(); btnPing.Disable(); btnCheckIP.Disable()
		default:
			statusText.Text = "Статус: Отключено"
			statusText.Color = color.NRGBA{R: 207, G: 216, B: 220, A: 255}
			btnConnect.Enable(); btnDisconnect.Disable(); btnPing.Disable(); btnCheckIP.Disable()
		}
		statusText.Refresh()
	}

	hexPinRe := regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

	btnConnect = widget.NewButton("Connect", func() {
		srv := strings.TrimSpace(serverEntry.Text)
		psk := strings.TrimSpace(pskEntry.Text)
		pin := strings.ReplaceAll(strings.TrimSpace(pinEntry.Text), ":", "")

		parts := strings.Split(srv, ":")
		port := 0
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}
		if srv == "" || len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || port < 1 || port > 65535 {
			errorText.Text = "Ошибка: укажите сервер в формате IP:Port."
			errorText.Show()
			return
		}
		if psk == "" {
			errorText.Text = "Ошибка: не указан PSK."
			errorText.Show()
			return
		}
		if pin != "" && !hexPinRe.MatchString(pin) {
			errorText.Text = "Ошибка: SHA-256 Pin должен содержать 64 hex-символа."
			errorText.Show()
			return
		}
		errorText.Hide()

		prefs.SetString("server", srv)
		prefs.SetString("psk", psk)
		prefs.SetString("pin", pin)
		prefs.SetBool("check_conn", checkConn.Checked)

		pingText.Text = ""; pingText.Refresh()
		ipText.Text = ""; ipText.Refresh()

		setUIState("CONNECTING")
		go func() {
			if err := launchHelper(srv, psk, pin, checkConn.Checked); err != nil {
				errorText.Text = err.Error()
				errorText.Show()
				setUIState("DISCONNECTED")
			}
		}()
	})
	btnConnect.Importance = widget.HighImportance

	btnDisconnect = widget.NewButton("Disconnect", func() {
		go func() {
			_ = stopHelper()
			pingText.Text = ""; pingText.Refresh()
			ipText.Text = ""; ipText.Refresh()
			setUIState("DISCONNECTED")
		}()
	})
	btnDisconnect.Disable()

	btnPing = widget.NewButton("Тест ping 8.8.8.8", func() {
		pingText.Text = "Выполняется ping 8.8.8.8..."
		pingText.Color = color.NRGBA{R: 255, G: 213, B: 79, A: 255}
		pingText.Refresh()
		go func() {
			code, msg := callCtl("/ping")
			pingText.Text = msg
			if code == 200 {
				pingText.Color = color.NRGBA{R: 0, G: 230, B: 118, A: 255}
			} else {
				pingText.Color = color.NRGBA{R: 255, G: 82, B: 82, A: 255}
			}
			pingText.Refresh()
		}()
	})
	btnPing.Disable()

	btnCheckIP = widget.NewButton("Проверить IP и страну", func() {
		ipText.Text = "Запрос ifconfig.io..."
		ipText.Color = color.NRGBA{R: 255, G: 213, B: 79, A: 255}
		ipText.Refresh()
		go func() {
			code, msg := callCtl("/checkip")
			ipText.Text = msg
			if code == 200 {
				ipText.Color = color.NRGBA{R: 0, G: 230, B: 118, A: 255}
			} else {
				ipText.Color = color.NRGBA{R: 255, G: 82, B: 82, A: 255}
			}
			ipText.Refresh()
		}()
	})
	btnCheckIP.Disable()

	content := container.NewVBox(
		logoLabel, subTitle, widget.NewSeparator(),
		widget.NewLabel("Server IP:Port"), serverEntry,
		widget.NewLabel("Pre-Shared Key (PSK)"), pskEntry,
		widget.NewLabel("Cert SHA-256 Pin"), pinEntry,
		checkRow, errorText,
		container.NewGridWithColumns(2, btnConnect, btnDisconnect),
		statusText,
		container.NewGridWithColumns(2, btnPing, btnCheckIP),
		pingText, ipText,
		widget.NewLabel("Логи подключения:"), logScroll,
	)

	w.SetContent(container.NewPadded(content))

	go func() {
		lastState := "DISCONNECTED"
		lastLogCount := 0
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			resp, err := fetchStatus()
			if err != nil {
				if lastState == "CONNECTED" || lastState == "CONNECTING" {
					lastState = "DISCONNECTED"
					setUIState("DISCONNECTED")
				}
				continue
			}
			if resp.State != lastState {
				lastState = resp.State
				setUIState(resp.State)
			}
			if len(resp.Logs) != lastLogCount {
				lastLogCount = len(resp.Logs)
				logLabel.SetText(strings.Join(resp.Logs, "\n"))
				logScroll.ScrollToBottom()
			}
		}
	}()

	w.SetOnClosed(func() { _ = stopHelper() })
	w.ShowAndRun()
}

func ensureHelperExtracted() error {
	if len(embeddedHelper) == 0 {
		return fmt.Errorf("встроенный хелпер пуст")
	}
	wantHash := sha256.Sum256(embeddedHelper)
	if existing, err := os.ReadFile(helperPath); err == nil {
		gotHash := sha256.Sum256(existing)
		if bytes.Equal(wantHash[:], gotHash[:]) {
			_ = os.Chmod(helperPath, 0755)
			return nil
		}
	}
	return os.WriteFile(helperPath, embeddedHelper, 0755)
}

func launchHelper(server, psk, pin string, checkConn bool) error {
	if err := ensureHelperExtracted(); err != nil {
		return err
	}
	cfgBytes, _ := json.Marshal(map[string]any{"server": server, "psk": psk, "pin": pin, "check_conn": checkConn})
	cfgPath := fmt.Sprintf("/tmp/winrm-vpn-linux-cfg-%d.json", os.Getpid())
	if err := os.WriteFile(cfgPath, cfgBytes, 0600); err != nil {
		return err
	}
	shellCmd := fmt.Sprintf("nohup '%s' -config '%s' >/tmp/winrm-vpn-linux.log 2>&1 </dev/null &", helperPath, cfgPath)
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.Command("sh", "-c", shellCmd)
	} else if _, err := exec.LookPath("pkexec"); err == nil {
		cmd = exec.Command("pkexec", "sh", "-c", shellCmd)
	} else {
		_ = os.Remove(cfgPath)
		return fmt.Errorf("не найден pkexec (установите policykit-1 или запустите GUI с sudo)")
	}
	if err := cmd.Run(); err != nil {
		_ = os.Remove(cfgPath)
		return fmt.Errorf("запуск отменён или ошибка прав (%v)", err)
	}
	return nil
}

func loadMeta() (*CtlMeta, error) {
	raw, err := os.ReadFile(ctlMetaPath)
	if err != nil {
		return nil, err
	}
	var m CtlMeta
	return &m, json.Unmarshal(raw, &m)
}

func fetchStatus() (*StatusResponse, error) {
	m, err := loadMeta()
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 1 * time.Second}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/status", m.Port), nil)
	req.Header.Set("X-Ctl-Token", m.Token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var st StatusResponse
	return &st, json.NewDecoder(resp.Body).Decode(&st)
}

func callCtl(path string) (int, string) {
	m, err := loadMeta()
	if err != nil {
		return 500, "Хелпер не запущен"
	}
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d%s", m.Port, path), nil)
	req.Header.Set("X-Ctl-Token", m.Token)
	resp, err := client.Do(req)
	if err != nil {
		return 500, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func pushWatchdog(enabled bool) error {
	code, _ := callCtl(fmt.Sprintf("/watchdog?enabled=%v", enabled))
	if code != 200 {
		return fmt.Errorf("status %d", code)
	}
	return nil
}

func stopHelper() error {
	code, _ := callCtl("/stop")
	if code != 200 {
		return fmt.Errorf("status %d", code)
	}
	return nil
}
