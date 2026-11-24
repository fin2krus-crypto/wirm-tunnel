package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultWebPort = 49777

type PanelConfig struct {
	Port     int    `json:"port"`
	Password string `json:"password,omitempty"`
}

func loadPanelConfig(dataDir string) PanelConfig {
	cfg := PanelConfig{Port: defaultWebPort}
	raw, err := os.ReadFile(filepath.Join(dataDir, "panel.json"))
	if err == nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		cfg.Port = defaultWebPort
	}
	return cfg
}

func savePanelConfig(dataDir string, cfg PanelConfig) error {
	_ = os.MkdirAll(dataDir, 0700)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, "panel.json"), data, 0600)
}

type WebPanelServer struct {
	mu          sync.Mutex
	dataDir     string
	statsMgr    *StatsManager
	vpnEngine   *VPNEngine
	cfg         PanelConfig
	sessionKey  string
	curListener net.Listener
	curServer   *http.Server
	handler     http.Handler
}

func StartWebPanel(dataDir string, portOverride int, statsMgr *StatsManager, vpnEngine *VPNEngine) (*WebPanelServer, error) {
	cfg := loadPanelConfig(dataDir)
	if portOverride > 0 && portOverride <= 65535 {
		cfg.Port = portOverride
		_ = savePanelConfig(dataDir, cfg)
	}
	statsMgr.SetWebPort(cfg.Port)

	var sk [16]byte
	_, _ = rand.Read(sk[:])

	wp := &WebPanelServer{
		dataDir:    dataDir,
		statsMgr:   statsMgr,
		vpnEngine:  vpnEngine,
		cfg:        cfg,
		sessionKey: hex.EncodeToString(sk[:]),
	}
	wp.handler = wp.buildRouter()

	if err := wp.listenOnPort(cfg.Port); err != nil {
		return nil, err
	}
	return wp, nil
}

func (wp *WebPanelServer) Port() int {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	return wp.cfg.Port
}

func (wp *WebPanelServer) listenOnPort(port int) error {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           wp.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	wp.mu.Lock()
	oldLn := wp.curListener
	oldSrv := wp.curServer
	wp.curListener = ln
	wp.curServer = srv
	wp.cfg.Port = port
	wp.mu.Unlock()

	wp.statsMgr.SetWebPort(port)

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[WEB] Server error on %s: %v", addr, err)
		}
	}()

	if oldSrv != nil {
		go func() {
			time.Sleep(350 * time.Millisecond)
			_ = oldSrv.Close()
			if oldLn != nil {
				_ = oldLn.Close()
			}
		}()
	}

	return nil
}

func (wp *WebPanelServer) isAuthorized(r *http.Request) bool {
	wp.mu.Lock()
	pass := wp.cfg.Password
	sess := wp.sessionKey
	wp.mu.Unlock()

	if pass == "" {
		return true
	}
	if c, err := r.Cookie("winrm_panel_auth"); err == nil {
		if subtle.ConstantTimeCompare([]byte(c.Value), []byte(sess)) == 1 {
			return true
		}
	}
	if hdr := r.Header.Get("X-Panel-Pass"); hdr != "" {
		if subtle.ConstantTimeCompare([]byte(hdr), []byte(pass)) == 1 {
			return true
		}
	}
	return false
}

func (wp *WebPanelServer) buildRouter() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, webPanelHTML)
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		wp.mu.Lock()
		expected := wp.cfg.Password
		sess := wp.sessionKey
		wp.mu.Unlock()

		if expected != "" && subtle.ConstantTimeCompare([]byte(body.Password), []byte(expected)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Неверный пароль"})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "winrm_panel_auth",
			Value:    sess,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   86400 * 7,
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if !wp.isAuthorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"auth_required": true})
			return
		}
		snap := wp.statsMgr.Snapshot()
		wp.mu.Lock()
		hasPass := wp.cfg.Password != ""
		wp.mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"stats":        snap,
			"has_password": hasPass,
		})
	})

	mux.HandleFunc("/api/vpn/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !wp.isAuthorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if err := wp.vpnEngine.Start(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/vpn/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !wp.isAuthorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		wp.vpnEngine.Stop()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/vpn/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !wp.isAuthorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if err := wp.vpnEngine.Restart(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/users/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !wp.isAuthorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		var body struct {
			PSK   string `json:"psk"`
			Label string `json:"label"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "неверный запрос"})
			return
		}
		psk := strings.TrimSpace(body.PSK)
		if psk == "" {
			psk = generateRandomPSK()
		}
		if err := wp.statsMgr.AddUserDirect(psk, body.Label); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "psk": psk})
	})

	mux.HandleFunc("/api/users/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !wp.isAuthorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		var body struct {
			OldPSK string `json:"old_psk"`
			NewPSK string `json:"new_psk"`
			Label  string `json:"label"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "неверный запрос"})
			return
		}
		if err := wp.statsMgr.UpdateUserDirect(body.OldPSK, body.NewPSK, body.Label); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/users/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !wp.isAuthorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		var body struct {
			PSK string `json:"psk"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "неверный запрос"})
			return
		}
		if err := wp.statsMgr.DeleteUserDirect(body.PSK); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/settings/web", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !wp.isAuthorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		var body struct {
			Port          int    `json:"port"`
			Password      string `json:"password"`
			ClearPassword bool   `json:"clear_password"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "неверный JSON"})
			return
		}
		if body.Port < 1 || body.Port > 65535 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "порт должен быть от 1 до 65535"})
			return
		}
		if body.Port == 5986 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "порт 5986 занят VPN-сервером WinRM"})
			return
		}

		wp.mu.Lock()
		oldPort := wp.cfg.Port
		newCfg := wp.cfg
		wp.mu.Unlock()

		if body.ClearPassword {
			newCfg.Password = ""
		} else if body.Password != "" {
			newCfg.Password = body.Password
		}

		portChanged := (body.Port != oldPort)
		if portChanged {
			if err := wp.listenOnPort(body.Port); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"ok":    false,
					"error": fmt.Sprintf("не удалось занять порт %d: %v", body.Port, err),
				})
				return
			}
			newCfg.Port = body.Port
			openUfwPortIfActive(body.Port)
		}

		wp.mu.Lock()
		wp.cfg = newCfg
		wp.mu.Unlock()
		_ = savePanelConfig(wp.dataDir, newCfg)

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"port_changed": portChanged,
			"new_port":     newCfg.Port,
		})
	})

	return mux
}

func openUfwPortIfActive(port int) {
	if _, err := exec.LookPath("ufw"); err != nil {
		return
	}
	out, err := exec.Command("ufw", "status").CombinedOutput()
	if err == nil && strings.Contains(string(out), "Status: active") {
		_ = exec.Command("ufw", "allow", fmt.Sprintf("%d/tcp", port)).Run()
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

const webPanelHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>WinRM-VPN Control Panel</title>
<style>
  :root {
    --bg: #0d1117;
    --card: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --green: #00e676;
    --cyan: #38bdf8;
    --amber: #f59e0b;
    --red: #ff5252;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 12px;
    line-height: 1.45;
  }
  .container { max-width: 960px; margin: 0 auto; display: flex; flex-direction: column; gap: 12px; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px;
  }
  .header { text-align: center; }
  .ascii-logo {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: clamp(5.5px, 2.05vw, 11px);
    line-height: 1.15;
    color: var(--green);
    white-space: pre;
    overflow-x: auto;
    margin-bottom: 8px;
  }
  .subtitle { font-size: 12px; color: var(--muted); font-family: monospace; }
  .status-pill {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600;
    margin-top: 8px; border: 1px solid var(--border);
  }
  .dot { width: 8px; height: 8px; border-radius: 50%; }
  .dot-on { background: var(--green); box-shadow: 0 0 8px var(--green); }
  .dot-off { background: var(--red); }
  .grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
  }
  @media (min-width: 680px) {
    .grid { grid-template-columns: repeat(4, 1fr); }
  }
  .stat-box {
    background: #0d1117;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 12px;
  }
  .stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.4px; }
  .stat-val { font-size: 16px; font-weight: 700; margin-top: 3px; font-family: monospace; }
  .stat-sub { font-size: 11px; color: var(--muted); margin-top: 2px; font-family: monospace; }
  .section-title {
    font-size: 14px; font-weight: 700; margin-bottom: 10px;
    display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap;
  }
  .btn-row { display: flex; gap: 8px; flex-wrap: wrap; }
  button {
    min-height: 42px;
    padding: 8px 14px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: #21262d;
    color: var(--text);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    flex: 1 1 auto;
    transition: opacity 0.15s;
  }
  button:active { opacity: 0.75; }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-green { background: #14532d; border-color: #22c55e; color: #dcfce7; }
  .btn-red { background: #7f1d1d; border-color: #ef4444; color: #fee2e2; }
  .btn-amber { background: #78350f; border-color: #f59e0b; color: #fef3c7; }
  .btn-cyan { background: #0c4a6e; border-color: #38bdf8; color: #e0f2fe; }
  .btn-sm { min-height: 34px; padding: 5px 10px; font-size: 12px; flex: 0 0 auto; }
  input[type="text"], input[type="number"], input[type="password"] {
    width: 100%;
    min-height: 42px;
    padding: 8px 12px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: #0d1117;
    color: var(--text);
    font-size: 13px;
    font-family: monospace;
  }
  .form-row { display: flex; gap: 8px; flex-direction: column; }
  @media (min-width: 600px) {
    .form-row { flex-direction: row; }
  }
  .chart-wrap {
    width: 100%;
    height: 190px;
    background: #0d1117;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 8px;
    position: relative;
  }
  canvas { width: 100%; height: 100%; display: block; }
  .legend { display: flex; gap: 14px; font-size: 12px; font-family: monospace; }
  .user-card {
    background: #0d1117;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px;
    margin-bottom: 8px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .user-card.online { border-color: #22c55e66; }
  .user-top { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
  .badge {
    font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 700; font-family: monospace;
  }
  .badge-on { background: #14532d; color: #4ade80; }
  .badge-off { background: #21262d; color: #8b949e; }
  .psk-box {
    font-family: monospace; font-size: 12px; word-break: break-all;
    background: #161b22; padding: 6px 8px; border-radius: 6px; border: 1px solid #30363d;
  }
  .meta-line { font-size: 12px; color: var(--muted); font-family: monospace; }
  .pin-bar {
    font-family: monospace; font-size: 11px; word-break: break-all;
    background: #0d1117; padding: 8px 10px; border-radius: 8px; border: 1px solid var(--border);
    margin-top: 8px; display: flex; justify-content: space-between; align-items: center; gap: 8px;
  }
  .toast {
    position: fixed; bottom: 16px; left: 50%; transform: translateX(-50%);
    background: #1f2937; color: #fff; border: 1px solid var(--green);
    padding: 10px 16px; border-radius: 10px; font-size: 13px; z-index: 999; display: none;
    max-width: 92vw; text-align: center;
  }
  .modal-bg {
    position: fixed; inset: 0; background: rgba(0,0,0,0.75);
    display: none; align-items: center; justify-content: center; padding: 16px; z-index: 1000;
  }
  .modal {
    background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 16px; width: 100%; max-width: 420px; display: flex; flex-direction: column; gap: 10px;
  }
</style>
</head>
<body>
<div class="container">
  <div class="card header">
<pre class="ascii-logo"> __        ___       ____  __  __    __     ______  _   _
 \ \      / (_)_ __ |  _ \|  \/  |   \ \   / /  _ \| \ | |
  \ \ /\ / /| | '_ \| |_) | |\/| |____\ \ / /| |_) |  \| |
   \ V  V / | | | | |  _ &lt;| |  | |_____\ V / |  __/| |\  |
    \_/\_/  |_|_| |_|_| \_\_|  |_|      \_/  |_|   |_| \_|</pre>
    <div class="subtitle" id="subInfo">WinRM-VPN Server v0.3.0 | Панель управления</div>
    <div>
      <span class="status-pill" id="vpnStatusPill">
        <span class="dot dot-off" id="vpnDot"></span>
        <span id="vpnStatusText">Загрузка...</span>
      </span>
    </div>
    <div class="pin-bar">
      <span><b>Cert SHA-256 Pin:</b> <span id="certPinVal">—</span></span>
      <button class="btn-sm" onclick="copyText(document.getElementById('certPinVal').textContent)">Копировать</button>
    </div>
  </div>

  <div class="grid">
    <div class="stat-box">
      <div class="stat-label">Внешний IP</div>
      <div class="stat-val" id="statIP">—</div>
      <div class="stat-sub" id="statHost">WIN-...</div>
    </div>
    <div class="stat-box">
      <div class="stat-label">Время работы</div>
      <div class="stat-val" id="statUptime">—</div>
      <div class="stat-sub" id="statListen">:5986</div>
    </div>
    <div class="stat-box">
      <div class="stat-label">Пользователи</div>
      <div class="stat-val" id="statUsers">0 / 0</div>
      <div class="stat-sub">онлайн / всего</div>
    </div>
    <div class="stat-box">
      <div class="stat-label">Трафик (с запуска)</div>
      <div class="stat-val" id="statTotalTraffic">0 B</div>
      <div class="stat-sub" id="statRxTxSub">Вх 0 B | Исх 0 B</div>
    </div>
  </div>

  <div class="card">
    <div class="section-title">Управление VPN-сервером</div>
    <div class="btn-row">
      <button class="btn-green" id="btnStart" onclick="vpnAction('start')">Включить VPN</button>
      <button class="btn-red" id="btnStop" onclick="vpnAction('stop')">Выключить VPN</button>
      <button class="btn-amber" id="btnRestart" onclick="vpnAction('restart')">Перезапустить</button>
    </div>
  </div>

  <div class="card">
    <div class="section-title">
      <span>Трафик VPN в реальном времени</span>
      <div class="legend">
        <span style="color: var(--green);">● Вх: <b id="speedRx">0 B/s</b></span>
        <span style="color: var(--cyan);">● Исх: <b id="speedTx">0 B/s</b></span>
      </div>
    </div>
    <div class="chart-wrap">
      <canvas id="trafficChart"></canvas>
    </div>
  </div>

  <div class="card">
    <div class="section-title">
      <span>Активные пользователи (Онлайн)</span>
      <span class="badge badge-on" id="onlineBadge">0</span>
    </div>
    <div id="activeUsersList"><div class="meta-line">Нет подключённых пользователей</div></div>
  </div>

  <div class="card">
    <div class="section-title">Управление пользователями</div>
    <div class="form-row" style="margin-bottom: 12px;">
      <input type="text" id="newLabel" placeholder="Имя / заметка (напр. iPhone)" />
      <input type="text" id="newPSK" placeholder="PSK (оставьте пустым для автогенерации)" />
      <button class="btn-cyan" style="flex: 0 0 auto;" onclick="createUser()">+ Создать</button>
    </div>
    <div id="allUsersList"></div>
  </div>

  <div class="card">
    <div class="section-title">Настройки веб-панели</div>
    <div class="form-row" style="margin-bottom: 8px;">
      <input type="number" id="webPortInput" placeholder="Порт веб-панели (по умолч. 49777)" min="1" max="65535" />
      <input type="password" id="webPassInput" placeholder="Новый пароль панели (опционально)" />
    </div>
    <div class="btn-row">
      <button class="btn-cyan" onclick="saveWebSettings(false)">Сохранить порт / пароль</button>
      <button class="btn-sm" id="btnClearPass" style="display:none;" onclick="saveWebSettings(true)">Сбросить пароль</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="editModal">
  <div class="modal">
    <div class="section-title">Редактировать пользователя</div>
    <input type="hidden" id="editOldPSK" />
    <label class="meta-line">Имя / заметка:</label>
    <input type="text" id="editLabel" placeholder="Имя устройства" />
    <label class="meta-line">PSK ключ:</label>
    <input type="text" id="editNewPSK" />
    <div class="btn-row">
      <button class="btn-sm" onclick="genEditPSK()">Сгенерировать PSK</button>
      <button class="btn-green" onclick="submitEditUser()">Сохранить</button>
      <button class="btn-sm" onclick="closeEditModal()">Отмена</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="loginModal">
  <div class="modal">
    <div class="section-title">Вход в панель WinRM-VPN</div>
    <input type="password" id="loginPass" placeholder="Введите пароль панели" />
    <button class="btn-green" onclick="submitLogin()">Войти</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let lastHistory = [];
let portRedirecting = false;

function showToast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.style.display = 'block';
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => { el.style.display = 'none'; }, 3000);
}

function copyText(txt) {
  if (!txt || txt === '—') return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(() => showToast('Скопировано в буфер'));
  } else {
    const ta = document.createElement('textarea');
    ta.value = txt;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Скопировано в буфер');
  }
}

function fmtBytes(b) {
  if (!b || b < 1024) return (b || 0) + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { b /= 1024; i++; } while (b >= 1024 && i < units.length - 1);
  return b.toFixed(2) + ' ' + units[i];
}

function fmtUptime(sec) {
  if (!sec || sec <= 0) return '0с';
  const d = Math.floor(sec / 86400); sec %= 86400;
  const h = Math.floor(sec / 3600); sec %= 3600;
  const m = Math.floor(sec / 60); const s = sec % 60;
  if (d > 0) return d + 'д ' + h + 'ч ' + m + 'м';
  if (h > 0) return h + 'ч ' + m + 'м ' + s + 'с';
  if (m > 0) return m + 'м ' + s + 'с';
  return s + 'с';
}

function esc(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function apiPost(url, data) {
  const r = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data || {})
  });
  return r.json();
}

async function vpnAction(act) {
  try {
    const res = await apiPost('/api/vpn/' + act);
    if (res.ok) {
      showToast(act === 'start' ? 'VPN включён' : (act === 'stop' ? 'VPN выключен' : 'VPN перезапущен'));
      pollStats();
    } else {
      showToast('Ошибка: ' + (res.error || 'неизвестно'));
    }
  } catch (e) {
    showToast('Ошибка связи с сервером');
  }
}

async function createUser() {
  const label = document.getElementById('newLabel').value.trim();
  const psk = document.getElementById('newPSK').value.trim();
  try {
    const res = await apiPost('/api/users/create', {psk, label});
    if (res.ok) {
      document.getElementById('newLabel').value = '';
      document.getElementById('newPSK').value = '';
      showToast('Пользователь создан!');
      pollStats();
    } else {
      showToast('Ошибка: ' + res.error);
    }
  } catch (e) { showToast('Ошибка создания'); }
}

async function deleteUser(psk) {
  if (!confirm('Удалить пользователя с PSK ' + psk.slice(0, 10) + '...?')) return;
  try {
    const res = await apiPost('/api/users/delete', {psk});
    if (res.ok) {
      showToast('Пользователь удалён');
      pollStats();
    } else {
      showToast('Ошибка: ' + res.error);
    }
  } catch (e) { showToast('Ошибка удаления'); }
}

function openEditModal(psk, label) {
  document.getElementById('editOldPSK').value = psk;
  document.getElementById('editNewPSK').value = psk;
  document.getElementById('editLabel').value = label || '';
  document.getElementById('editModal').style.display = 'flex';
}

function closeEditModal() {
  document.getElementById('editModal').style.display = 'none';
}

function genEditPSK() {
  const arr = new Uint8Array(24);
  crypto.getRandomValues(arr);
  document.getElementById('editNewPSK').value = Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

async function submitEditUser() {
  const old_psk = document.getElementById('editOldPSK').value;
  const new_psk = document.getElementById('editNewPSK').value.trim();
  const label = document.getElementById('editLabel').value.trim();
  try {
    const res = await apiPost('/api/users/update', {old_psk, new_psk, label});
    if (res.ok) {
      closeEditModal();
      showToast('Пользователь обновлён');
      pollStats();
    } else {
      showToast('Ошибка: ' + res.error);
    }
  } catch (e) { showToast('Ошибка обновления'); }
}

async function saveWebSettings(clearPass) {
  const port = parseInt(document.getElementById('webPortInput').value, 10);
  const password = document.getElementById('webPassInput').value;
  if (!port || port < 1 || port > 65535) {
    showToast('Укажите корректный порт (1-65535)');
    return;
  }
  try {
    const res = await apiPost('/api/settings/web', {port, password, clear_password: clearPass});
    if (!res.ok) {
      showToast('Ошибка: ' + res.error);
      return;
    }
    document.getElementById('webPassInput').value = '';
    if (res.port_changed) {
      portRedirecting = true;
      showToast('Порт изменён на ' + res.new_port + '. Переход через 1.5 сек...');
      setTimeout(() => {
        window.location.href = window.location.protocol + '//' + window.location.hostname + ':' + res.new_port + '/';
      }, 1500);
    } else {
      showToast('Настройки сохранены');
      pollStats();
    }
  } catch (e) {
    showToast('Ошибка сохранения настроек');
  }
}

async function submitLogin() {
  const password = document.getElementById('loginPass').value;
  const res = await apiPost('/api/login', {password});
  if (res.ok) {
    document.getElementById('loginModal').style.display = 'none';
    pollStats();
  } else {
    showToast(res.error || 'Неверный пароль');
  }
}

function renderUsers(users) {
  const activeEl = document.getElementById('activeUsersList');
  const allEl = document.getElementById('allUsersList');

  const active = users.filter(u => u.online);
  document.getElementById('onlineBadge').textContent = active.length;

  if (active.length === 0) {
    activeEl.innerHTML = '<div class="meta-line">Нет подключённых пользователей</div>';
  } else {
    activeEl.innerHTML = active.map(u => {
      const title = u.label ? esc(u.label) + ' ' : '';
      return '<div class="user-card online">' +
        '<div class="user-top">' +
          '<span><b>' + title + '</b><span class="badge badge-on">ОНЛАЙН (' + u.online_conns + ')</span></span>' +
          '<span class="meta-line">' + esc(u.last_connected) + '</span>' +
        '</div>' +
        '<div class="psk-box">' + esc(u.psk) + '</div>' +
        '<div class="meta-line">С запуска: Вх ' + fmtBytes(u.session_rx) + ' / Исх ' + fmtBytes(u.session_tx) +
        ' | Сегодня: Вх ' + fmtBytes(u.today_rx) + ' / Исх ' + fmtBytes(u.today_tx) + '</div>' +
      '</div>';
    }).join('');
  }

  if (users.length === 0) {
    allEl.innerHTML = '<div class="meta-line">Список пользователей пуст</div>';
  } else {
    allEl.innerHTML = users.map((u, idx) => {
      const badge = u.online
        ? '<span class="badge badge-on">ОНЛАЙН</span>'
        : '<span class="badge badge-off">оффлайн</span>';
      const title = u.label ? '<b>' + esc(u.label) + '</b> ' : '<b>#' + (idx + 1) + '</b> ';
      const encPsk = encodeURIComponent(u.psk);
      const encLbl = encodeURIComponent(u.label || '');
      return '<div class="user-card ' + (u.online ? 'online' : '') + '">' +
        '<div class="user-top">' +
          '<span>' + title + badge + '</span>' +
          '<div class="btn-row" style="gap:6px;">' +
            '<button class="btn-sm" onclick="copyText(decodeURIComponent(\'' + encPsk + '\'))">Копировать</button>' +
            '<button class="btn-sm btn-cyan" onclick="openEditModal(decodeURIComponent(\'' + encPsk + '\'), decodeURIComponent(\'' + encLbl + '\'))">Изменить</button>' +
            '<button class="btn-sm btn-red" onclick="deleteUser(decodeURIComponent(\'' + encPsk + '\'))">Удалить</button>' +
          '</div>' +
        '</div>' +
        '<div class="psk-box">' + esc(u.psk) + '</div>' +
        '<div class="meta-line">С запуска: Вх ' + fmtBytes(u.session_rx) + ' / Исх ' + fmtBytes(u.session_tx) + '</div>' +
        '<div class="meta-line">За сегодня: Вх ' + fmtBytes(u.today_rx) + ' / Исх ' + fmtBytes(u.today_tx) +
        ' | Посл. вход: ' + (esc(u.last_connected) || 'Никогда') + '</div>' +
      '</div>';
    }).join('');
  }
}

function drawChart(history) {
  const canvas = document.getElementById('trafficChart');
  const rect = canvas.parentElement.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(200, (rect.width - 16) * dpr);
  canvas.height = Math.max(100, (rect.height - 16) * dpr);

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  const w = canvas.width / dpr;
  const h = canvas.height / dpr;

  ctx.clearRect(0, 0, w, h);

  if (!history || history.length < 2) {
    ctx.fillStyle = '#8b949e';
    ctx.font = '12px monospace';
    ctx.fillText('Сбор данных трафика...', 12, h / 2);
    return;
  }

  let maxVal = 1024;
  for (const p of history) {
    if (p.rx_bps > maxVal) maxVal = p.rx_bps;
    if (p.tx_bps > maxVal) maxVal = p.tx_bps;
  }
  maxVal *= 1.15;

  const padL = 62, padR = 8, padT = 10, padB = 20;
  const cw = w - padL - padR;
  const ch = h - padT - padB;

  ctx.strokeStyle = '#21262d';
  ctx.lineWidth = 1;
  ctx.fillStyle = '#8b949e';
  ctx.font = '10px monospace';

  for (let i = 0; i <= 3; i++) {
    const y = padT + (ch * i) / 3;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
    const val = maxVal * (1 - i / 3);
    ctx.fillText(fmtBytes(val) + '/s', 2, y + 3);
  }

  function plotLine(key, strokeCol, fillCol) {
    ctx.beginPath();
    history.forEach((p, idx) => {
      const x = padL + (idx / (history.length - 1)) * cw;
      const y = padT + ch - (p[key] / maxVal) * ch;
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = strokeCol;
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.lineTo(padL + cw, padT + ch);
    ctx.lineTo(padL, padT + ch);
    ctx.closePath();
    ctx.fillStyle = fillCol;
    ctx.fill();
  }

  plotLine('tx_bps', '#38bdf8', 'rgba(56, 189, 248, 0.14)');
  plotLine('rx_bps', '#00e676', 'rgba(0, 230, 118, 0.16)');

  ctx.fillStyle = '#8b949e';
  ctx.fillText(history[0].time, padL, h - 4);
  const lastT = history[history.length - 1].time;
  ctx.fillText(lastT, w - padR - ctx.measureText(lastT).width, h - 4);
}

async function pollStats() {
  if (portRedirecting) return;
  try {
    const r = await fetch('/api/stats');
    if (r.status === 401) {
      document.getElementById('loginModal').style.display = 'flex';
      return;
    }
    const data = await r.json();
    if (!data.stats) return;
    const s = data.stats;

    document.getElementById('subInfo').textContent = 'WinRM-VPN Server v' + s.version + ' | Веб-панель :' + s.web_port;
    const dot = document.getElementById('vpnDot');
    const stText = document.getElementById('vpnStatusText');
    if (s.vpn_running) {
      dot.className = 'dot dot-on';
      stText.textContent = 'VPN АКТИВЕН (PID ' + s.pid + ')';
      document.getElementById('btnStart').disabled = true;
      document.getElementById('btnStop').disabled = false;
    } else {
      dot.className = 'dot dot-off';
      stText.textContent = 'VPN ОСТАНОВЛЕН';
      document.getElementById('btnStart').disabled = false;
      document.getElementById('btnStop').disabled = true;
    }

    document.getElementById('certPinVal').textContent = s.cert_pin || '—';
    document.getElementById('statIP').textContent = s.external_ip || '—';
    document.getElementById('statHost').textContent = s.host_name || '—';
    document.getElementById('statUptime').textContent = s.vpn_running ? fmtUptime(s.uptime_sec) : 'Остановлен';
    document.getElementById('statListen').textContent = s.listen_addr || ':5986';
    document.getElementById('statUsers').textContent = s.online_users + ' / ' + s.total_users;
    document.getElementById('statTotalTraffic').textContent = fmtBytes((s.total_rx || 0) + (s.total_tx || 0));
    document.getElementById('statRxTxSub').textContent = 'Вх ' + fmtBytes(s.total_rx) + ' | Исх ' + fmtBytes(s.total_tx);
    document.getElementById('speedRx').textContent = fmtBytes(s.rx_bps) + '/s';
    document.getElementById('speedTx').textContent = fmtBytes(s.tx_bps) + '/s';

    const portInput = document.getElementById('webPortInput');
    if (document.activeElement !== portInput && !portInput.value) {
      portInput.value = s.web_port;
    }
    document.getElementById('btnClearPass').style.display = data.has_password ? 'inline-block' : 'none';

    lastHistory = s.history || [];
    drawChart(lastHistory);
    renderUsers(s.users || []);
  } catch (e) {}
}

window.addEventListener('resize', () => drawChart(lastHistory));
pollStats();
setInterval(pollStats, 1000);
</script>
</body>
</html>`
