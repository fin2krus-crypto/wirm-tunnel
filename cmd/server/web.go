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
	Enabled  bool   `json:"enabled"`
	Password string `json:"password,omitempty"`
}

func loadPanelConfig(dataDir string) PanelConfig {
	cfg := PanelConfig{Port: defaultWebPort, Enabled: true}
	if raw, err := os.ReadFile(filepath.Join(dataDir, "panel.json")); err == nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	if cfg.Port < 1 || cfg.Port > 65535 { cfg.Port = defaultWebPort }
	return cfg
}

func savePanelConfig(dataDir string, cfg PanelConfig) error {
	_ = os.MkdirAll(dataDir, 0700)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil { return err }
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

func InitWebPanel(dataDir string, portOverride int, statsMgr *StatsManager, vpnEngine *VPNEngine) (*WebPanelServer, error) {
	cfg := loadPanelConfig(dataDir)
	if portOverride > 0 && portOverride <= 65535 {
		cfg.Port = portOverride; cfg.Enabled = true
		_ = savePanelConfig(dataDir, cfg)
	}
	var sk [16]byte; _, _ = rand.Read(sk[:])
	wp := &WebPanelServer{dataDir: dataDir, statsMgr: statsMgr, vpnEngine: vpnEngine, cfg: cfg, sessionKey: hex.EncodeToString(sk[:])}
	wp.handler = wp.buildRouter()
	if cfg.Enabled {
		if err := wp.listenOnPort(cfg.Port); err != nil {
			statsMgr.SetWebStatus(cfg.Port, false)
			return wp, err
		}
		statsMgr.SetWebStatus(cfg.Port, true)
	} else {
		statsMgr.SetWebStatus(cfg.Port, false)
	}
	return wp, nil
}

func (wp *WebPanelServer) Port() int { wp.mu.Lock(); defer wp.mu.Unlock(); return wp.cfg.Port }
func (wp *WebPanelServer) IsRunning() bool { wp.mu.Lock(); defer wp.mu.Unlock(); return wp.curListener != nil }

func (wp *WebPanelServer) Start() error {
	wp.mu.Lock()
	if wp.curListener != nil {
		wp.cfg.Enabled = true; c := wp.cfg; wp.mu.Unlock()
		_ = savePanelConfig(wp.dataDir, c); wp.statsMgr.SetWebStatus(c.Port, true); return nil
	}
	port := wp.cfg.Port; wp.mu.Unlock()
	if err := wp.listenOnPort(port); err != nil { return err }
	wp.mu.Lock(); wp.cfg.Enabled = true; c := wp.cfg; wp.mu.Unlock()
	_ = savePanelConfig(wp.dataDir, c); openUfwPortIfActive(port); wp.statsMgr.SetWebStatus(port, true)
	return nil
}

func (wp *WebPanelServer) Stop() {
	wp.mu.Lock()
	srv, ln := wp.curServer, wp.curListener
	wp.curServer, wp.curListener = nil, nil
	wp.cfg.Enabled = false; c := wp.cfg
	wp.mu.Unlock()
	if srv != nil { _ = srv.Close() }
	if ln != nil { _ = ln.Close() }
	_ = savePanelConfig(wp.dataDir, c); wp.statsMgr.SetWebStatus(c.Port, false)
}

func (wp *WebPanelServer) listenOnPort(port int) error {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil { return err }
	srv := &http.Server{Handler: wp.handler, ReadHeaderTimeout: 10 * time.Second}
	wp.mu.Lock()
	oldLn, oldSrv := wp.curListener, wp.curServer
	wp.curListener, wp.curServer, wp.cfg.Port = ln, srv, port
	wp.mu.Unlock()
	wp.statsMgr.SetWebStatus(port, true)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed { log.Printf("[WEB] %v", err) }
	}()
	if oldSrv != nil {
		go func() { time.Sleep(350 * time.Millisecond); _ = oldSrv.Close(); if oldLn != nil { _ = oldLn.Close() } }()
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
  :root { --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --green:#00e676; --cyan:#38bdf8; --red:#ff5252; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:12px; line-height:1.45; }
  .container { max-width:960px; margin:0 auto; display:flex; flex-direction:column; gap:12px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:14px; }
  .header { text-align:center; }
  .ascii-logo { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:clamp(5.5px,2.05vw,11px); line-height:1.15; color:var(--green); white-space:pre; overflow-x:auto; margin-bottom:8px; }
  .subtitle { font-size:12px; color:var(--muted); font-family:monospace; }
  .status-pill { display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:600; margin-top:8px; border:1px solid var(--border); }
  .dot { width:8px; height:8px; border-radius:50%; }
  .dot-on { background:var(--green); box-shadow:0 0 8px var(--green); }
  .dot-off { background:var(--red); }
  .grid { display:grid; grid-template-columns:repeat(2,1fr); gap:10px; }
  @media (min-width:680px) { .grid { grid-template-columns:repeat(4,1fr); } }
  .stat-box { background:#0d1117; border:1px solid var(--border); border-radius:10px; padding:10px 12px; }
  .stat-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.4px; }
  .stat-val { font-size:16px; font-weight:700; margin-top:3px; font-family:monospace; }
  .stat-sub { font-size:11px; color:var(--muted); margin-top:2px; font-family:monospace; }
  .section-title { font-size:14px; font-weight:700; margin-bottom:10px; display:flex; align-items:center; justify-content:space-between; gap:8px; flex-wrap:wrap; }
  .btn-row { display:flex; gap:8px; flex-wrap:wrap; }
  button { min-height:42px; padding:8px 14px; border-radius:8px; border:1px solid var(--border); background:#21262d; color:var(--text); font-size:13px; font-weight:600; cursor:pointer; flex:1 1 auto; }
  button:disabled { opacity:0.4; cursor:not-allowed; }
  .btn-green { background:#14532d; border-color:#22c55e; color:#dcfce7; }
  .btn-red { background:#7f1d1d; border-color:#ef4444; color:#fee2e2; }
  .btn-amber { background:#78350f; border-color:#f59e0b; color:#fef3c7; }
  .btn-cyan { background:#0c4a6e; border-color:#38bdf8; color:#e0f2fe; }
  .btn-sm { min-height:34px; padding:5px 10px; font-size:12px; flex:0 0 auto; }
  input[type="text"],input[type="number"],input[type="password"] { width:100%; min-height:42px; padding:8px 12px; border-radius:8px; border:1px solid var(--border); background:#0d1117; color:var(--text); font-size:13px; font-family:monospace; }
  .form-row { display:flex; gap:8px; flex-direction:column; }
  @media (min-width:600px) { .form-row { flex-direction:row; } }
  .chart-wrap { width:100%; height:190px; background:#0d1117; border:1px solid var(--border); border-radius:10px; padding:8px; }
  canvas { width:100%; height:100%; display:block; }
  .legend { display:flex; gap:14px; font-size:12px; font-family:monospace; }
  .user-card { background:#0d1117; border:1px solid var(--border); border-radius:10px; padding:12px; margin-bottom:8px; display:flex; flex-direction:column; gap:8px; }
  .user-card.online { border-color:#22c55e66; }
  .user-top { display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap; }
  .badge { font-size:11px; padding:2px 8px; border-radius:999px; font-weight:700; font-family:monospace; }
  .badge-on { background:#14532d; color:#4ade80; }
  .badge-off { background:#21262d; color:#8b949e; }
  .psk-box { font-family:monospace; font-size:12px; word-break:break-all; background:#161b22; padding:6px 8px; border-radius:6px; border:1px solid #30363d; }
  .meta-line { font-size:12px; color:var(--muted); font-family:monospace; }
  .pin-bar { font-family:monospace; font-size:11px; word-break:break-all; background:#0d1117; padding:8px 10px; border-radius:8px; border:1px solid var(--border); margin-top:8px; display:flex; justify-content:space-between; align-items:center; gap:8px; }
  .toast { position:fixed; bottom:16px; left:50%; transform:translateX(-50%); background:#1f2937; color:#fff; border:1px solid var(--green); padding:10px 16px; border-radius:10px; font-size:13px; z-index:999; display:none; max-width:92vw; text-align:center; }
  .modal-bg { position:fixed; inset:0; background:rgba(0,0,0,0.75); display:none; align-items:center; justify-content:center; padding:16px; z-index:1000; }
  .modal { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; width:100%; max-width:420px; display:flex; flex-direction:column; gap:10px; }
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
    <div class="subtitle" id="subInfo">WinRM-VPN Server v0.4.5 | Панель управления</div>
    <div><span class="status-pill"><span class="dot dot-off" id="vpnDot"></span><span id="vpnStatusText">Загрузка...</span></span></div>
    <div class="pin-bar"><span><b>Cert SHA-256 Pin:</b> <span id="certPinVal">—</span></span><button class="btn-sm" onclick="copyText(document.getElementById('certPinVal').textContent)">Копировать</button></div>
  </div>
  <div class="grid">
    <div class="stat-box"><div class="stat-label">Внешний IP</div><div class="stat-val" id="statIP">—</div><div class="stat-sub" id="statHost">WIN-...</div></div>
    <div class="stat-box"><div class="stat-label">Время работы</div><div class="stat-val" id="statUptime">—</div><div class="stat-sub" id="statListen">:5986</div></div>
    <div class="stat-box"><div class="stat-label">Пользователи</div><div class="stat-val" id="statUsers">0 / 0</div><div class="stat-sub">онлайн / всего</div></div>
    <div class="stat-box"><div class="stat-label">Трафик (с запуска)</div><div class="stat-val" id="statTotalTraffic">0 B</div><div class="stat-sub" id="statRxTxSub">Вх 0 B | Исх 0 B</div></div>
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
    <div class="section-title"><span>Трафик VPN в реальном времени</span><div class="legend"><span style="color:var(--green)">● Вх: <b id="speedRx">0 B/s</b></span><span style="color:var(--cyan)">● Исх: <b id="speedTx">0 B/s</b></span></div></div>
    <div class="chart-wrap"><canvas id="trafficChart"></canvas></div>
  </div>
  <div class="card">
    <div class="section-title"><span>Активные пользователи (Онлайн)</span><span class="badge badge-on" id="onlineBadge">0</span></div>
    <div id="activeUsersList"><div class="meta-line">Нет подключённых пользователей</div></div>
  </div>
  <div class="card">
    <div class="section-title">Управление пользователями</div>
    <div class="form-row" style="margin-bottom:12px;">
      <input type="text" id="newLabel" placeholder="Имя / заметка (напр. iPhone)" />
      <input type="text" id="newPSK" placeholder="PSK (оставьте пустым для автогенерации)" />
      <button class="btn-cyan" style="flex:0 0 auto;" onclick="createUser()">+ Создать</button>
    </div>
    <div id="allUsersList"></div>
  </div>
  <div class="card">
    <div class="section-title">Настройки веб-панели</div>
    <div class="form-row" style="margin-bottom:8px;">
      <input type="number" id="webPortInput" placeholder="Порт веб-панели (по умолч. 49777)" min="1" max="65535" />
      <input type="password" id="webPassInput" placeholder="Новый пароль панели (опционально)" />
    </div>
    <div class="btn-row">
      <button class="btn-cyan" onclick="saveWebSettings(false)">Сохранить порт / пароль</button>
      <button class="btn-sm" id="btnClearPass" style="display:none;" onclick="saveWebSettings(true)">Сбросить пароль</button>
    </div>
  </div>
</div>
<div class="modal-bg" id="editModal"><div class="modal">
  <div class="section-title">Редактировать пользователя</div>
  <input type="hidden" id="editOldPSK" />
  <label class="meta-line">Имя / заметка:</label><input type="text" id="editLabel" placeholder="Имя устройства" />
  <label class="meta-line">PSK ключ:</label><input type="text" id="editNewPSK" />
  <div class="btn-row"><button class="btn-sm" onclick="genEditPSK()">Сгенерировать PSK</button><button class="btn-green" onclick="submitEditUser()">Сохранить</button><button class="btn-sm" onclick="closeEditModal()">Отмена</button></div>
</div></div>
<div class="modal-bg" id="loginModal"><div class="modal">
  <div class="section-title">Вход в панель WinRM-VPN</div>
  <input type="password" id="loginPass" placeholder="Введите пароль панели" />
  <button class="btn-green" onclick="submitLogin()">Войти</button>
</div></div>
<div class="toast" id="toast"></div>
<script>
let lastHistory=[],portRedirecting=false;
function showToast(m){const e=document.getElementById('toast');e.textContent=m;e.style.display='block';clearTimeout(window._tt);window._tt=setTimeout(()=>e.style.display='none',3000);}
function copyText(t){if(!t||t==='—')return;if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(()=>showToast('Скопировано'));}else{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');document.body.removeChild(a);showToast('Скопировано');}}
function fmtBytes(b){if(!b||b<1024)return(b||0)+' B';const u=['KB','MB','GB','TB'];let i=-1;do{b/=1024;i++;}while(b>=1024&&i<u.length-1);return b.toFixed(2)+' '+u[i];}
function fmtUptime(s){if(!s||s<=0)return'0с';const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);s%=3600;const m=Math.floor(s/60);const x=s%60;if(d>0)return d+'д '+h+'ч '+m+'м';if(h>0)return h+'ч '+m+'м '+x+'с';if(m>0)return m+'м '+x+'с';return x+'с';}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
async function apiPost(u,d){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d||{})});return r.json();}
async function vpnAction(a){try{const r=await apiPost('/api/vpn/'+a);if(r.ok){showToast(a==='start'?'VPN включён':(a==='stop'?'VPN выключен':'VPN перезапущен'));pollStats();}else showToast('Ошибка: '+(r.error||''));}catch(e){showToast('Ошибка связи');}}
async function createUser(){const label=document.getElementById('newLabel').value.trim(),psk=document.getElementById('newPSK').value.trim();const r=await apiPost('/api/users/create',{psk,label});if(r.ok){document.getElementById('newLabel').value='';document.getElementById('newPSK').value='';showToast('Создан');pollStats();}else showToast('Ошибка: '+r.error);}
async function deleteUser(psk){if(!confirm('Удалить пользователя?'))return;const r=await apiPost('/api/users/delete',{psk});if(r.ok){showToast('Удалён');pollStats();}else showToast('Ошибка: '+r.error);}
function openEditModal(p,l){document.getElementById('editOldPSK').value=p;document.getElementById('editNewPSK').value=p;document.getElementById('editLabel').value=l||'';document.getElementById('editModal').style.display='flex';}
function closeEditModal(){document.getElementById('editModal').style.display='none';}
function genEditPSK(){const a=new Uint8Array(24);crypto.getRandomValues(a);document.getElementById('editNewPSK').value=Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');}
async function submitEditUser(){const r=await apiPost('/api/users/update',{old_psk:document.getElementById('editOldPSK').value,new_psk:document.getElementById('editNewPSK').value.trim(),label:document.getElementById('editLabel').value.trim()});if(r.ok){closeEditModal();showToast('Обновлён');pollStats();}else showToast('Ошибка: '+r.error);}
async function saveWebSettings(c){const port=parseInt(document.getElementById('webPortInput').value,10),password=document.getElementById('webPassInput').value;if(!port||port<1||port>65535){showToast('Неверный порт');return;}const r=await apiPost('/api/settings/web',{port,password,clear_password:c});if(!r.ok){showToast('Ошибка: '+r.error);return;}document.getElementById('webPassInput').value='';if(r.port_changed){portRedirecting=true;showToast('Порт '+r.new_port+'... переход');setTimeout(()=>window.location.href=window.location.protocol+'//'+window.location.hostname+':'+r.new_port+'/',1500);}else{showToast('Сохранено');pollStats();}}
async function submitLogin(){const r=await apiPost('/api/login',{password:document.getElementById('loginPass').value});if(r.ok){document.getElementById('loginModal').style.display='none';pollStats();}else showToast(r.error||'Неверный пароль');}
function renderUsers(users){
  const ae=document.getElementById('activeUsersList'),le=document.getElementById('allUsersList');
  const act=users.filter(u=>u.online); document.getElementById('onlineBadge').textContent=act.length;
  ae.innerHTML=act.length===0?'<div class="meta-line">Нет подключённых пользователей</div>':act.map(u=>'<div class="user-card online"><div class="user-top"><span><b>'+(u.label?esc(u.label)+' ':'')+'</b><span class="badge badge-on">ОНЛАЙН ('+u.online_conns+')</span></span><span class="meta-line">'+esc(u.last_connected)+'</span></div><div class="psk-box">'+esc(u.psk)+'</div><div class="meta-line">С запуска: Вх '+fmtBytes(u.session_rx)+' / Исх '+fmtBytes(u.session_tx)+' | Сегодня: Вх '+fmtBytes(u.today_rx)+' / Исх '+fmtBytes(u.today_tx)+'</div></div>').join('');
  le.innerHTML=users.length===0?'<div class="meta-line">Список пользователей пуст</div>':users.map((u,i)=>{const ep=encodeURIComponent(u.psk),el=encodeURIComponent(u.label||'');return'<div class="user-card '+(u.online?'online':'')+'"><div class="user-top"><span>'+(u.label?'<b>'+esc(u.label)+'</b> ':'<b>#'+(i+1)+'</b> ')+(u.online?'<span class="badge badge-on">ОНЛАЙН</span>':'<span class="badge badge-off">оффлайн</span>')+'</span><div class="btn-row" style="gap:6px;"><button class="btn-sm" onclick="copyText(decodeURIComponent(\''+ep+'\'))">Копировать</button><button class="btn-sm btn-cyan" onclick="openEditModal(decodeURIComponent(\''+ep+'\'),decodeURIComponent(\''+el+'\'))">Изменить</button><button class="btn-sm btn-red" onclick="deleteUser(decodeURIComponent(\''+ep+'\'))">Удалить</button></div></div><div class="psk-box">'+esc(u.psk)+'</div><div class="meta-line">С запуска: Вх '+fmtBytes(u.session_rx)+' / Исх '+fmtBytes(u.session_tx)+'</div><div class="meta-line">За сегодня: Вх '+fmtBytes(u.today_rx)+' / Исх '+fmtBytes(u.today_tx)+' | Посл. вход: '+(esc(u.last_connected)||'Никогда')+'</div></div>';}).join('');
}
function drawChart(h){
  const c=document.getElementById('trafficChart'),rc=c.parentElement.getBoundingClientRect(),d=window.devicePixelRatio||1;
  c.width=Math.max(200,(rc.width-16)*d);c.height=Math.max(100,(rc.height-16)*d);
  const ctx=c.getContext('2d');ctx.scale(d,d);const w=c.width/d,ht=c.height/d;ctx.clearRect(0,0,w,ht);
  if(!h||h.length<2){ctx.fillStyle='#8b949e';ctx.font='12px monospace';ctx.fillText('Сбор данных трафика...',12,ht/2);return;}
  let mv=1024;for(const p of h){if(p.rx_bps>mv)mv=p.rx_bps;if(p.tx_bps>mv)mv=p.tx_bps;}mv*=1.15;
  const pL=62,pR=8,pT=10,pB=20,cw=w-pL-pR,ch=ht-pT-pB;ctx.strokeStyle='#21262d';ctx.fillStyle='#8b949e';ctx.font='10px monospace';
  for(let i=0;i<=3;i++){const y=pT+(ch*i)/3;ctx.beginPath();ctx.moveTo(pL,y);ctx.lineTo(w-pR,y);ctx.stroke();ctx.fillText(fmtBytes(mv*(1-i/3))+'/s',2,y+3);}
  function pl(k,sc,fc){ctx.beginPath();h.forEach((p,idx)=>{const x=pL+(idx/(h.length-1))*cw,y=pT+ch-(p[k]/mv)*ch;if(idx===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);});ctx.strokeStyle=sc;ctx.lineWidth=2;ctx.stroke();ctx.lineTo(pL+cw,pT+ch);ctx.lineTo(pL,pT+ch);ctx.closePath();ctx.fillStyle=fc;ctx.fill();}
  pl('tx_bps','#38bdf8','rgba(56,189,248,0.14)');pl('rx_bps','#00e676','rgba(0,230,118,0.16)');
  ctx.fillStyle='#8b949e';ctx.fillText(h[0].time,pL,ht-4);const lt=h[h.length-1].time;ctx.fillText(lt,w-pR-ctx.measureText(lt).width,ht-4);
}
async function pollStats(){
  if(portRedirecting)return;
  try{
    const r=await fetch('/api/stats');if(r.status===401){document.getElementById('loginModal').style.display='flex';return;}
    const d=await r.json();if(!d.stats)return;const s=d.stats;
    document.getElementById('subInfo').textContent='WinRM-VPN Server v'+s.version+' | Веб-панель :'+s.web_port;
    const dot=document.getElementById('vpnDot'),st=document.getElementById('vpnStatusText');
    if(s.vpn_running){dot.className='dot dot-on';st.textContent='VPN АКТИВЕН (PID '+s.pid+')';document.getElementById('btnStart').disabled=true;document.getElementById('btnStop').disabled=false;}
    else{dot.className='dot dot-off';st.textContent='VPN ОСТАНОВЛЕН';document.getElementById('btnStart').disabled=false;document.getElementById('btnStop').disabled=true;}
    document.getElementById('certPinVal').textContent=s.cert_pin||'—';
    document.getElementById('statIP').textContent=s.external_ip||'—';
    document.getElementById('statHost').textContent=s.host_name||'—';
    document.getElementById('statUptime').textContent=s.vpn_running?fmtUptime(s.uptime_sec):'Остановлен';
    document.getElementById('statListen').textContent=s.listen_addr||':5986';
    document.getElementById('statUsers').textContent=s.online_users+' / '+s.total_users;
    document.getElementById('statTotalTraffic').textContent=fmtBytes((s.total_rx||0)+(s.total_tx||0));
    document.getElementById('statRxTxSub').textContent='Вх '+fmtBytes(s.total_rx)+' | Исх '+fmtBytes(s.total_tx);
    document.getElementById('speedRx').textContent=fmtBytes(s.rx_bps)+'/s';
    document.getElementById('speedTx').textContent=fmtBytes(s.tx_bps)+'/s';
    const pi=document.getElementById('webPortInput');if(document.activeElement!==pi&&!pi.value)pi.value=s.web_port;
    document.getElementById('btnClearPass').style.display=d.has_password?'inline-block':'none';
    lastHistory=s.history||[];drawChart(lastHistory);renderUsers(s.users||[]);
  }catch(e){}
}
window.addEventListener('resize',()=>drawChart(lastHistory));pollStats();setInterval(pollStats,1000);
</script>
</body>
</html>`
