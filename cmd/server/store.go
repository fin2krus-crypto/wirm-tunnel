package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type UserRecord struct {
	PSK           string `json:"psk"`
	Label         string `json:"label,omitempty"`
	CreatedAt     string `json:"created_at"`
	TodayDate     string `json:"today_date"`
	TodayRx       uint64 `json:"today_rx"`
	TodayTx       uint64 `json:"today_tx"`
	LastConnected string `json:"last_connected"`
}

type UsersDB struct {
	Users []*UserRecord `json:"users"`
}

type UserSnapshot struct {
	PSK           string `json:"psk"`
	Label         string `json:"label"`
	CreatedAt     string `json:"created_at"`
	SessionRx     uint64 `json:"session_rx"`
	SessionTx     uint64 `json:"session_tx"`
	TodayRx       uint64 `json:"today_rx"`
	TodayTx       uint64 `json:"today_tx"`
	Online        bool   `json:"online"`
	OnlineConns   int    `json:"online_conns"`
	LastConnected string `json:"last_connected"`
}

type TrafficPoint struct {
	Time  string `json:"time"`
	RxBps uint64 `json:"rx_bps"`
	TxBps uint64 `json:"tx_bps"`
}

type ServerStatsSnapshot struct {
	Version          string         `json:"version"`
	Running          bool           `json:"running"`
	VPNEngineRunning bool           `json:"vpn_running"`
	PID              int            `json:"pid"`
	ListenAddr       string         `json:"listen_addr"`
	WebPort          int            `json:"web_port"`
	WebEnabled       bool           `json:"web_enabled"`
	HostName         string         `json:"host_name"`
	CertPin          string         `json:"cert_pin"`
	ExternalIP       string         `json:"external_ip"`
	StartTime        time.Time      `json:"start_time"`
	UptimeSec        int64          `json:"uptime_sec"`
	TotalUsers       int            `json:"total_users"`
	OnlineUsers      int            `json:"online_users"`
	TotalRx          uint64         `json:"total_rx"`
	TotalTx          uint64         `json:"total_tx"`
	RxBps            uint64         `json:"rx_bps"`
	TxBps            uint64         `json:"tx_bps"`
	History          []TrafficPoint `json:"history"`
	Users            []UserSnapshot `json:"users"`
}

type liveUserState struct {
	SessionRx   uint64
	SessionTx   uint64
	OnlineConns int
	ActiveConns map[uint64]net.Conn
}

type StatsManager struct {
	mu           sync.RWMutex
	dataDir      string
	dbPath       string
	envPath      string
	sockPath     string
	vpnRunning   bool
	listenAddr   string
	webPort      int
	webEnabled   bool
	hostName     string
	certPin      string
	externalIP   string
	startTime    time.Time
	totalRx      uint64
	totalTx      uint64
	prevSampleRx uint64
	prevSampleTx uint64
	curRxBps     uint64
	curTxBps     uint64
	history      []TrafficPoint
	nextConnID   uint64
	users        map[string]*UserRecord
	userOrder    []string
	live         map[string]*liveUserState
	stopFlushCh  chan struct{}
}

func resolveDataDir(flagDir string) string {
	if flagDir != "" {
		return flagDir
	}
	if _, err := os.Stat("/etc/winrm-vpn"); err == nil {
		return "/etc/winrm-vpn"
	}
	if os.Geteuid() == 0 {
		return "/etc/winrm-vpn"
	}
	return "."
}

func NewStatsManager(dataDir string) *StatsManager {
	return &StatsManager{
		dataDir:     dataDir,
		dbPath:      filepath.Join(dataDir, "users.json"),
		envPath:     filepath.Join(dataDir, "config.env"),
		sockPath:    filepath.Join(dataDir, "control.sock"),
		startTime:   time.Now(),
		webPort:     defaultWebPort,
		history:     make([]TrafficPoint, 0, 60),
		users:       make(map[string]*UserRecord),
		live:        make(map[string]*liveUserState),
		stopFlushCh: make(chan struct{}),
	}
}

func currentDateStr() string {
	return time.Now().Format("2006-01-02")
}

func rolloverUserDay(u *UserRecord, today string) {
	if u.TodayDate != today {
		u.TodayDate = today
		u.TodayRx = 0
		u.TodayTx = 0
	}
}

func (sm *StatsManager) SetMetadata(listenAddr, hostName, certPin, extIP string, webPort int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if listenAddr != "" {
		sm.listenAddr = listenAddr
	}
	if hostName != "" {
		sm.hostName = hostName
	}
	if certPin != "" {
		sm.certPin = certPin
	}
	if extIP != "" {
		sm.externalIP = extIP
	}
	if webPort > 0 {
		sm.webPort = webPort
	}
}

func (sm *StatsManager) SetWebPort(port int) {
	sm.SetWebStatus(port, sm.webEnabled)
}

func (sm *StatsManager) SetWebStatus(port int, enabled bool) {
	sm.mu.Lock()
	if port > 0 { sm.webPort = port }
	sm.webEnabled = enabled
	sm.mu.Unlock()
}

func (sm *StatsManager) SetVPNRunning(running bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.vpnRunning = running
	if running {
		sm.startTime = time.Now()
		sm.totalRx = 0
		sm.totalTx = 0
		sm.prevSampleRx = 0
		sm.prevSampleTx = 0
		sm.curRxBps = 0
		sm.curTxBps = 0
		for _, lv := range sm.live {
			lv.SessionRx = 0
			lv.SessionTx = 0
		}
	} else {
		sm.curRxBps = 0
		sm.curTxBps = 0
	}
}

func (sm *StatsManager) CloseAllActive() {
	sm.mu.Lock()
	var toClose []net.Conn
	for _, lv := range sm.live {
		for _, c := range lv.ActiveConns {
			toClose = append(toClose, c)
		}
	}
	sm.mu.Unlock()

	for _, c := range toClose {
		_ = c.Close()
	}
}

func (sm *StatsManager) LoadOrInit(cliPSKs []string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_ = os.MkdirAll(sm.dataDir, 0700)
	sm.loadFromDiskLocked()

	today := currentDateStr()
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	added := false
	for _, psk := range cliPSKs {
		psk = strings.TrimSpace(psk)
		if psk == "" {
			continue
		}
		if _, exists := sm.users[psk]; !exists {
			u := &UserRecord{
				PSK:       psk,
				CreatedAt: nowStr,
				TodayDate: today,
			}
			sm.users[psk] = u
			sm.userOrder = append(sm.userOrder, psk)
			sm.live[psk] = &liveUserState{ActiveConns: make(map[uint64]net.Conn)}
			added = true
		}
	}

	if len(sm.userOrder) == 0 {
		for _, psk := range readPSKsFromEnv(sm.envPath) {
			if _, exists := sm.users[psk]; !exists {
				u := &UserRecord{
					PSK:       psk,
					CreatedAt: nowStr,
					TodayDate: today,
				}
				sm.users[psk] = u
				sm.userOrder = append(sm.userOrder, psk)
				sm.live[psk] = &liveUserState{ActiveConns: make(map[uint64]net.Conn)}
				added = true
			}
		}
	}

	if added || len(sm.userOrder) > 0 {
		_ = sm.saveToDiskLocked()
	}
	return nil
}

func (sm *StatsManager) loadFromDiskLocked() {
	raw, err := os.ReadFile(sm.dbPath)
	if err != nil {
		return
	}
	var db UsersDB
	if err := json.Unmarshal(raw, &db); err != nil {
		return
	}

	today := currentDateStr()
	sm.users = make(map[string]*UserRecord)
	sm.userOrder = nil

	for _, u := range db.Users {
		if u == nil || u.PSK == "" {
			continue
		}
		rolloverUserDay(u, today)
		sm.users[u.PSK] = u
		sm.userOrder = append(sm.userOrder, u.PSK)
		if _, ok := sm.live[u.PSK]; !ok {
			sm.live[u.PSK] = &liveUserState{ActiveConns: make(map[uint64]net.Conn)}
		}
	}
}

func (sm *StatsManager) saveToDiskLocked() error {
	db := UsersDB{Users: make([]*UserRecord, 0, len(sm.userOrder))}
	today := currentDateStr()
	for _, psk := range sm.userOrder {
		if u, ok := sm.users[psk]; ok {
			rolloverUserDay(u, today)
			copyU := *u
			db.Users = append(db.Users, &copyU)
		}
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp := sm.dbPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, sm.dbPath); err != nil {
		return err
	}
	syncPSKsToEnv(sm.envPath, sm.userOrder)
	return nil
}

func (sm *StatsManager) AddUserDirect(psk, label string) error {
	psk = strings.TrimSpace(psk)
	label = strings.TrimSpace(label)
	if psk == "" {
		return errors.New("PSK не может быть пустым")
	}
	if strings.Contains(psk, ",") {
		return errors.New("PSK не должен содержать запятую")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if _, exists := sm.users[psk]; exists {
		return errors.New("пользователь с таким PSK уже существует")
	}

	u := &UserRecord{
		PSK:       psk,
		Label:     label,
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		TodayDate: currentDateStr(),
	}
	sm.users[psk] = u
	sm.userOrder = append(sm.userOrder, psk)
	sm.live[psk] = &liveUserState{ActiveConns: make(map[uint64]net.Conn)}
	return sm.saveToDiskLocked()
}

func (sm *StatsManager) UpdateUserDirect(oldPSK, newPSK, label string) error {
	oldPSK = strings.TrimSpace(oldPSK)
	newPSK = strings.TrimSpace(newPSK)
	label = strings.TrimSpace(label)
	if newPSK == "" {
		return errors.New("новый PSK не может быть пустым")
	}
	if strings.Contains(newPSK, ",") {
		return errors.New("PSK не должен содержать запятую")
	}

	sm.mu.Lock()
	u, exists := sm.users[oldPSK]
	if !exists {
		sm.mu.Unlock()
		return errors.New("пользователь не найден")
	}

	var toClose []net.Conn
	if oldPSK != newPSK {
		if _, collision := sm.users[newPSK]; collision {
			sm.mu.Unlock()
			return errors.New("пользователь с таким новым PSK уже существует")
		}
		delete(sm.users, oldPSK)
		u.PSK = newPSK
		u.Label = label
		sm.users[newPSK] = u

		for i, k := range sm.userOrder {
			if k == oldPSK {
				sm.userOrder[i] = newPSK
				break
			}
		}

		if lv, ok := sm.live[oldPSK]; ok {
			for _, c := range lv.ActiveConns {
				toClose = append(toClose, c)
			}
			delete(sm.live, oldPSK)
		}
		sm.live[newPSK] = &liveUserState{ActiveConns: make(map[uint64]net.Conn)}
	} else {
		u.Label = label
	}
	err := sm.saveToDiskLocked()
	sm.mu.Unlock()

	for _, c := range toClose {
		_ = c.Close()
	}
	return err
}

func (sm *StatsManager) DeleteUserDirect(psk string) error {
	psk = strings.TrimSpace(psk)

	sm.mu.Lock()
	if _, exists := sm.users[psk]; !exists {
		sm.mu.Unlock()
		return errors.New("пользователь не найден")
	}
	delete(sm.users, psk)
	newOrder := make([]string, 0, len(sm.userOrder))
	for _, k := range sm.userOrder {
		if k != psk {
			newOrder = append(newOrder, k)
		}
	}
	sm.userOrder = newOrder

	var toClose []net.Conn
	if lv, ok := sm.live[psk]; ok {
		for _, c := range lv.ActiveConns {
			toClose = append(toClose, c)
		}
		delete(sm.live, psk)
	}
	err := sm.saveToDiskLocked()
	sm.mu.Unlock()

	for _, c := range toClose {
		_ = c.Close()
	}
	return err
}

func (sm *StatsManager) ReloadFromDisk() []net.Conn {
	sm.mu.Lock()
	raw, err := os.ReadFile(sm.dbPath)
	if err != nil {
		sm.mu.Unlock()
		return nil
	}
	var db UsersDB
	if err := json.Unmarshal(raw, &db); err != nil {
		sm.mu.Unlock()
		return nil
	}

	today := currentDateStr()
	newUsers := make(map[string]*UserRecord)
	var newOrder []string
	for _, u := range db.Users {
		if u == nil || u.PSK == "" {
			continue
		}
		rolloverUserDay(u, today)
		newUsers[u.PSK] = u
		newOrder = append(newOrder, u.PSK)
		if _, ok := sm.live[u.PSK]; !ok {
			sm.live[u.PSK] = &liveUserState{ActiveConns: make(map[uint64]net.Conn)}
		}
	}

	var toClose []net.Conn
	for psk, lv := range sm.live {
		if _, stillExists := newUsers[psk]; !stillExists {
			for _, c := range lv.ActiveConns {
				toClose = append(toClose, c)
			}
			delete(sm.live, psk)
		}
	}

	sm.users = newUsers
	sm.userOrder = newOrder
	sm.mu.Unlock()

	return toClose
}

func (sm *StatsManager) GetAllPSKs() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	out := make([]string, len(sm.userOrder))
	copy(out, sm.userOrder)
	return out
}

func (sm *StatsManager) ClientConnected(psk string, c net.Conn) uint64 {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.nextConnID++
	connID := sm.nextConnID

	today := currentDateStr()
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	if u, ok := sm.users[psk]; ok {
		rolloverUserDay(u, today)
		u.LastConnected = nowStr
	}

	lv, ok := sm.live[psk]
	if !ok {
		lv = &liveUserState{ActiveConns: make(map[uint64]net.Conn)}
		sm.live[psk] = lv
	}
	lv.OnlineConns++
	lv.ActiveConns[connID] = c

	_ = sm.saveToDiskLocked()
	return connID
}

func (sm *StatsManager) ClientDisconnected(psk string, connID uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if lv, ok := sm.live[psk]; ok {
		if _, exists := lv.ActiveConns[connID]; exists {
			delete(lv.ActiveConns, connID)
			if lv.OnlineConns > 0 {
				lv.OnlineConns--
			}
		}
	}
	_ = sm.saveToDiskLocked()
}

func (sm *StatsManager) AddRx(psk string, n int) {
	if n <= 0 {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	bytes := uint64(n)
	sm.totalRx += bytes
	today := currentDateStr()
	if u, ok := sm.users[psk]; ok {
		rolloverUserDay(u, today)
		u.TodayRx += bytes
	}
	if lv, ok := sm.live[psk]; ok {
		lv.SessionRx += bytes
	}
}

func (sm *StatsManager) AddTx(psk string, n int) {
	if n <= 0 {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	bytes := uint64(n)
	sm.totalTx += bytes
	today := currentDateStr()
	if u, ok := sm.users[psk]; ok {
		rolloverUserDay(u, today)
		u.TodayTx += bytes
	}
	if lv, ok := sm.live[psk]; ok {
		lv.SessionTx += bytes
	}
}

func (sm *StatsManager) sampleTrafficSecond() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var rxBps, txBps uint64
	if sm.totalRx >= sm.prevSampleRx {
		rxBps = sm.totalRx - sm.prevSampleRx
	}
	if sm.totalTx >= sm.prevSampleTx {
		txBps = sm.totalTx - sm.prevSampleTx
	}
	sm.prevSampleRx = sm.totalRx
	sm.prevSampleTx = sm.totalTx
	sm.curRxBps = rxBps
	sm.curTxBps = txBps

	pt := TrafficPoint{
		Time:  time.Now().Format("15:04:05"),
		RxBps: rxBps,
		TxBps: txBps,
	}
	sm.history = append(sm.history, pt)
	if len(sm.history) > 60 {
		sm.history = sm.history[len(sm.history)-60:]
	}
}

func (sm *StatsManager) Snapshot() ServerStatsSnapshot {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	today := currentDateStr()
	onlineUsers := 0
	usersOut := make([]UserSnapshot, 0, len(sm.userOrder))

	for _, psk := range sm.userOrder {
		u, ok := sm.users[psk]
		if !ok {
			continue
		}
		todayRx, todayTx := u.TodayRx, u.TodayTx
		if u.TodayDate != today {
			todayRx, todayTx = 0, 0
		}
		var sessRx, sessTx uint64
		var conns int
		if lv, ok := sm.live[psk]; ok {
			sessRx = lv.SessionRx
			sessTx = lv.SessionTx
			conns = lv.OnlineConns
		}
		isOnline := conns > 0
		if isOnline {
			onlineUsers++
		}
		usersOut = append(usersOut, UserSnapshot{
			PSK:           u.PSK,
			Label:         u.Label,
			CreatedAt:     u.CreatedAt,
			SessionRx:     sessRx,
			SessionTx:     sessTx,
			TodayRx:       todayRx,
			TodayTx:       todayTx,
			Online:        isOnline,
			OnlineConns:   conns,
			LastConnected: u.LastConnected,
		})
	}

	histCopy := make([]TrafficPoint, len(sm.history))
	copy(histCopy, sm.history)

	var uptimeSec int64
	if sm.vpnRunning {
		uptimeSec = int64(time.Since(sm.startTime).Seconds())
	}

	return ServerStatsSnapshot{
		Version:          AppVersion,
		Running:          sm.vpnRunning,
		VPNEngineRunning: sm.vpnRunning,
		PID:              os.Getpid(),
		ListenAddr:       sm.listenAddr,
		WebPort:          sm.webPort,
		WebEnabled:       sm.webEnabled,
		HostName:         sm.hostName,
		CertPin:          sm.certPin,
		ExternalIP:       sm.externalIP,
		StartTime:        sm.startTime,
		UptimeSec:        uptimeSec,
		TotalUsers:       len(usersOut),
		OnlineUsers:      onlineUsers,
		TotalRx:          sm.totalRx,
		TotalTx:          sm.totalTx,
		RxBps:            sm.curRxBps,
		TxBps:            sm.curTxBps,
		History:          histCopy,
		Users:            usersOut,
	}
}

func (sm *StatsManager) StartPeriodicFlush() {
	go func() {
		secTicker := time.NewTicker(1 * time.Second)
		saveTicker := time.NewTicker(15 * time.Second)
		defer secTicker.Stop()
		defer saveTicker.Stop()
		for {
			select {
			case <-secTicker.C:
				sm.sampleTrafficSecond()
			case <-saveTicker.C:
				sm.mu.Lock()
				_ = sm.saveToDiskLocked()
				sm.mu.Unlock()
			case <-sm.stopFlushCh:
				return
			}
		}
	}()
}

func (sm *StatsManager) FlushAndClose() {
	select {
	case <-sm.stopFlushCh:
	default:
		close(sm.stopFlushCh)
	}
	sm.mu.Lock()
	_ = sm.saveToDiskLocked()
	sm.mu.Unlock()
	_ = os.Remove(sm.sockPath)
}

func (sm *StatsManager) StartControlSocket(vpnEngine *VPNEngine, webPanel *WebPanelServer, onShutdown func()) error {
	_ = os.Remove(sm.sockPath)
	ln, err := net.Listen("unix", sm.sockPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(sm.sockPath, 0600)

	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		snap := sm.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
	})
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		toClose := sm.ReloadFromDisk()
		for _, c := range toClose {
			_ = c.Close()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})
	mux.HandleFunc("/vpn/start", func(w http.ResponseWriter, r *http.Request) {
		if vpnEngine != nil {
			if err := vpnEngine.Start(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		_, _ = w.Write([]byte("STARTED\n"))
	})
	mux.HandleFunc("/vpn/stop", func(w http.ResponseWriter, r *http.Request) {
		if vpnEngine != nil {
			vpnEngine.Stop()
		}
		_, _ = w.Write([]byte("STOPPED\n"))
	})
	mux.HandleFunc("/vpn/restart", func(w http.ResponseWriter, r *http.Request) {
		if vpnEngine != nil {
			if err := vpnEngine.Restart(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		_, _ = w.Write([]byte("RESTARTED\n"))
	})
	mux.HandleFunc("/web/start", func(w http.ResponseWriter, r *http.Request) {
		if webPanel != nil {
			if err := webPanel.Start(); err != nil { http.Error(w, err.Error(), 500); return }
		}
		_, _ = w.Write([]byte("OK\n"))
	})
	mux.HandleFunc("/web/stop", func(w http.ResponseWriter, r *http.Request) {
		if webPanel != nil { webPanel.Stop() }
		_, _ = w.Write([]byte("OK\n"))
	})
	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("STOPPING\n"))
		go func() {
			time.Sleep(100 * time.Millisecond)
			if onShutdown != nil {
				onShutdown()
			}
		}()
	})

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(ln)
	}()
	return nil
}

func readPSKsFromEnv(envPath string) []string {
	raw, err := os.ReadFile(envPath)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "WINRM_PSK=") {
			val := strings.TrimPrefix(line, "WINRM_PSK=")
			val = strings.Trim(val, `"'`)
			var out []string
			for _, k := range strings.Split(val, ",") {
				k = strings.TrimSpace(k)
				if k != "" {
					out = append(out, k)
				}
			}
			return out
		}
	}
	return nil
}

func syncPSKsToEnv(envPath string, psks []string) {
	raw, err := os.ReadFile(envPath)
	if err != nil {
		return
	}
	newVal := fmt.Sprintf(`WINRM_PSK="%s"`, strings.Join(psks, ","))
	lines := strings.Split(string(raw), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "WINRM_PSK=") {
			lines[i] = newVal
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append(lines, newVal)
	}
	_ = os.WriteFile(envPath, []byte(strings.Join(lines, "\n")), 0600)
}

func fetchLiveStats(dataDir string) (*ServerStatsSnapshot, error) {
	sockPath := filepath.Join(dataDir, "control.sock")
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Dial: func(_, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", sockPath, time.Second)
			},
		},
	}
	resp, err := client.Get("http://unix/stats")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("bad control socket response")
	}
	var snap ServerStatsSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

func sendControlCommand(dataDir, endpoint string) error {
	sockPath := filepath.Join(dataDir, "control.sock")
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Dial: func(_, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", sockPath, time.Second)
			},
		},
	}
	resp, err := client.Post("http://unix"+endpoint, "text/plain", nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func loadOfflineUsersSnapshot(dataDir string) ServerStatsSnapshot {
	dbPath := filepath.Join(dataDir, "users.json")
	envPath := filepath.Join(dataDir, "config.env")
	today := currentDateStr()

	var db UsersDB
	if raw, err := os.ReadFile(dbPath); err == nil {
		_ = json.Unmarshal(raw, &db)
	}

	if len(db.Users) == 0 {
		for _, psk := range readPSKsFromEnv(envPath) {
			db.Users = append(db.Users, &UserRecord{
				PSK:       psk,
				CreatedAt: "—",
				TodayDate: today,
			})
		}
	}

	users := make([]UserSnapshot, 0, len(db.Users))
	for _, u := range db.Users {
		if u == nil || u.PSK == "" {
			continue
		}
		tRx, tTx := u.TodayRx, u.TodayTx
		if u.TodayDate != today {
			tRx, tTx = 0, 0
		}
		users = append(users, UserSnapshot{
			PSK:           u.PSK,
			Label:         u.Label,
			CreatedAt:     u.CreatedAt,
			TodayRx:       tRx,
			TodayTx:       tTx,
			LastConnected: u.LastConnected,
		})
	}

	panelCfg := loadPanelConfig(dataDir)

	return ServerStatsSnapshot{
		Version:    AppVersion,
		Running:    false,
		WebPort:    panelCfg.Port,
		WebEnabled: panelCfg.Enabled,
		TotalUsers: len(users),
		Users:      users,
	}
}

func addUserToStorage(dataDir, newPSK string) error {
	newPSK = strings.TrimSpace(newPSK)
	if newPSK == "" {
		return errors.New("PSK не может быть пустым")
	}
	if strings.Contains(newPSK, ",") {
		return errors.New("PSK не должен содержать запятые")
	}

	_ = os.MkdirAll(dataDir, 0700)
	dbPath := filepath.Join(dataDir, "users.json")
	envPath := filepath.Join(dataDir, "config.env")

	var db UsersDB
	if raw, err := os.ReadFile(dbPath); err == nil {
		_ = json.Unmarshal(raw, &db)
	}
	if len(db.Users) == 0 {
		for _, psk := range readPSKsFromEnv(envPath) {
			db.Users = append(db.Users, &UserRecord{
				PSK:       psk,
				CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
				TodayDate: currentDateStr(),
			})
		}
	}

	for _, u := range db.Users {
		if u.PSK == newPSK {
			return errors.New("пользователь с таким PSK уже существует")
		}
	}

	db.Users = append(db.Users, &UserRecord{
		PSK:       newPSK,
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		TodayDate: currentDateStr(),
	})

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		return err
	}

	psks := make([]string, 0, len(db.Users))
	for _, u := range db.Users {
		psks = append(psks, u.PSK)
	}
	syncPSKsToEnv(envPath, psks)
	_ = sendControlCommand(dataDir, "/reload")
	return nil
}

func deleteUserFromStorage(dataDir, targetPSK string) error {
	dbPath := filepath.Join(dataDir, "users.json")
	envPath := filepath.Join(dataDir, "config.env")

	var db UsersDB
	if raw, err := os.ReadFile(dbPath); err == nil {
		_ = json.Unmarshal(raw, &db)
	}
	if len(db.Users) == 0 {
		for _, psk := range readPSKsFromEnv(envPath) {
			db.Users = append(db.Users, &UserRecord{
				PSK:       psk,
				CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
				TodayDate: currentDateStr(),
			})
		}
	}

	filtered := make([]*UserRecord, 0, len(db.Users))
	found := false
	for _, u := range db.Users {
		if u.PSK == targetPSK {
			found = true
			continue
		}
		filtered = append(filtered, u)
	}
	if !found {
		return errors.New("пользователь не найден")
	}

	db.Users = filtered
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		return err
	}

	psks := make([]string, 0, len(db.Users))
	for _, u := range db.Users {
		psks = append(psks, u.PSK)
	}
	syncPSKsToEnv(envPath, psks)
	_ = sendControlCommand(dataDir, "/reload")
	return nil
}
