//go:build linux

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"winrm-vpn/common"
)

const (
	AppVersion         = "0.1.1"
	maxConnectAttempts = 3
	ctlMetaPath        = "/tmp/winrm-vpn-linux-ctl.json"
)

type HelperConfig struct {
	Server    string `json:"server"`
	PSK       string `json:"psk"`
	Pin       string `json:"pin"`
	CheckConn bool   `json:"check_conn"`
}

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

var (
	stateMu    sync.RWMutex
	curState   = "CONNECTING"
	logsBuf    []string
	checkConn  bool
	activeMu   sync.Mutex
	activeConn net.Conn
	stopCh     = make(chan struct{})
	reconnCh   = make(chan struct{}, 1)
	stopOnce   sync.Once
)

func addLog(format string, args ...any) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	stateMu.Lock()
	logsBuf = append(logsBuf, line)
	if len(logsBuf) > 300 {
		logsBuf = logsBuf[len(logsBuf)-300:]
	}
	stateMu.Unlock()
}

func setState(s string) {
	stateMu.Lock()
	curState = s
	stateMu.Unlock()
}

func triggerReconnect() {
	activeMu.Lock()
	if activeConn != nil {
		_ = activeConn.Close()
	}
	activeMu.Unlock()

	select {
	case reconnCh <- struct{}{}:
	default:
	}
}

func triggerStop() {
	stopOnce.Do(func() {
		close(stopCh)
		activeMu.Lock()
		if activeConn != nil {
			_ = activeConn.Close()
		}
		activeMu.Unlock()
	})
}

func main() {
	cfgPath := flag.String("config", "", "Path to JSON config")
	flag.Parse()

	if *cfgPath == "" {
		fmt.Println("Usage: winrm-vpn-linux-helper -config <path>")
		os.Exit(1)
	}

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		fmt.Printf("Read config failed: %v\n", err)
		os.Exit(1)
	}
	var cfg HelperConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fmt.Printf("Parse config failed: %v\n", err)
		os.Exit(1)
	}
	_ = os.Remove(*cfgPath)

	stateMu.Lock()
	checkConn = cfg.CheckConn
	stateMu.Unlock()

	hostOnly, _, err := net.SplitHostPort(cfg.Server)
	if err != nil || hostOnly == "" {
		fmt.Printf("Invalid server address: %s\n", cfg.Server)
		os.Exit(1)
	}
	serverIPs, err := net.LookupIP(hostOnly)
	if err != nil || len(serverIPs) == 0 {
		fmt.Printf("Cannot resolve server IP: %v\n", err)
		os.Exit(1)
	}
	serverIPv4 := ""
	for _, ip := range serverIPs {
		if v4 := ip.To4(); v4 != nil {
			serverIPv4 = v4.String()
			break
		}
	}
	if serverIPv4 == "" {
		fmt.Println("No IPv4 address for server")
		os.Exit(1)
	}

	if err := startControlServer(); err != nil {
		fmt.Printf("Control server error: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(ctlMetaPath)

	netState := &LinuxNetworkState{}
	defer netState.Restore()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		addLog("[LINUX] Получен сигнал завершения...")
		triggerStop()
	}()

	go runHealthCheckLoop()
	go runNetworkSwitchMonitor(netState)

	expectedPin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(cfg.Pin), ":", ""))

	var tunFile *os.File
	var tunName string
	tunRxCh := make(chan []byte, 128)

	defer func() {
		if tunFile != nil {
			_ = tunFile.Close()
		}
	}()

	ensureTun := func() (*os.File, error) {
		if tunFile != nil {
			return tunFile, nil
		}
		addLog("[LINUX] Авторизация пройдена. Открываю TUN и настраиваю маршруты...")
		f, name, err := openLinuxTun()
		if err != nil {
			return nil, err
		}
		if err := netState.Setup(name, serverIPv4); err != nil {
			_ = f.Close()
			return nil, err
		}
		tunFile = f
		tunName = name
		addLog("[LINUX] Интерфейс %s поднят (10.88.0.2/24, DNS 1.1.1.1).", tunName)

		go func(tf *os.File) {
			buf := make([]byte, 2048)
			for {
				n, err := tf.Read(buf)
				if err != nil {
					return
				}
				if n >= 20 && (buf[0]>>4) == 4 {
					pkt := make([]byte, n)
					copy(pkt, buf[:n])
					select {
					case tunRxCh <- pkt:
					default:
						select {
						case <-tunRxCh:
						default:
						}
						select {
						case tunRxCh <- pkt:
						default:
						}
					}
				}
			}
		}(tunFile)

		return tunFile, nil
	}

	attempt := 0
	for {
		select {
		case <-stopCh:
			setState("DISCONNECTED")
			return
		default:
		}

		attempt++
		addLog("[SYS] Попытка подключения %d/%d...", attempt, maxConnectAttempts)
		setState("CONNECTING")

		wasConnected, err := runSingleSession(cfg.Server, cfg.PSK, expectedPin, ensureTun, tunRxCh)
		if err != nil {
			addLog("[ERR] Session ended: %v", err)
		}
		if wasConnected {
			attempt = 0
		}

		select {
		case <-stopCh:
			setState("DISCONNECTED")
			return
		default:
		}

		if attempt >= maxConnectAttempts {
			addLog("[ERR] Исчерпан лимит попыток (%d/%d). Выключение...", attempt, maxConnectAttempts)
			setState("ERROR")
			time.Sleep(1500 * time.Millisecond)
			return
		}

		delayMs := 2000 + mathrand.Intn(4001)
		addLog("[SYS] Повторная попытка через %.1f сек...", float64(delayMs)/1000.0)

		select {
		case <-stopCh:
			setState("DISCONNECTED")
			return
		case <-reconnCh:
			attempt = 0
			addLog("[SYS] Немедленное переподключение...")
		case <-time.After(time.Duration(delayMs) * time.Millisecond):
		}
	}
}

func startControlServer() error {
	var tokBytes [16]byte
	_, _ = rand.Read(tokBytes[:])
	token := hex.EncodeToString(tokBytes[:])

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	meta, _ := json.Marshal(CtlMeta{Port: port, Token: token, PID: os.Getpid()})
	if err := os.WriteFile(ctlMetaPath, meta, 0644); err != nil {
		_ = ln.Close()
		return err
	}

	authCheck := func(r *http.Request) bool {
		return r.Header.Get("X-Ctl-Token") == token
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if !authCheck(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		stateMu.RLock()
		logsCopy := make([]string, len(logsBuf))
		copy(logsCopy, logsBuf)
		resp := StatusResponse{
			State:     curState,
			CheckConn: checkConn,
			Logs:      logsCopy,
		}
		stateMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/watchdog", func(w http.ResponseWriter, r *http.Request) {
		if !authCheck(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		enabled := r.URL.Query().Get("enabled") == "true"
		stateMu.Lock()
		checkConn = enabled
		stateMu.Unlock()
		addLog("[UI] Проверка соединения (Watchdog): %v", map[bool]string{true: "ВКЛ", false: "ВЫКЛ"}[enabled])
		_, _ = w.Write([]byte("OK"))
	})

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		if !authCheck(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		addLog("[PING] Running ping -c 1 -W 3 8.8.8.8 ...")
		out, err := exec.Command("ping", "-c", "1", "-W", "3", "8.8.8.8").CombinedOutput()
		text := string(out)
		if err == nil {
			re := regexp.MustCompile(`time=([0-9.]+\s*ms)`)
			rtt := ""
			if m := re.FindStringSubmatch(text); len(m) > 1 {
				rtt = " (" + m[1] + ")"
			}
			msg := "Тестовый пинг 8.8.8.8 прошел" + rtt
			addLog("[PING] SUCCESS: 8.8.8.8 reachable%s", rtt)
			_, _ = w.Write([]byte(msg))
		} else {
			msg := fmt.Sprintf("Ошибка: пинг 8.8.8.8 не прошел (%v)", err)
			addLog("[PING] FAILED: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(msg))
		}
	})

	mux.HandleFunc("/checkip", func(w http.ResponseWriter, r *http.Request) {
		if !authCheck(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		addLog("[IP-CHECK] Fetching http://ifconfig.io/country_code & /host ...")
		cc, err1 := httpGetCurl("http://ifconfig.io/country_code")
		host, err2 := httpGetCurl("http://ifconfig.io/host")
		if err1 != nil || err2 != nil {
			err := err1
			if err == nil {
				err = err2
			}
			msg := fmt.Sprintf("Ошибка проверки IP: %v", err)
			addLog("[IP-CHECK] ERROR: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(msg))
			return
		}
		cc = strings.ToUpper(strings.TrimSpace(cc))
		host = strings.TrimSpace(host)
		res := fmt.Sprintf("%s  |  IP/Host: %s", cc, host)
		addLog("[IP-CHECK] Result: %s", res)
		_, _ = w.Write([]byte(res))
	})

	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		if !authCheck(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		addLog("[LINUX] Остановка VPN пользователем...")
		_, _ = w.Write([]byte("STOPPING"))
		go func() {
			time.Sleep(50 * time.Millisecond)
			triggerStop()
		}()
	})

	go func() {
		_ = http.Serve(ln, mux)
	}()
	return nil
}

func runNetworkSwitchMonitor(netState *LinuxNetworkState) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			if changed, desc := netState.UpdateOnNetworkChange(); changed {
				addLog("[NETWORK] Сеть изменилась -> %s. Переподключение...", desc)
				triggerReconnect()
			}
		}
	}
}

func runHealthCheckLoop() {
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		stateMu.RLock()
		enabled := checkConn
		st := curState
		stateMu.RUnlock()

		if !enabled || st != "CONNECTED" {
			select {
			case <-stopCh:
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}

		waitSec := 30 + mathrand.Intn(31)
		if !interruptibleSleepSec(waitSec) {
			continue
		}
		if exec.Command("ping", "-c", "1", "-W", "3", "1.1.1.1").Run() == nil {
			addLog("[WATCHDOG] ping 1.1.1.1 OK (след. через 30-60с)")
			continue
		}

		retrySec := 10 + mathrand.Intn(11)
		addLog("[WATCHDOG] ping 1.1.1.1 не прошёл! Повтор через %dс...", retrySec)
		if !interruptibleSleepSec(retrySec) {
			continue
		}
		if exec.Command("ping", "-c", "1", "-W", "3", "1.1.1.1").Run() == nil {
			addLog("[WATCHDOG] Повторный ping 1.1.1.1 OK")
		} else {
			addLog("[WATCHDOG] Повторный ping 1.1.1.1 не прошёл! Перезапуск VPN...")
			triggerReconnect()
			select {
			case <-stopCh:
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func interruptibleSleepSec(sec int) bool {
	for i := 0; i < sec; i++ {
		stateMu.RLock()
		enabled := checkConn
		st := curState
		stateMu.RUnlock()
		if !enabled || st != "CONNECTED" {
			return false
		}
		select {
		case <-stopCh:
			return false
		case <-time.After(1 * time.Second):
		}
	}
	return true
}

func httpGetCurl(urlStr string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "curl/8.5.0")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return string(b), err
}

func runSingleSession(
	serverAddr, psk, expectedPin string,
	ensureTun func() (*os.File, error),
	tunRxCh <-chan []byte,
) (bool, error) {
	addLog("[TCP] Dialing %s (IPv4)...", serverAddr)

	dialer := &net.Dialer{Timeout: 4 * time.Second}
	rawConn, err := dialer.Dial("tcp4", serverAddr)
	if err != nil {
		return false, fmt.Errorf("TCP connect failed: %w", err)
	}

	activeMu.Lock()
	activeConn = rawConn
	activeMu.Unlock()

	defer func() {
		activeMu.Lock()
		if activeConn == rawConn {
			activeConn = nil
		}
		activeMu.Unlock()
		_ = rawConn.Close()
	}()

	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	addLog("[TCP] Connected to %s", rawConn.RemoteAddr().String())
	addLog("[TLS] Handshake (Profile: Ansible / Linux OpenSSL 3.x, no SNI)...")

	uConn := utls.UClient(rawConn, &utls.Config{InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uConn.ApplyPreset(buildAnsibleLinuxOpenSSL3Spec()); err != nil {
		return false, err
	}
	if err := uConn.Handshake(); err != nil {
		return false, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := uConn.ConnectionState()
	addLog("[TLS] Handshake OK (Cipher: %s)", tls.CipherSuiteName(state.CipherSuite))

	if len(state.PeerCertificates) == 0 {
		return false, errors.New("server provided no certificate")
	}
	h := sha256.Sum256(state.PeerCertificates[0].Raw)
	gotPin := hex.EncodeToString(h[:])
	addLog("[TLS] Cert CN=%s, SHA-256=%s...", state.PeerCertificates[0].Subject.CommonName, gotPin[:16])

	if expectedPin != "" {
		if gotPin != expectedPin {
			return false, fmt.Errorf("Cert Pin mismatch! Got %s...", gotPin[:12])
		}
		addLog("[TLS] Certificate Pin verified OK")
	}

	br := bufio.NewReader(uConn)
	soapBody := common.BuildSoapCreateShellXML(serverAddr)

	// Шаг 1/3: без Authorization
	addLog("[HTTP 1/3] -> POST %s (no auth, SOAP %dB)", common.WinRMPath, len(soapBody))
	req0 := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, len(soapBody), soapBody)
	if _, err := io.WriteString(uConn, req0); err != nil {
		return false, err
	}
	resp0, err := http.ReadResponse(br, nil)
	if err != nil {
		return false, err
	}
	_, _ = io.Copy(io.Discard, resp0.Body)
	_ = resp0.Body.Close()
	if resp0.StatusCode != 401 {
		return false, fmt.Errorf("expected 401 on step 1/3, got %d", resp0.StatusCode)
	}

	// Шаг 2/3: NTLM Type 1
	addLog("[HTTP 2/3] -> POST %s (NTLM Type 1)", common.WinRMPath)
	t1 := common.BuildNTLMType1()
	req1 := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nAuthorization: NTLM %s\r\nContent-Length: 0\r\n\r\n",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, t1)
	if _, err := io.WriteString(uConn, req1); err != nil {
		return false, err
	}
	resp1, err := http.ReadResponse(br, nil)
	if err != nil {
		return false, err
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != 401 {
		return false, fmt.Errorf("expected 401 on step 2/3, got %d", resp1.StatusCode)
	}

	var serverChallenge [8]byte
	found := false
	for _, hdr := range resp1.Header.Values("WWW-Authenticate") {
		var b64 string
		if strings.HasPrefix(hdr, "NTLM ") {
			b64 = strings.TrimSpace(strings.TrimPrefix(hdr, "NTLM "))
		} else if strings.HasPrefix(hdr, "Negotiate ") {
			b64 = strings.TrimSpace(strings.TrimPrefix(hdr, "Negotiate "))
		}
		if b64 != "" {
			if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && len(raw) >= 32 {
				copy(serverChallenge[:], raw[24:32])
				found = true
			}
		}
	}
	if !found {
		return false, errors.New("no NTLM Type 2 Challenge")
	}

	// Шаг 3/3: NTLM Type 3 + SOAP
	addLog("[HTTP 3/3] -> POST %s (NTLM Type 3 + SOAP)", common.WinRMPath)
	t3 := common.BuildNTLMType3WithAuth(psk, serverChallenge)
	req2 := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nAuthorization: NTLM %s\r\nContent-Length: %d\r\n\r\n%s",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, t3, len(soapBody), soapBody)
	if _, err := io.WriteString(uConn, req2); err != nil {
		return false, err
	}
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		return false, err
	}
	if resp2.StatusCode != 200 {
		return false, fmt.Errorf("auth rejected (%d) — проверьте PSK или часы", resp2.StatusCode)
	}
	if resp2.ContentLength > 0 {
		_, _ = io.CopyN(io.Discard, resp2.Body, resp2.ContentLength)
	}

	_ = rawConn.SetDeadline(time.Time{})

	tf, err := ensureTun()
	if err != nil {
		return false, err
	}

	addLog("[VPN] Tunnel ESTABLISHED! Routing IPv4 via WinRM stream.")
	setState("CONNECTED")

	sessionDone := make(chan struct{})
	defer close(sessionDone)
	errCh := make(chan error, 2)

	go func() {
		for {
			select {
			case <-sessionDone:
				return
			case <-stopCh:
				return
			case pkt := <-tunRxCh:
				if err := common.WritePaddedFrame(uConn, pkt); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}
	}()

	go func() {
		scratch := make([]byte, 65536)
		for {
			pkt, err := common.ReadPaddedFrame(br, scratch)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
				if _, err := tf.Write(pkt); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}
	}()

	select {
	case <-stopCh:
		return true, nil
	case err := <-errCh:
		return true, err
	}
}

func buildAnsibleLinuxOpenSSL3Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			0x1302, 0x1303, 0x1301,
			0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc02b, 0xc02f,
			0xc024, 0xc028, 0xc023, 0xc027,
			0xc00a, 0xc014, 0xc009, 0xc013,
			0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []utls.TLSExtension{
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00, 0x01, 0x02}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519, utls.CurveP256, utls.CurveP521, utls.CurveP384,
			}},
			&utls.SessionTicketExtension{},
			&utls.GenericExtension{Id: 22},
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512,
				utls.PKCS1WithSHA256, utls.PKCS1WithSHA384, utls.PKCS1WithSHA512,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
		},
	}
}
