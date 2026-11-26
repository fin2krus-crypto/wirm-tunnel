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
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"winrm-vpn/common"
)

const (
	AppVersion         = "0.4.2"
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
	stateMu       sync.RWMutex
	curState      = "CONNECTING"
	logsBuf       []string
	checkConn     atomic.Bool
	lastRxNano    atomic.Int64
	activeMu      sync.Mutex
	activeRecvRaw net.Conn
	activeSendRaw net.Conn
	stopCh        = make(chan struct{})
	reconnCh      = make(chan struct{}, 1)
	stopOnce      sync.Once
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
	r, s := activeRecvRaw, activeSendRaw
	activeMu.Unlock()
	if r != nil {
		_ = r.Close()
	}
	if s != nil {
		_ = s.Close()
	}
	select {
	case reconnCh <- struct{}{}:
	default:
	}
}

func triggerStop() {
	stopOnce.Do(func() {
		close(stopCh)
	})
}

func gracefulTLSClose(uConn *utls.UConn, rawConn net.Conn) {
	if rawConn != nil {
		_ = rawConn.SetWriteDeadline(time.Now().Add(150 * time.Millisecond))
	}
	if uConn != nil {
		_ = uConn.Close()
	} else if rawConn != nil {
		_ = rawConn.Close()
	}
}

func main() {
	cfgPath := flag.String("config", "", "Path to JSON config")
	flag.Parse()
	if *cfgPath == "" {
		os.Exit(1)
	}

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		os.Exit(1)
	}
	var cfg HelperConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		os.Exit(1)
	}
	_ = os.Remove(*cfgPath)
	checkConn.Store(cfg.CheckConn)

	hostOnly, _, err := net.SplitHostPort(cfg.Server)
	if err != nil || hostOnly == "" {
		os.Exit(1)
	}
	serverIPs, err := net.LookupIP(hostOnly)
	if err != nil || len(serverIPs) == 0 {
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
		os.Exit(1)
	}

	if err := startControlServer(); err != nil {
		os.Exit(1)
	}
	defer os.Remove(ctlMetaPath)

	netState := &LinuxNetworkState{}
	defer netState.Restore()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		addLog("[LINUX] Завершение работы...")
		triggerStop()
	}()

	go runNetworkSwitchMonitor(netState)

	expectedPin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(cfg.Pin), ":", ""))
	var sessionID [16]byte
	_, _ = rand.Read(sessionID[:])

	var tunFile *os.File
	tunRxCh := make(chan []byte, 1024)
	defer func() {
		if tunFile != nil {
			_ = tunFile.Close()
		}
	}()

	ensureTun := func() (*os.File, error) {
		if tunFile != nil {
			return tunFile, nil
		}
		addLog("[LINUX] Авторизация пройдена. Открываю TUN...")
		f, name, err := openLinuxTun()
		if err != nil {
			return nil, err
		}
		if err := netState.Setup(name, serverIPv4); err != nil {
			_ = f.Close()
			return nil, err
		}
		tunFile = f
		addLog("[LINUX] Интерфейс %s поднят (10.88.0.2/24, DNS 1.1.1.1).", name)

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

		wasConnected, rotated, err := runDualChannelSession(cfg.Server, cfg.PSK, expectedPin, sessionID, ensureTun, tunRxCh)
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

		if rotated {
			addLog("[SYS] Плановая ротация сокетов WinRM...")
			continue
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
			_, _ = rand.Read(sessionID[:])
			addLog("[SYS] Переключение сети — переподключение...")
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
		resp := StatusResponse{State: curState, CheckConn: checkConn.Load(), Logs: logsCopy}
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
		checkConn.Store(enabled)
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
		if err == nil {
			re := regexp.MustCompile(`time=([0-9.]+\s*ms)`)
			rtt := ""
			if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
				rtt = " (" + m[1] + ")"
			}
			msg := "Тестовый пинг 8.8.8.8 прошел" + rtt
			addLog("[PING] SUCCESS%s", rtt)
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
			e := err1
			if e == nil {
				e = err2
			}
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(fmt.Sprintf("Ошибка проверки IP: %v", e)))
			return
		}
		res := fmt.Sprintf("%s  |  IP/Host: %s", strings.ToUpper(strings.TrimSpace(cc)), strings.TrimSpace(host))
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

	go func() { _ = http.Serve(ln, mux) }()
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

func dialWinRMChannel(serverAddr, psk, expectedPin string, sessionID [16]byte, role byte, verbose bool) (net.Conn, *utls.UConn, *bufio.Reader, error) {
	rawConn, err := (&net.Dialer{Timeout: 4 * time.Second}).Dial("tcp4", serverAddr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("TCP connect failed: %w", err)
	}
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	uConn := utls.UClient(rawConn, &utls.Config{InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uConn.ApplyPreset(buildAnsibleLinuxOpenSSL3Spec()); err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, err
	}
	if err := uConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := uConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = rawConn.Close()
		return nil, nil, nil, errors.New("no cert")
	}
	h := sha256.Sum256(state.PeerCertificates[0].Raw)
	gotPin := hex.EncodeToString(h[:])
	if verbose {
		addLog("[TLS] OK (%s), Cert CN=%s, Pin=%s...",
			tls.CipherSuiteName(state.CipherSuite), state.PeerCertificates[0].Subject.CommonName, gotPin[:12])
	}
	if expectedPin != "" && gotPin != expectedPin {
		gracefulTLSClose(uConn, rawConn)
		return nil, nil, nil, fmt.Errorf("Cert Pin mismatch! Got %s...", gotPin[:12])
	}

	br := bufio.NewReader(uConn)
	soapBody := common.BuildSoapCreateShellXML(serverAddr)

	req0 := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, len(soapBody), soapBody)
	if _, err := io.WriteString(uConn, req0); err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, err
	}
	resp0, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, err
	}
	_, _ = io.Copy(io.Discard, resp0.Body)
	_ = resp0.Body.Close()
	if resp0.StatusCode != 401 {
		gracefulTLSClose(uConn, rawConn)
		return nil, nil, nil, fmt.Errorf("expected 401 on 1/3, got %d", resp0.StatusCode)
	}

	t1 := common.BuildNTLMType1()
	req1 := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nAuthorization: NTLM %s\r\nContent-Length: 0\r\n\r\n",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, t1)
	if _, err := io.WriteString(uConn, req1); err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, err
	}
	resp1, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, err
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != 401 {
		gracefulTLSClose(uConn, rawConn)
		return nil, nil, nil, fmt.Errorf("expected 401 on 2/3, got %d", resp1.StatusCode)
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
		gracefulTLSClose(uConn, rawConn)
		return nil, nil, nil, errors.New("no NTLM Type 2 Challenge")
	}

	t3 := common.BuildNTLMType3SessionAuth(psk, serverChallenge, sessionID, role)
	req2 := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nAuthorization: NTLM %s\r\nContent-Length: %d\r\n\r\n%s",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, t3, len(soapBody), soapBody)
	if _, err := io.WriteString(uConn, req2); err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, err
	}
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, nil, err
	}
	if resp2.StatusCode != 200 {
		gracefulTLSClose(uConn, rawConn)
		return nil, nil, nil, fmt.Errorf("auth rejected (%d)", resp2.StatusCode)
	}
	if resp2.ContentLength > 0 {
		_, _ = io.CopyN(io.Discard, resp2.Body, resp2.ContentLength)
	}
	_ = resp2.Body.Close()

	_ = rawConn.SetDeadline(time.Time{})
	return rawConn, uConn, br, nil
}

func runDualChannelSession(
	serverAddr, psk, expectedPin string,
	sessionID [16]byte,
	ensureTun func() (*os.File, error),
	tunRxCh <-chan []byte,
) (bool, bool, error) {
	addLog("[HTTP] Открытие канала Receive...")
	recvRaw, recvU, recvBR, err := dialWinRMChannel(serverAddr, psk, expectedPin, sessionID, common.RoleRecv, true)
	if err != nil {
		return false, false, err
	}

	addLog("[HTTP] Открытие канала Send...")
	sendRaw, sendU, sendBR, err := dialWinRMChannel(serverAddr, psk, expectedPin, sessionID, common.RoleSend, false)
	if err != nil {
		gracefulTLSClose(recvU, recvRaw)
		return false, false, err
	}

	activeMu.Lock()
	activeRecvRaw, activeSendRaw = recvRaw, sendRaw
	activeMu.Unlock()

	tf, err := ensureTun()
	if err != nil {
		gracefulTLSClose(recvU, recvRaw)
		gracefulTLSClose(sendU, sendRaw)
		activeMu.Lock()
		activeRecvRaw, activeSendRaw = nil, nil
		activeMu.Unlock()
		return false, false, err
	}

	lastRxNano.Store(time.Now().UnixNano())
	addLog("[VPN] 2-канальный WinRM туннель активен.")
	setState("CONNECTED")

	sessionDone := make(chan struct{})
	errCh := make(chan error, 3)
	kaReqCh := make(chan struct{}, 4)
	kaAckCh := make(chan struct{}, 4)

	rotateTimer := time.NewTimer(time.Duration(10+mathrand.Intn(6)) * time.Minute)
	defer rotateTimer.Stop()

	go func() {
		for {
			select {
			case <-sessionDone:
				return
			default:
			}
			recvSoap := common.BuildSoapReceiveXML(serverAddr)
			reqStr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s",
				common.WinRMPath, serverAddr, common.WinRMUserAgent, len(recvSoap), recvSoap)

			_ = recvRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.WriteString(recvU, reqStr); err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			_ = recvRaw.SetWriteDeadline(time.Time{})

			resp, err := http.ReadResponse(recvBR, nil)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					_ = resp.Body.Close()
				}
				select {
				case errCh <- errors.New("recv response failed"):
				default:
				}
				return
			}

			for {
				fType, pkts, err := common.DecodeBatchFrame(resp.Body)
				if err != nil {
					_ = resp.Body.Close()
					if errors.Is(err, io.EOF) {
						break
					}
					select {
					case errCh <- err:
					default:
					}
					return
				}
				lastRxNano.Store(time.Now().UnixNano())
				if fType == common.FrameKeepAlive {
					select {
					case kaAckCh <- struct{}{}:
					default:
					}
				} else {
					for _, pkt := range pkts {
						if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
							_, _ = tf.Write(pkt)
						}
					}
				}
			}
		}
	}()

	// Канал 2: Send (Transfer-Encoding: chunked POST /wsman, ротация 55-85с / 20МБ + 1мс батчер)
	go func() {
		const maxSendChunkedBytes = 20 * 1024 * 1024
		for {
			select {
			case <-sessionDone:
				return
			case <-stopCh:
				return
			default:
			}
			hdr := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nTransfer-Encoding: chunked\r\n\r\n",
				common.WinRMPath, serverAddr, common.WinRMUserAgent)
			_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.WriteString(sendU, hdr); err != nil {
				select { case errCh <- err: default: }
				return
			}
			_ = sendRaw.SetWriteDeadline(time.Time{})
			rolloverTimer := time.NewTimer(time.Duration(55+mathrand.Intn(31)) * time.Second)
			sentBytes, rolloverNow := 0, false
			for !rolloverNow {
				select {
				case <-sessionDone:
					rolloverTimer.Stop(); return
				case <-stopCh:
					rolloverTimer.Stop(); return
				case <-rolloverTimer.C:
					rolloverNow = true
				case <-kaReqCh:
					frame := common.EncodeBatchFrame(nil, common.FrameKeepAlive)
					_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if err := common.WriteHTTPChunk(sendU, frame); err != nil {
						rolloverTimer.Stop(); select { case errCh <- err: default: }; return
					}
					_ = sendRaw.SetWriteDeadline(time.Time{}); sentBytes += len(frame)
				case firstPkt := <-tunRxCh:
					pkts := make([][]byte, 1, 64); pkts[0] = firstPkt; batchBytes := len(firstPkt)
					cTimer := time.NewTimer(1 * time.Millisecond)
				drain:
					for len(pkts) < 64 && batchBytes < 65536 {
						select {
						case p := <-tunRxCh: pkts = append(pkts, p); batchBytes += len(p)
						case <-cTimer.C: break drain
						}
					}
					if !cTimer.Stop() { select { case <-cTimer.C: default: } }
					frame := common.EncodeBatchFrame(pkts, common.FrameData)
					_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if err := common.WriteHTTPChunk(sendU, frame); err != nil {
						rolloverTimer.Stop(); select { case errCh <- err: default: }; return
					}
					_ = sendRaw.SetWriteDeadline(time.Time{}); sentBytes += len(frame)
				}
				if sentBytes >= maxSendChunkedBytes { rolloverTimer.Stop(); rolloverNow = true }
			}
			_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.WriteString(sendU, "0\r\n\r\n"); err != nil { select { case errCh <- err: default: }; return }
			_ = sendRaw.SetWriteDeadline(time.Time{}); _ = sendRaw.SetReadDeadline(time.Now().Add(10 * time.Second))
			resp, err := http.ReadResponse(sendBR, nil)
			if err != nil { select { case errCh <- err: default: }; return }
			_, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close(); _ = sendRaw.SetReadDeadline(time.Time{})
			if resp.StatusCode != 200 { select { case errCh <- fmt.Errorf("send %d", resp.StatusCode): default: }; return }
		}
	}()

	go func() {
		for {
			waitSec := 30 + mathrand.Intn(31)
			select {
			case <-sessionDone:
				return
			case <-stopCh:
				return
			case <-time.After(time.Duration(waitSec) * time.Second):
			}
			if !checkConn.Load() || time.Since(time.Unix(0, lastRxNano.Load())) < 30*time.Second {
				continue
			}
			for len(kaAckCh) > 0 {
				<-kaAckCh
			}
			select {
			case kaReqCh <- struct{}{}:
			default:
			}
			got := false
			select {
			case <-kaAckCh:
				got = true
			case <-time.After(5 * time.Second):
			case <-sessionDone:
				return
			}
			if got || time.Since(time.Unix(0, lastRxNano.Load())) < 10*time.Second {
				addLog("[WATCHDOG] WinRM KeepAlive OK")
				continue
			}

			retrySec := 10 + mathrand.Intn(11)
			addLog("[WATCHDOG] Нет ответа на KeepAlive. Повтор через %dс...", retrySec)
			select {
			case <-sessionDone:
				return
			case <-stopCh:
				return
			case <-time.After(time.Duration(retrySec) * time.Second):
			}
			if !checkConn.Load() {
				continue
			}
			select {
			case kaReqCh <- struct{}{}:
			default:
			}
			got = false
			select {
			case <-kaAckCh:
				got = true
			case <-time.After(5 * time.Second):
			case <-sessionDone:
				return
			}
			if got || time.Since(time.Unix(0, lastRxNano.Load())) < 10*time.Second {
				addLog("[WATCHDOG] Повторный KeepAlive OK")
				continue
			}
			addLog("[WATCHDOG] Повторный KeepAlive не прошёл! Перезапуск...")
			select {
			case errCh <- errors.New("watchdog timeout"):
			default:
			}
			return
		}
	}()

	var retErr error
	var isRotate bool
	select {
	case <-stopCh:
		addLog("[VPN] Штатное отключение (TLS close_notify)...")
		close(sessionDone)
		gracefulTLSClose(recvU, recvRaw)
		gracefulTLSClose(sendU, sendRaw)
	case <-rotateTimer.C:
		isRotate = true
		close(sessionDone)
		gracefulTLSClose(recvU, recvRaw)
		gracefulTLSClose(sendU, sendRaw)
	case retErr = <-errCh:
		close(sessionDone)
		_ = recvRaw.Close()
		_ = sendRaw.Close()
	}

	activeMu.Lock()
	activeRecvRaw, activeSendRaw = nil, nil
	activeMu.Unlock()
	return true, isRotate, retErr
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
