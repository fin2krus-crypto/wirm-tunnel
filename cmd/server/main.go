package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"winrm-vpn/common"
)

const AppVersion = "0.3.0"

//go:embed embedded/winrm-tls-rustls
var embeddedRustlsBin []byte

func printQuickGuide() {
	fmt.Printf(`WinRM-VPN Server v%s (All-in-One: Rustls + gVisor + Web-Panel :49777)

Короткая инструкция по запуску на Linux (x86_64):
  1. Откройте порты в фаерволе:
       ufw allow 5986/tcp   (WinRM VPN)
       ufw allow 49777/tcp  (Веб-панель управления)

  2. Запустите интерактивное меню управления (без параметров):
       winrm-vpn-server

  3. Или запустите сервер напрямую параметрами:
       winrm-vpn-server -listen 0.0.0.0:5986 -psk "ВАШ_КЛЮЧ_PSK"
     (Несколько ключей можно указать через запятую: -psk "key1,key2")

  4. Веб-панель управления доступна по адресу:
       http://<IP_СЕРВЕРА>:49777

Параметры запуска:
  -listen   string   Внешний адрес и порт VPN (по умолчанию "0.0.0.0:5986")
  -web-port int      Принудительный порт веб-панели (по умолчанию из panel.json или 49777)
  -psk      string   Ключ или список ключей через запятую
  -daemon            Запуск с использованием пользователей из users.json (без -psk)
  -data-dir string   Директория хранения users.json, panel.json, сокета и сертификата
  -cert     string   Путь к TLS-сертификату (по умолчанию "winrm_cert.pem")
  -key      string   Путь к приватному ключу (по умолчанию "winrm_key.pem")
`, AppVersion)
}

// VPNEngine управляет жизненным циклом VPN-туннеля (порт 5986 + rustls) независимо от веб-панели
type VPNEngine struct {
	mu         sync.Mutex
	running    bool
	stopReq    bool
	listenAddr string
	certPath   string
	keyPath    string
	hostName   string
	certPin    string
	statsMgr   *StatsManager

	backendLn net.Listener
	rustlsCmd *exec.Cmd
	tmpPath   string
}

func NewVPNEngine(listenAddr, certPath, keyPath string, statsMgr *StatsManager) *VPNEngine {
	return &VPNEngine{
		listenAddr: listenAddr,
		certPath:   certPath,
		keyPath:    keyPath,
		statsMgr:   statsMgr,
	}
}

func (e *VPNEngine) Start() error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil
	}

	_, fingerprint, hostName, err := loadOrGenerateWindowsCert(e.certPath, e.keyPath)
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("certificate error: %w", err)
	}
	e.certPin = fingerprint
	e.hostName = hostName
	e.statsMgr.SetMetadata(e.listenAddr, hostName, fingerprint, "", 0)

	backendLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		e.mu.Unlock()
		return fmt.Errorf("backend listen failed: %w", err)
	}
	backendAddr := backendLn.Addr().String()

	rustlsCmd, tmpPath, err := startEmbeddedRustls(e.listenAddr, backendAddr, e.certPath, e.keyPath)
	if err != nil {
		_ = backendLn.Close()
		e.mu.Unlock()
		return fmt.Errorf("failed to start embedded rustls: %w", err)
	}

	e.backendLn = backendLn
	e.rustlsCmd = rustlsCmd
	e.tmpPath = tmpPath
	e.stopReq = false
	e.running = true
	e.statsMgr.SetVPNRunning(true)
	e.mu.Unlock()

	go func(cmd *exec.Cmd, tmp string) {
		err := cmd.Wait()
		_ = os.Remove(tmp)

		e.mu.Lock()
		wasExpected := e.stopReq || e.rustlsCmd != cmd
		if e.rustlsCmd == cmd {
			e.running = false
			e.rustlsCmd = nil
			e.tmpPath = ""
			if e.backendLn != nil {
				_ = e.backendLn.Close()
				e.backendLn = nil
			}
			e.statsMgr.SetVPNRunning(false)
		}
		e.mu.Unlock()

		if !wasExpected {
			log.Printf("[ERR] Embedded rustls frontend exited unexpectedly: %v", err)
		}
	}(rustlsCmd, tmpPath)

	go func(ln net.Listener, hName string) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleWinRMConnection(conn, e.statsMgr, hName)
		}
	}(backendLn, hostName)

	log.Printf("[VPN] Engine started on %s (Hostname: %s)", e.listenAddr, hostName)
	return nil
}

func (e *VPNEngine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.stopReq = true
	e.running = false
	ln := e.backendLn
	cmd := e.rustlsCmd
	tmp := e.tmpPath
	e.backendLn = nil
	e.rustlsCmd = nil
	e.tmpPath = ""
	e.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		time.Sleep(150 * time.Millisecond)
		_ = cmd.Process.Kill()
	}
	if tmp != "" {
		_ = os.Remove(tmp)
	}

	e.statsMgr.SetVPNRunning(false)
	e.statsMgr.CloseAllActive()
	log.Printf("[VPN] Engine stopped (Web panel remains online)")
}

func (e *VPNEngine) Restart() error {
	e.Stop()
	time.Sleep(300 * time.Millisecond)
	return e.Start()
}

func main() {
	if len(os.Args) == 1 {
		runInteractiveCLI()
		return
	}

	listenAddr := flag.String("listen", "0.0.0.0:5986", "WinRM HTTPS listen address")
	webPortFlag := flag.Int("web-port", 0, "Override web panel port (default 49777 or saved in panel.json)")
	pskFlag := flag.String("psk", "", "Pre-Shared Key(s), comma-separated")
	daemonMode := flag.Bool("daemon", false, "Run server using users from users.json")
	dataDirFlag := flag.String("data-dir", "", "Directory for users.json, panel.json and control.sock")
	certFile := flag.String("cert", "winrm_cert.pem", "Path to TLS cert")
	keyFile := flag.String("key", "winrm_key.pem", "Path to TLS key")
	_ = flag.Bool("no-tun", false, "Deprecated (TUN is no longer required)")
	flag.Parse()

	dataDir := resolveDataDir(*dataDirFlag)

	var cliPSKs []string
	for _, k := range strings.Split(*pskFlag, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			cliPSKs = append(cliPSKs, k)
		}
	}

	if !*daemonMode && len(cliPSKs) == 0 {
		fmt.Println("Ошибка: укажите параметр -psk или -daemon (либо запустите без параметров для CLI-меню).")
		fmt.Println()
		printQuickGuide()
		os.Exit(1)
	}

	statsMgr := NewStatsManager(dataDir)
	if err := statsMgr.LoadOrInit(cliPSKs); err != nil {
		log.Fatalf("Failed to initialize user store: %v", err)
	}
	if len(statsMgr.GetAllPSKs()) == 0 {
		log.Fatal("ERROR: в базе нет ни одного пользователя (PSK). Добавьте пользователя в CLI-меню или передайте -psk.")
	}
	statsMgr.StartPeriodicFlush()

	certPath := resolveAssetPath(*certFile, "winrm_cert.pem", dataDir)
	keyPath := resolveAssetPath(*keyFile, "winrm_key.pem", dataDir)

	vpnEngine := NewVPNEngine(*listenAddr, certPath, keyPath, statsMgr)
	if err := vpnEngine.Start(); err != nil {
		log.Fatalf("Failed to start VPN engine: %v", err)
	}

	webPanel, err := StartWebPanel(dataDir, *webPortFlag, statsMgr, vpnEngine)
	if err != nil {
		log.Printf("[WARN] Веб-панель не запущена: %v", err)
	} else {
		log.Printf("[WEB] Веб-панель управления доступна на порту :%d", webPanel.Port())
	}

	go func() {
		extIP := fetchExternalIP()
		statsMgr.SetMetadata("", "", "", extIP, 0)
	}()

	shutdownFn := func() {
		log.Printf("[SYS] Shutting down WinRM-VPN Server v%s...", AppVersion)
		vpnEngine.Stop()
		statsMgr.FlushAndClose()
		os.Exit(0)
	}

	if err := statsMgr.StartControlSocket(vpnEngine, shutdownFn); err != nil {
		log.Printf("[WARN] Control socket not started: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		shutdownFn()
	}()

	log.Printf("================================================================")
	log.Printf("WinRM-VPN Server v%s Ready on %s", AppVersion, *listenAddr)
	if webPanel != nil {
		log.Printf("Web Control Panel : http://0.0.0.0:%d", webPanel.Port())
	}
	log.Printf("Emulated Hostname : %s", vpnEngine.hostName)
	log.Printf("Loaded PSK keys   : %d (DataDir: %s)", len(statsMgr.GetAllPSKs()), dataDir)
	log.Printf("Certificate SHA-256 Pin (copy to Android/macOS App):")
	log.Printf("%s", vpnEngine.certPin)
	log.Printf("================================================================")

	select {}
}

func resolveAssetPath(val, defaultName, dataDir string) string {
	if val != defaultName || filepath.IsAbs(val) || dataDir == "." {
		return val
	}
	if _, err := os.Stat(val); err == nil {
		return val
	}
	return filepath.Join(dataDir, val)
}

func startEmbeddedRustls(listenAddr, backendAddr, certPath, keyPath string) (*exec.Cmd, string, error) {
	if len(embeddedRustlsBin) == 0 {
		return nil, "", errors.New("embedded rustls binary is empty")
	}

	tmpFile, err := os.CreateTemp("", "winrm-tls-*")
	if err != nil {
		return nil, "", err
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(embeddedRustlsBin); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, "", err
	}
	if err := tmpFile.Chmod(0700); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, "", err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, "", err
	}

	cmd := exec.Command(tmpPath, listenAddr, backendAddr, certPath, keyPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	if err := cmd.Start(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, "", err
	}
	return cmd, tmpPath, nil
}

func verifyAnyPSK(b64Token string, pskList []string, challenge [8]byte) (string, bool) {
	for _, psk := range pskList {
		if common.VerifyNTLMType3Auth(b64Token, psk, challenge) {
			return psk, true
		}
	}
	return "", false
}

func isTimeoutOrClosed(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, net.ErrClosed)
}

func handleWinRMConnection(conn net.Conn, statsMgr *StatsManager, hostName string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))

	br := bufio.NewReader(conn)
	var currentChallenge [8]byte
	hasChallenge := false

	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !isTimeoutOrClosed(err) {
				writeHttpSys400(conn)
			}
			return
		}
		if req.Host == "" {
			writeHttpSys400(conn)
			return
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(req.Body, 524288))
		_ = req.Body.Close()

		path := req.URL.Path
		if !strings.EqualFold(path, "/wsman") && !strings.EqualFold(path, "/wsman-anon") {
			writeHttpSys404(conn)
			return
		}
		if req.Method != http.MethodPost {
			writeHttpSys404(conn)
			return
		}

		bodyStr := string(bodyBytes)
		if strings.Contains(bodyStr, "wsmanidentity.xsd") && strings.Contains(bodyStr, ":Identify") {
			writeWSManIdentify200(conn)
			continue
		}

		authHdr := req.Header.Get("Authorization")
		if authHdr == "" {
			writeWinRM401NoToken(conn)
			continue
		}

		var authScheme, b64Token string
		if strings.HasPrefix(authHdr, "Negotiate ") {
			authScheme = "Negotiate"
			b64Token = strings.TrimSpace(strings.TrimPrefix(authHdr, "Negotiate "))
		} else if strings.HasPrefix(authHdr, "NTLM ") {
			authScheme = "NTLM"
			b64Token = strings.TrimSpace(strings.TrimPrefix(authHdr, "NTLM "))
		} else {
			writeWinRM401NoToken(conn)
			continue
		}

		if strings.HasPrefix(b64Token, "TlRMTVNTUAAB") {
			var type2B64 string
			type2B64, currentChallenge = common.BuildNTLMType2(hostName)
			hasChallenge = true
			writeWinRM401Type2(conn, authScheme, type2B64)
			continue
		}

		if hasChallenge && strings.HasPrefix(b64Token, "TlRMTVNTUAAD") {
			if matchedPSK, ok := verifyAnyPSK(b64Token, statsMgr.GetAllPSKs(), currentChallenge); ok {
				writeWinRM200StreamStart(conn, req.Host)
				_ = conn.SetDeadline(time.Time{})

				connID := statsMgr.ClientConnected(matchedPSK, conn)
				defer statsMgr.ClientDisconnected(matchedPSK, connID)

				ns, err := NewClientNetstack(func(pkt []byte) error {
					if err := common.WritePaddedFrame(conn, pkt); err != nil {
						return err
					}
					statsMgr.AddTx(matchedPSK, len(pkt))
					return nil
				})
				if err != nil {
					log.Printf("Netstack init error: %v", err)
					return
				}
				defer ns.Close()

				log.Printf("[+] Client connected (key: %.8s...)", matchedPSK)
				scratch := make([]byte, 65536)
				for {
					ipPkt, err := common.ReadPaddedFrame(br, scratch)
					if err != nil {
						break
					}
					statsMgr.AddRx(matchedPSK, len(ipPkt))
					ns.InjectPacket(ipPkt)
				}
				log.Printf("[-] Client disconnected (key: %.8s...)", matchedPSK)
				return
			}
		}

		writeWinRM401Final(conn, authScheme)
		return
	}
}

func httpDate() string {
	return time.Now().UTC().Format(http.TimeFormat)
}

func writeHttpSys400(w io.Writer) {
	body := common.HttpSysBadRequestHTML
	resp := fmt.Sprintf("HTTP/1.1 400 Bad Request\r\n"+
		"Content-Type: text/html; charset=us-ascii\r\n"+
		"Server: %s\r\n"+
		"Date: %s\r\n"+
		"Connection: close\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		common.ServerHeader, httpDate(), len(body), body)
	_, _ = io.WriteString(w, resp)
}

func writeHttpSys404(w io.Writer) {
	body := common.HttpSysNotFoundHTML
	resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\n"+
		"Content-Type: text/html; charset=us-ascii\r\n"+
		"Server: %s\r\n"+
		"Date: %s\r\n"+
		"Connection: close\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		common.ServerHeader, httpDate(), len(body), body)
	_, _ = io.WriteString(w, resp)
}

func writeWSManIdentify200(w io.Writer) {
	body := common.WSManIdentifyResponseXML
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
		"Server: %s\r\n"+
		"Date: %s\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		common.ServerHeader, httpDate(), len(body), body)
	_, _ = io.WriteString(w, resp)
}

func writeWinRM401NoToken(w io.Writer) {
	resp := fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\n"+
		"Server: %s\r\n"+
		"WWW-Authenticate: Negotiate\r\n"+
		"WWW-Authenticate: Kerberos\r\n"+
		"WWW-Authenticate: CredSSP\r\n"+
		"WWW-Authenticate: NTLM\r\n"+
		"Date: %s\r\n"+
		"Content-Length: 0\r\n\r\n",
		common.ServerHeader, httpDate())
	_, _ = io.WriteString(w, resp)
}

func writeWinRM401Type2(w io.Writer, scheme string, type2B64 string) {
	resp := fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\n"+
		"Server: %s\r\n"+
		"WWW-Authenticate: %s %s\r\n"+
		"Date: %s\r\n"+
		"Content-Length: 0\r\n\r\n",
		common.ServerHeader, scheme, type2B64, httpDate())
	_, _ = io.WriteString(w, resp)
}

func writeWinRM401Final(w io.Writer, scheme string) {
	resp := fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\n"+
		"Server: %s\r\n"+
		"WWW-Authenticate: %s\r\n"+
		"Date: %s\r\n"+
		"Connection: close\r\n"+
		"Content-Length: 0\r\n\r\n",
		common.ServerHeader, scheme, httpDate())
	_, _ = io.WriteString(w, resp)
}

func writeWinRM200StreamStart(w io.Writer, hostAddr string) {
	soap := common.BuildSoapCreateShellResponseXML(hostAddr)
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
		"Server: %s\r\n"+
		"Date: %s\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		common.ServerHeader, httpDate(), len(soap), soap)
	_, _ = io.WriteString(w, resp)
}

func generateRandomWinHost() string {
	const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 11)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return "WIN-" + string(b)
}

func loadOrGenerateWindowsCert(certPath, keyPath string) (tls.Certificate, string, string, error) {
	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, "", "", err
		}
		h := sha256.Sum256(cert.Certificate[0])
		hostName := ""
		if parsed, err := x509.ParseCertificate(cert.Certificate[0]); err == nil && parsed.Subject.CommonName != "" {
			hostName = parsed.Subject.CommonName
		} else {
			hostName = generateRandomWinHost()
		}
		return cert, hex.EncodeToString(h[:]), hostName, nil
	}

	hostName := generateRandomWinHost()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}

	serialBytes := make([]byte, 16)
	_, _ = rand.Read(serialBytes)
	serialBytes[0] &= 0x7f

	now := time.Now().UTC()
	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes),
		Subject:      pkix.Name{CommonName: hostName},
		NotBefore:    now.Add(-10 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostName},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	_ = certOut.Close()

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	_ = keyOut.Close()

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}
	h := sha256.Sum256(derBytes)
	return cert, hex.EncodeToString(h[:]), hostName, nil
}
