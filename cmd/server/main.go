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
	"strings"
	"syscall"
	"time"

	"winrm-vpn/common"
)

const AppVersion = "0.0.8"

//go:embed embedded/winrm-tls-rustls
var embeddedRustlsBin []byte

func printQuickGuide() {
	fmt.Printf(`WinRM-VPN Server v%s (All-in-One: Rustls AES-GCM + gVisor Netstack — БЕЗ TUN и БЕЗ root!)

Короткая инструкция по запуску на Linux (x86_64):
  1. Откройте порт 5986/TCP в фаерволе:
       ufw allow 5986/tcp

  2. Сгенерируйте секретный ключ (PSK):
       openssl rand -hex 24

  3. Запустите единый бинарник (root и iptables НЕ требуются):
       ./winrm-vpn-server -listen 0.0.0.0:5986 -psk "ВАШ_КЛЮЧ_PSK"

     (Для нескольких пользователей укажите ключи через запятую: -psk "key1,key2")

  4. Скопируйте выведенный Certificate SHA-256 Pin в Android-клиент.

Опционально (если есть root, для полного TCP-отпечатка Windows Server):
  sysctl -w net.ipv4.tcp_timestamps=0

Параметры запуска:
  -listen string   Внешний адрес и порт прослушивания (по умолчанию "0.0.0.0:5986")
  -psk    string   Ключ или список ключей через запятую (обязательно)
  -cert   string   Путь к TLS-сертификату (по умолчанию "winrm_cert.pem")
  -key    string   Путь к приватному ключу (по умолчанию "winrm_key.pem")
`, AppVersion)
}

func main() {
	if len(os.Args) == 1 {
		printQuickGuide()
		os.Exit(0)
	}

	listenAddr := flag.String("listen", "0.0.0.0:5986", "WinRM HTTPS listen address")
	pskFlag := flag.String("psk", "", "Pre-Shared Key(s), comma-separated (required)")
	certFile := flag.String("cert", "winrm_cert.pem", "Path to TLS cert")
	keyFile := flag.String("key", "winrm_key.pem", "Path to TLS key")
	_ = flag.Bool("no-tun", false, "Deprecated (TUN is no longer required)")
	flag.Parse()

	var pskList []string
	for _, k := range strings.Split(*pskFlag, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			pskList = append(pskList, k)
		}
	}
	if len(pskList) == 0 {
		fmt.Println("Ошибка: не указан обязательный параметр -psk.")
		fmt.Println()
		printQuickGuide()
		os.Exit(1)
	}

	_, fingerprint, hostName, err := loadOrGenerateWindowsCert(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Certificate error: %v", err)
	}

	// 1. Поднимаем локальный Go-бэкенд (WinRM + gVisor Netstack) на свободном loopback-порту
	backendLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Internal backend listen failed: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	// 2. Распаковываем и запускаем встроенный Rustls-фронтенд (AES-GCM only, без ChaCha20, TTL=128)
	rustlsCmd, tmpPath, err := startEmbeddedRustls(*listenAddr, backendAddr, *certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to start embedded rustls frontend: %v", err)
	}
	cleanup := func() {
		if rustlsCmd != nil && rustlsCmd.Process != nil {
			_ = rustlsCmd.Process.Signal(syscall.SIGTERM)
			_ = rustlsCmd.Wait()
		}
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}
	defer cleanup()

	// Корректная остановка обоих процессов по Ctrl+C / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("[SYS] Shutting down WinRM-VPN Server v%s...", AppVersion)
		cleanup()
		os.Exit(0)
	}()

	// Следим, чтобы фронтенд не упал (например, если порт 5986 уже занят)
	go func() {
		err := rustlsCmd.Wait()
		_ = os.Remove(tmpPath)
		log.Fatalf("Embedded rustls frontend exited unexpectedly: %v", err)
	}()

	log.Printf("================================================================")
	log.Printf("WinRM-VPN Server v%s (All-in-One: Rustls + gVisor) Ready on %s", AppVersion, *listenAddr)
	log.Printf("Emulated Windows Hostname: %s", hostName)
	log.Printf("Loaded PSK keys: %d", len(pskList))
	log.Printf("Certificate SHA-256 Pin (copy to Android App):")
	log.Printf("%s", fingerprint)
	log.Printf("================================================================")

	for {
		conn, err := backendLn.Accept()
		if err != nil {
			continue
		}
		go handleWinRMConnection(conn, pskList, hostName)
	}
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
	// Обязательно закрываем дескриптор до запуска, чтобы избежать ETXTBSY
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

func verifyAnyPSK(b64Token string, pskList []string, challenge [8]byte) bool {
	for _, psk := range pskList {
		if common.VerifyNTLMType3Auth(b64Token, psk, challenge) {
			return true
		}
	}
	return false
}

func isTimeoutOrClosed(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, net.ErrClosed)
}

func handleWinRMConnection(conn net.Conn, pskList []string, hostName string) {
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

		var b64Token string
		if strings.HasPrefix(authHdr, "Negotiate ") {
			b64Token = strings.TrimSpace(strings.TrimPrefix(authHdr, "Negotiate "))
		} else if strings.HasPrefix(authHdr, "NTLM ") {
			b64Token = strings.TrimSpace(strings.TrimPrefix(authHdr, "NTLM "))
		} else {
			writeWinRM401NoToken(conn)
			continue
		}

		if strings.HasPrefix(b64Token, "TlRMTVNTUAAB") {
			var type2B64 string
			type2B64, currentChallenge = common.BuildNTLMType2(hostName)
			hasChallenge = true
			writeWinRM401Type2(conn, type2B64)
			continue
		}

		if hasChallenge && strings.HasPrefix(b64Token, "TlRMTVNTUAAD") {
			if verifyAnyPSK(b64Token, pskList, currentChallenge) {
				writeWinRM200StreamStart(conn)
				_ = conn.SetDeadline(time.Time{})

				ns, err := NewClientNetstack(func(pkt []byte) error {
					return common.WritePaddedFrame(conn, pkt)
				})
				if err != nil {
					log.Printf("Netstack init error: %v", err)
					return
				}
				defer ns.Close()

				log.Printf("[+] Client connected")
				scratch := make([]byte, 65536)
				for {
					ipPkt, err := common.ReadPaddedFrame(br, scratch)
					if err != nil {
						break
					}
					ns.InjectPacket(ipPkt)
				}
				log.Printf("[-] Client disconnected")
				return
			}
		}

		writeWinRM401Final(conn)
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
		"Date: %s\r\n"+
		"Content-Length: 0\r\n\r\n",
		common.ServerHeader, httpDate())
	_, _ = io.WriteString(w, resp)
}

func writeWinRM401Type2(w io.Writer, type2B64 string) {
	resp := fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\n"+
		"Server: %s\r\n"+
		"WWW-Authenticate: Negotiate %s\r\n"+
		"Date: %s\r\n"+
		"Content-Length: 0\r\n\r\n",
		common.ServerHeader, type2B64, httpDate())
	_, _ = io.WriteString(w, resp)
}

func writeWinRM401Final(w io.Writer) {
	resp := fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\n"+
		"Server: %s\r\n"+
		"WWW-Authenticate: Negotiate\r\n"+
		"Date: %s\r\n"+
		"Connection: close\r\n"+
		"Content-Length: 0\r\n\r\n",
		common.ServerHeader, httpDate())
	_, _ = io.WriteString(w, resp)
}

func writeWinRM200StreamStart(w io.Writer) {
	soap := common.FakeSoapCreateShellResponseXML
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
