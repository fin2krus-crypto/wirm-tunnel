package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"strings"
	"syscall"
	"time"

	"winrm-vpn/common"
)

const AppVersion = "0.0.4"

func printQuickGuide() {
	fmt.Printf(`WinRM-VPN Server v%s (Userspace Netstack — БЕЗ TUN и БЕЗ root!)

Короткая инструкция по запуску на Linux (x86_64):
  1. Откройте порт 5986/TCP в фаерволе:
       ufw allow 5986/tcp

  2. Сгенерируйте секретный ключ (PSK):
       openssl rand -hex 24

  3. Запустите сервер (root и iptables НЕ требуются):
       ./winrm-vpn-server -listen 0.0.0.0:5986 -psk "ВАШ_КЛЮЧ_PSK"

     (Для нескольких пользователей можно указать ключи через запятую: -psk "key1,key2")

  4. Скопируйте выведенный Certificate SHA-256 Pin в Android-клиент.

Опционально (если есть root, для полного TCP-отпечатка Windows Server):
  sysctl -w net.ipv4.tcp_timestamps=0

Параметры запуска:
  -listen string   Адрес и порт прослушивания (по умолчанию "0.0.0.0:5986")
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

listenAddr := flag.String("listen", "0.0.0.0:5986", "WinRM listen address")
	pskFlag := flag.String("psk", "", "Pre-Shared Key(s), comma-separated (required)")
	certFile := flag.String("cert", "winrm_cert.pem", "Path to TLS cert")
	keyFile := flag.String("key", "winrm_key.pem", "Path to TLS key")
	plainMode := flag.Bool("plain", false, "Listen plain TCP (use behind winrm-tls-rustls)")
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

	tlsCert, fingerprint, hostName, err := loadOrGenerateWindowsCert(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Certificate error: %v", err)
	}
	log.Printf("================================================================")
	log.Printf("WinRM-VPN Server v%s (No-TUN, Plain=%v) Ready on %s", AppVersion, *plainMode, *listenAddr)
	log.Printf("Emulated Windows Hostname: %s", hostName)
	log.Printf("Loaded PSK keys: %d", len(pskList))
	log.Printf("Certificate SHA-256 Pin (copy to Android App):")
	log.Printf("%s", fingerprint)
	log.Printf("================================================================")

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 128)
			})
			return nil
		},
	}

	rawLn, err := lc.Listen(context.Background(), "tcp4", *listenAddr)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}

	var ln net.Listener = rawLn
	if !*plainMode {
		tlsConfig := &tls.Config{
			Certificates:             []tls.Certificate{tlsCert},
			MinVersion:               tls.VersionTLS12,
			MaxVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			NextProtos:               nil,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		}
		ln = tls.NewListener(rawLn, tlsConfig)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleWinRMConnection(conn, pskList, hostName)
	}
	
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
			// На битые HTTP-пробы отвечаем эталонным 400 Bad Request от http.sys
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
					log.Printf("Netstack init error for %s: %v", conn.RemoteAddr(), err)
					return
				}
				defer ns.Close()

				log.Printf("[+] Client connected: %s", conn.RemoteAddr())
				scratch := make([]byte, 65536)
				for {
					ipPkt, err := common.ReadPaddedFrame(br, scratch)
					if err != nil {
						break
					}
					ns.InjectPacket(ipPkt)
				}
				log.Printf("[-] Client disconnected: %s", conn.RemoteAddr())
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

// Генерирует случайное 15-символьное имя хоста в формате Windows Server: WIN-XXXXXXXXXXX
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
