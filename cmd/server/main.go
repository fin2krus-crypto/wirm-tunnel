package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/songgao/water"
	"winrm-vpn/common"
)

const (
	AppVersion  = "0.0.4"
	ServerTunIP = "10.88.0.1/24"
	WinRMHost   = "WIN-8K2M9P1Q4R0"
)

var (
	clientWriterMu sync.RWMutex
	activeClientW  io.Writer
)

func printQuickGuide() {
	fmt.Printf(`WinRM-VPN Server v%s (Windows Server 2022/2025 WinRM HTTPS Mimicry)

Короткая инструкция по настройке на Linux (x86_64):
  1. Откройте порт 5986/TCP в фаерволе:
       ufw allow 5986/tcp

  2. Примените настройки NAT и TCP-стека Windows (TTL=128, tcp_timestamps=0):
       chmod +x setup_linux_stealth.sh
       ./setup_linux_stealth.sh

  3. Сгенерируйте секретный ключ (PSK):
       openssl rand -hex 24

  4. Запустите сервер (от root):
       ./winrm-vpn-server -listen 0.0.0.0:5986 -psk "ВАШ_КЛЮЧ_PSK"

  5. Скопируйте выведенный при запуске Certificate SHA-256 Pin в Android-клиент.

Параметры запуска:
  -listen string   Адрес и порт прослушивания (по умолчанию "0.0.0.0:5986")
  -psk    string   Секретный ключ для скрытой NTLM-авторизации (обязательно)
  -cert   string   Путь к TLS-сертификату (по умолчанию "winrm_cert.pem")
  -key    string   Путь к приватному ключу (по умолчанию "winrm_key.pem")
  -no-tun          Запуск без создания TUN-интерфейса (только режим проверки WinRM)
`, AppVersion)
}

func main() {
	if len(os.Args) == 1 {
		printQuickGuide()
		os.Exit(0)
	}

	listenAddr := flag.String("listen", "0.0.0.0:5986", "WinRM HTTPS listen address")
	psk := flag.String("psk", "", "Pre-Shared Key for covert NTLM authentication (required)")
	certFile := flag.String("cert", "winrm_cert.pem", "Path to TLS cert")
	keyFile := flag.String("key", "winrm_key.pem", "Path to TLS key")
	noTun := flag.Bool("no-tun", false, "Run without TUN interface (for CI Test-WSMan verification)")
	flag.Parse()

	if *psk == "" {
		fmt.Println("Ошибка: не указан обязательный параметр -psk.")
		fmt.Println()
		printQuickGuide()
		os.Exit(1)
	}

	tlsCert, fingerprint, err := loadOrGenerateWindowsCert(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Certificate error: %v", err)
	}
	log.Printf("================================================================")
	log.Printf("WinRM-VPN Server v%s Ready on %s", AppVersion, *listenAddr)
	log.Printf("Certificate SHA-256 Pin (copy to Android App):")
	log.Printf("%s", fingerprint)
	log.Printf("================================================================")

	var iface *water.Interface
	if !*noTun {
		iface, err = setupTunInterface()
		if err != nil {
			log.Fatalf("Failed to setup TUN: %v (run as root)", err)
		}
		go tunToClientLoop(iface)
	}

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

	ln, err := tls.Listen("tcp4", *listenAddr, tlsConfig)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleWinRMConnection(conn, *psk, iface)
	}
}

func setupTunInterface() (*water.Interface, error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.Name = "winrm0"
	iface, err := water.New(cfg)
	if err != nil {
		return nil, err
	}
	cmds := [][]string{
		{"ip", "addr", "replace", ServerTunIP, "dev", iface.Name()},
		{"ip", "link", "set", "dev", iface.Name(), "mtu", "1380", "up"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("%v: %s", err, string(out))
		}
	}
	return iface, nil
}

func tunToClientLoop(iface *water.Interface) {
	pkt := make([]byte, 2048)
	for {
		n, err := iface.Read(pkt)
		if err != nil {
			continue
		}
		if n < 20 || (pkt[0]>>4) != 4 {
			continue
		}
		clientWriterMu.RLock()
		w := activeClientW
		clientWriterMu.RUnlock()
		if w != nil {
			_ = common.WritePaddedFrame(w, pkt[:n])
		}
	}
}

func handleWinRMConnection(conn net.Conn, psk string, iface *water.Interface) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))

	br := bufio.NewReader(conn)
	var currentChallenge [8]byte
	hasChallenge := false

	for {
		req, err := http.ReadRequest(br)
		if err != nil {
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
			type2B64, currentChallenge = common.BuildNTLMType2(WinRMHost)
			hasChallenge = true
			writeWinRM401Type2(conn, type2B64)
			continue
		}

		if hasChallenge && strings.HasPrefix(b64Token, "TlRMTVNTUAAD") {
			if common.VerifyNTLMType3Auth(b64Token, psk, currentChallenge) {
				writeWinRM200StreamStart(conn)
				_ = conn.SetDeadline(time.Time{})

				if iface == nil {
					return
				}

				clientWriterMu.Lock()
				activeClientW = conn
				clientWriterMu.Unlock()

				scratch := make([]byte, 65536)
				for {
					ipPkt, err := common.ReadPaddedFrame(br, scratch)
					if err != nil {
						break
					}
					if len(ipPkt) >= 20 && (ipPkt[0]>>4) ==
