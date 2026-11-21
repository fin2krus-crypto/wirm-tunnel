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
	ServerTunIP = "10.88.0.1/24"
	WinRMHost   = "WIN-8K2M9P1Q4R0"
)

var (
	clientWriterMu sync.RWMutex
	activeClientW  io.Writer
)

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:5986", "WinRM HTTPS listen address")
	psk := flag.String("psk", "", "Pre-Shared Key for covert NTLM authentication (required)")
	certFile := flag.String("cert", "winrm_cert.pem", "Path to TLS cert")
	keyFile := flag.String("key", "winrm_key.pem", "Path to TLS key")
	noTun := flag.Bool("no-tun", false, "Run without TUN interface (for CI Test-WSMan verification)")
	flag.Parse()

	if *psk == "" {
		log.Fatal("ERROR: -psk flag is required")
	}

	tlsCert, fingerprint, err := loadOrGenerateWindowsCert(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Certificate error: %v", err)
	}
	log.Printf("================================================================")
	log.Printf("WinRM Stealth Server Ready on %s", *listenAddr)
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
					if len(ipPkt) >= 20 && (ipPkt[0]>>4) == 4 {
						_, _ = iface.Write(ipPkt)
					}
				}

				clientWriterMu.Lock()
				if activeClientW == conn {
					activeClientW = nil
				}
				clientWriterMu.Unlock()
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

func loadOrGenerateWindowsCert(certPath, keyPath string) (tls.Certificate, string, error) {
	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		h := sha256.Sum256(cert.Certificate[0])
		return cert, hex.EncodeToString(h[:]), nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	serialBytes := make([]byte, 16)
	_, _ = rand.Read(serialBytes)
	serialBytes[0] &= 0x7f

	now := time.Now().UTC()
	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes),
		Subject:      pkix.Name{CommonName: WinRMHost},
		NotBefore:    now.Add(-10 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{WinRMHost},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	_ = certOut.Close()

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	_ = keyOut.Close()

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	h := sha256.Sum256(derBytes)
	return cert, hex.EncodeToString(h[:]), nil
}
