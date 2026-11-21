package mobile

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"winrm-vpn/common"
)

type SocketProtector interface {
	Protect(fd int) bool
}

var (
	mu         sync.Mutex
	running    bool
	stopChan   chan struct{}
	activeConn net.Conn
)

func StartWinRMTunnel(tunFd int, serverAddr string, psk string, expectedCertSha256 string, protector SocketProtector) error {
	mu.Lock()
	if running {
		mu.Unlock()
		return errors.New("tunnel already running")
	}
	running = true
	stopChan = make(chan struct{})
	mu.Unlock()

	expectedPin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(expectedCertSha256), ":", ""))

	go func() {
		dupFd, err := syscall.Dup(tunFd)
		if err != nil {
			return
		}
		tunFile := os.NewFile(uintptr(dupFd), "tun")
		defer tunFile.Close()

		for {
			select {
			case <-stopChan:
				return
			default:
			}

			_ = runSingleSession(tunFile, serverAddr, psk, expectedPin, protector)

			select {
			case <-stopChan:
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	return nil
}

func StopWinRMTunnel() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
	running = false
	close(stopChan)
	if activeConn != nil {
		_ = activeConn.Close()
	}
}

func runSingleSession(tunFile *os.File, serverAddr, psk, expectedPin string, protector SocketProtector) error {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var protectErr error
			_ = c.Control(func(fd uintptr) {
				if protector != nil && !protector.Protect(int(fd)) {
					protectErr = errors.New("VpnService.protect(fd) failed")
				}
			})
			return protectErr
		},
	}

	rawConn, err := dialer.Dial("tcp4", serverAddr)
	if err != nil {
		return err
	}
	defer rawConn.Close()

	uCfg := &utls.Config{
		InsecureSkipVerify: true,
	}
	uConn := utls.UClient(rawConn, uCfg, utls.HelloCustom)
	if err := uConn.ApplyPreset(buildAnsibleLinuxOpenSSL3Spec()); err != nil {
		return err
	}
	if err := uConn.Handshake(); err != nil {
		return err
	}

	state := uConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("no server certificate")
	}
	h := sha256.Sum256(state.PeerCertificates[0].Raw)
	gotPin := hex.EncodeToString(h[:])
	if expectedPin != "" && gotPin != expectedPin {
		return fmt.Errorf("cert pin mismatch: got %s", gotPin)
	}

	br := bufio.NewReader(uConn)

	// Шаг 1: Запрос Ansible pywinrm (python-requests + requests-ntlm) с NTLM Type 1
	t1 := common.BuildNTLMType1()
	req1 := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: %s\r\n"+
		"Accept-Encoding: gzip, deflate\r\n"+
		"Accept: */*\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
		"Authorization: Negotiate %s\r\n"+
		"Content-Length: 0\r\n\r\n",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, t1)

	if _, err := io.WriteString(uConn, req1); err != nil {
		return err
	}

	resp1, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()

	if resp1.StatusCode != 401 {
		return fmt.Errorf("expected 401 on step 1, got %d", resp1.StatusCode)
	}

	var serverChallenge [8]byte
	for _, hdr := range resp1.Header.Values("WWW-Authenticate") {
		if strings.HasPrefix(hdr, "Negotiate ") {
			b64 := strings.TrimSpace(strings.TrimPrefix(hdr, "Negotiate "))
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err == nil && len(raw) >= 32 {
				copy(serverChallenge[:], raw[24:32])
			}
		}
	}

	// Шаг 2: Запрос Ansible pywinrm с NTLM Type 3 (скрытый HMAC) и телом SOAP Create Shell
	t3 := common.BuildNTLMType3WithAuth(psk, serverChallenge)
	soapBody := common.FakeSoapCreateShellXML
	req2 := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: %s\r\n"+
		"Accept-Encoding: gzip, deflate\r\n"+
		"Accept: */*\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
		"Authorization: Negotiate %s\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, t3, len(soapBody), soapBody)

	if _, err := io.WriteString(uConn, req2); err != nil {
		return err
	}

	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	if resp2.StatusCode != 200 {
		return fmt.Errorf("auth rejected with status %d", resp2.StatusCode)
	}
	if resp2.ContentLength > 0 {
		_, _ = io.CopyN(io.Discard, resp2.Body, resp2.ContentLength)
	}

	mu.Lock()
	activeConn = uConn
	mu.Unlock()

	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := tunFile.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if n >= 20 && (buf[0]>>4) == 4 {
				if err := common.WritePaddedFrame(uConn, buf[:n]); err != nil {
					errCh <- err
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
				errCh <- err
				return
			}
			if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
				if _, err := tunFile.Write(pkt); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	select {
	case <-stopChan:
		return nil
	case err := <-errCh:
		return err
	}
}

// buildAnsibleLinuxOpenSSL3Spec формирует TLS ClientHello от Linux OpenSSL 3.x (Ubuntu/Debian Python requests/pywinrm):
// - 100% консистентность с Linux TCP-стеком Android (TTL=64, Timestamps=1) -> отсутствие Cross-Layer Mismatch
// - Без SNI (подключение по IPv4-адресу)
// - Без GREASE
// - Без ALPN h2 (urllib3 в pywinrm использует только HTTP/1.1)
func buildAnsibleLinuxOpenSSL3Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			0x1302, // TLS_AES_256_GCM_SHA384
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			0x1301, // TLS_AES_128_GCM_SHA256
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
			0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
			0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
			0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
			0xc027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
			0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
			0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
			0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
			0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
			0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
			0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []utls.TLSExtension{
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00, 0x01, 0x02}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP521,
				utls.CurveP384,
			}},
			&utls.SessionTicketExtension{},
			&utls.GenericExtension{Id: 22}, // encrypt_then_mac (RFC 7366)
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
		},
	}
}
