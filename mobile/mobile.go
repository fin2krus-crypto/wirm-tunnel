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
	if err := uConn.ApplyPreset(buildWindowsSchannelSpec()); err != nil {
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

	t1 := common.BuildNTLMType1()
	req1 := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Connection: Keep-Alive\r\n"+
		"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
		"User-Agent: %s\r\n"+
		"Authorization: Negotiate %s\r\n"+
		"Content-Length: 0\r\n"+
		"Host: %s\r\n\r\n",
		common.WinRMPath, common.WinRMUserAgent, t1, serverAddr)

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

	t3 := common.BuildNTLMType3WithAuth(psk, serverChallenge)
	soapBody := common.FakeSoapCreateShellXML
	req2 := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Connection: Keep-Alive\r\n"+
		"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
		"User-Agent: %s\r\n"+
		"Authorization: Negotiate %s\r\n"+
		"Content-Length: %d\r\n"+
		"Host: %s\r\n\r\n%s",
		common.WinRMPath, common.WinRMUserAgent, t3, len(soapBody), serverAddr, soapBody)

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

// Профиль Windows Server 2022/2025 Schannel при обращении по IP (без SNI, без GREASE, без ChaCha20, без ALPN h2)
func buildWindowsSchannelSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			0x1302, // TLS_AES_256_GCM_SHA384
			0x1301, // TLS_AES_128_GCM_SHA256
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
			0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
			0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
			0xc027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
			0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
			0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
			0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
			0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
			0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []utls.TLSExtension{
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
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
			&utls.StatusRequestExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
		},
	}
}
