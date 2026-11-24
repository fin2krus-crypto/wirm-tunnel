package mobile

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
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

type TunnelCallback interface {
	OnLog(msg string)
	OnStateChanged(state string)
	OpenTun() int
}

var (
	mu            sync.Mutex
	running       bool
	stopChan      chan struct{}
	reconnectChan chan struct{}
	activeConn    net.Conn
)

const maxConnectAttempts = 3

func emitLog(cb TunnelCallback, format string, args ...any) {
	if cb != nil {
		cb.OnLog(fmt.Sprintf(format, args...))
	}
}

func emitState(cb TunnelCallback, state string) {
	if cb != nil {
		cb.OnStateChanged(state)
	}
}

func TriggerReconnect() {
	mu.Lock()
	if activeConn != nil {
		_ = activeConn.Close()
	}
	ch := reconnectChan
	mu.Unlock()

	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func StartWinRMTunnel(serverAddr string, psk string, expectedCertSha256 string, protector SocketProtector, cb TunnelCallback) error {
	mu.Lock()
	if running {
		mu.Unlock()
		return errors.New("tunnel already running")
	}
	running = true
	stopChan = make(chan struct{})
	reconnectChan = make(chan struct{}, 1)
	localStop := stopChan
	localReconn := reconnectChan
	mu.Unlock()

	expectedPin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(expectedCertSha256), ":", ""))

	go func() {
		var tunFile *os.File
		tunRxCh := make(chan []byte, 128)

		defer func() {
			if tunFile != nil {
				_ = tunFile.Close()
			}
		}()

		// Поднимает TUN-интерфейс на стороне Android только после успешного подключения к серверу
		ensureTun := func() (*os.File, error) {
			if tunFile != nil {
				return tunFile, nil
			}
			if cb == nil {
				return nil, errors.New("TunnelCallback is nil")
			}
			fd := cb.OpenTun()
			if fd < 0 {
				return nil, errors.New("не удалось поднять TUN интерфейс Android")
			}
			dupFd, err := syscall.Dup(fd)
			if err != nil {
				return nil, fmt.Errorf("syscall.Dup(tunFd) failed: %w", err)
			}
			_ = syscall.SetNonblock(dupFd, true)
			tunFile = os.NewFile(uintptr(dupFd), "tun")

			// Единственная горутина чтения TUN на всё время жизни сервиса
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
			case <-localStop:
				emitState(cb, "DISCONNECTED")
				return
			default:
			}

			attempt++
			emitLog(cb, "[SYS] Попытка подключения %d/%d...", attempt, maxConnectAttempts)
			emitState(cb, "CONNECTING")

			wasConnected, err := runSingleSession(serverAddr, psk, expectedPin, protector, cb, ensureTun, tunRxCh, localStop)
			if err != nil {
				emitLog(cb, "[ERR] Session ended: %v", err)
			}
			if wasConnected {
				// Если сессия была активна и оборвалась позже — сбрасываем счётчик попыток
				attempt = 0
			}

			select {
			case <-localStop:
				emitState(cb, "DISCONNECTED")
				return
			default:
			}

			if attempt >= maxConnectAttempts {
				emitLog(cb, "[ERR] Исчерпан лимит попыток подключения (%d/%d). Остановка VPN...", attempt, maxConnectAttempts)
				mu.Lock()
				if running {
					running = false
					close(stopChan)
					reconnectChan = nil
				}
				mu.Unlock()
				emitState(cb, "ERROR")
				return
			}

			// Случайная задержка от 2.0 до 6.0 секунд перед следующей попыткой
			delayMs := 2000 + mathrand.Intn(4001)
			emitLog(cb, "[SYS] Повторная попытка через %.1f сек...", float64(delayMs)/1000.0)

			select {
			case <-localStop:
				emitState(cb, "DISCONNECTED")
				return
			case <-localReconn:
				attempt = 0
				emitLog(cb, "[SYS] Переключение сети — немедленный сброс счётчика и переподключение...")
			case <-time.After(time.Duration(delayMs) * time.Millisecond):
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
	reconnectChan = nil
}

func runSingleSession(
	serverAddr, psk, expectedPin string,
	protector SocketProtector,
	cb TunnelCallback,
	ensureTun func() (*os.File, error),
	tunRxCh <-chan []byte,
	localStop <-chan struct{},
) (bool, error) {
	emitLog(cb, "[TCP] Dialing %s (IPv4)...", serverAddr)

	dialer := &net.Dialer{
		Timeout: 4 * time.Second,
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
		return false, fmt.Errorf("TCP connect failed: %w", err)
	}

	mu.Lock()
	activeConn = rawConn
	mu.Unlock()

	defer func() {
		mu.Lock()
		if activeConn == rawConn {
			activeConn = nil
		}
		mu.Unlock()
		_ = rawConn.Close()
	}()

	// Ограничение 5 сек на TLS + 3-шаговый NTLM хендшейк
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	emitLog(cb, "[TCP] Connected to %s", rawConn.RemoteAddr().String())
	emitLog(cb, "[TLS] Starting Handshake (Profile: Ansible / Linux OpenSSL 3.x, no SNI)...")

	uCfg := &utls.Config{
		InsecureSkipVerify: true,
	}
	uConn := utls.UClient(rawConn, uCfg, utls.HelloCustom)

	if err := uConn.ApplyPreset(buildAnsibleLinuxOpenSSL3Spec()); err != nil {
		return false, fmt.Errorf("uTLS preset error: %w", err)
	}
	if err := uConn.Handshake(); err != nil {
		return false, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := uConn.ConnectionState()
	emitLog(cb, "[TLS] Handshake OK (Version: 0x%x, Cipher: %s)", state.Version, tls.CipherSuiteName(state.CipherSuite))

	if len(state.PeerCertificates) == 0 {
		return false, errors.New("server provided no certificate")
	}
	h := sha256.Sum256(state.PeerCertificates[0].Raw)
	gotPin := hex.EncodeToString(h[:])
	emitLog(cb, "[TLS] Server Cert CN=%s, SHA-256=%s...", state.PeerCertificates[0].Subject.CommonName, gotPin[:16])

	if expectedPin != "" {
		if gotPin != expectedPin {
			return false, fmt.Errorf("Certificate Pin mismatch! Expected %s..., got %s...", expectedPin[:12], gotPin[:12])
		}
		emitLog(cb, "[TLS] Certificate Pin verified OK")
	} else {
		emitLog(cb, "[TLS] Pinning skipped (empty pin field)")
	}

	br := bufio.NewReader(uConn)

	soapBody := common.BuildSoapCreateShellXML(serverAddr)

	// Шаг 1/3: POST /wsman без заголовка Authorization
	emitLog(cb, "[HTTP 1/3] -> POST %s (no auth, SOAP %dB)", common.WinRMPath, len(soapBody))
	req0 := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: %s\r\n"+
		"Accept-Encoding: gzip, deflate\r\n"+
		"Accept: */*\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, len(soapBody), soapBody)

	if _, err := io.WriteString(uConn, req0); err != nil {
		return false, fmt.Errorf("HTTP step 1/3 write failed: %w", err)
	}

	resp0, err := http.ReadResponse(br, nil)
	if err != nil {
		return false, fmt.Errorf("HTTP step 1/3 read failed: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp0.Body)
	_ = resp0.Body.Close()

	emitLog(cb, "[HTTP 1/3] <- %s (Server: %s)", resp0.Status, resp0.Header.Get("Server"))
	if resp0.StatusCode != 401 {
		return false, fmt.Errorf("expected 401 on step 1/3, got %d", resp0.StatusCode)
	}

	// Шаг 2/3: POST /wsman с Authorization: NTLM <Type 1>
	emitLog(cb, "[HTTP 2/3] -> POST %s (Authorization: NTLM Type 1)", common.WinRMPath)
	t1 := common.BuildNTLMType1()
	req1 := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: %s\r\n"+
		"Accept-Encoding: gzip, deflate\r\n"+
		"Accept: */*\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
		"Authorization: NTLM %s\r\n"+
		"Content-Length: 0\r\n\r\n",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, t1)

	if _, err := io.WriteString(uConn, req1); err != nil {
		return false, fmt.Errorf("HTTP step 2/3 write failed: %w", err)
	}

	resp1, err := http.ReadResponse(br, nil)
	if err != nil {
		return false, fmt.Errorf("HTTP step 2/3 read failed: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()

	emitLog(cb, "[HTTP 2/3] <- %s", resp1.Status)
	if resp1.StatusCode != 401 {
		return false, fmt.Errorf("expected 401 Unauthorized on step 2/3, got %d", resp1.StatusCode)
	}

	var serverChallenge [8]byte
	foundChallenge := false
	for _, hdr := range resp1.Header.Values("WWW-Authenticate") {
		var b64 string
		if strings.HasPrefix(hdr, "NTLM ") {
			b64 = strings.TrimSpace(strings.TrimPrefix(hdr, "NTLM "))
		} else if strings.HasPrefix(hdr, "Negotiate ") {
			b64 = strings.TrimSpace(strings.TrimPrefix(hdr, "Negotiate "))
		}
		if b64 != "" {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err == nil && len(raw) >= 32 {
				copy(serverChallenge[:], raw[24:32])
				foundChallenge = true
			}
		}
	}
	if !foundChallenge {
		return false, errors.New("server did not return NTLM Type 2 Challenge")
	}
	emitLog(cb, "[NTLM] Received Type 2 Challenge: %s", hex.EncodeToString(serverChallenge[:]))

	// Шаг 3/3: POST /wsman с Authorization: NTLM <Type 3 + HMAC> и телом SOAP Create Shell
	emitLog(cb, "[HTTP 3/3] -> POST %s (Authorization: NTLM Type 3 + SOAP)", common.WinRMPath)
	t3 := common.BuildNTLMType3WithAuth(psk, serverChallenge)
	req2 := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: %s\r\n"+
		"Accept-Encoding: gzip, deflate\r\n"+
		"Accept: */*\r\n"+
		"Connection: keep-alive\r\n"+
		"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
		"Authorization: NTLM %s\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		common.WinRMPath, serverAddr, common.WinRMUserAgent, t3, len(soapBody), soapBody)

	if _, err := io.WriteString(uConn, req2); err != nil {
		return false, fmt.Errorf("HTTP step 3/3 write failed: %w", err)
	}

	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		return false, fmt.Errorf("HTTP step 3/3 read failed: %w", err)
	}
	emitLog(cb, "[HTTP 3/3] <- %s (SOAP %dB)", resp2.Status, resp2.ContentLength)
	if resp2.StatusCode != 200 {
		return false, fmt.Errorf("auth rejected (%d) — проверьте PSK или системное время!", resp2.StatusCode)
	}
	if resp2.ContentLength > 0 {
		_, _ = io.CopyN(io.Discard, resp2.Body, resp2.ContentLength)
	}

	_ = rawConn.SetDeadline(time.Time{})

	// Соединение с сервером успешно установлено — только теперь поднимаем Android TUN!
	tf, err := ensureTun()
	if err != nil {
		return false, err
	}

	emitLog(cb, "[VPN] Tunnel ESTABLISHED! Routing IPv4 via WinRM stream.")
	emitState(cb, "CONNECTED")

	sessionDone := make(chan struct{})
	defer close(sessionDone)

	errCh := make(chan error, 2)

	// TUN -> Сервер
	go func() {
		for {
			select {
			case <-sessionDone:
				return
			case <-localStop:
				return
			case pkt := <-tunRxCh:
				if err := common.WritePaddedFrame(uConn, pkt); err != nil {
					select {
					case errCh <- fmt.Errorf("tunnel write error: %w", err):
					default:
					}
					return
				}
			}
		}
	}()

	// Сервер -> TUN
	go func() {
		scratch := make([]byte, 65536)
		for {
			pkt, err := common.ReadPaddedFrame(br, scratch)
			if err != nil {
				select {
				case errCh <- fmt.Errorf("tunnel read error: %w", err):
				default:
				}
				return
			}
			if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
				if _, err := tf.Write(pkt); err != nil {
					select {
					case errCh <- fmt.Errorf("TUN write error: %w", err):
					default:
					}
					return
				}
			}
		}
	}()

	select {
	case <-localStop:
		emitLog(cb, "[VPN] Stopped by user.")
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
