package mobile

import (
	"bufio"
	"crypto/rand"
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
	"sync/atomic"
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
	mu               sync.Mutex
	running          bool
	stopChan         chan struct{}
	reconnectChan    chan struct{}
	activeRecvRaw    net.Conn
	activeSendRaw    net.Conn
	checkConnEnabled atomic.Bool
	lastRxNano       atomic.Int64
)

const maxConnectAttempts = 3

func SetCheckConnection(enabled bool) {
	checkConnEnabled.Store(enabled)
}

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
	rRaw := activeRecvRaw
	sRaw := activeSendRaw
	ch := reconnectChan
	mu.Unlock()

	if rRaw != nil {
		_ = rRaw.Close()
	}
	if sRaw != nil {
		_ = sRaw.Close()
	}

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

	var sessionID [16]byte
	_, _ = rand.Read(sessionID[:])

	go func() {
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

			wasConnected, rotated, err := runDualChannelSession(serverAddr, psk, expectedPin, sessionID, protector, cb, ensureTun, tunRxCh, localStop)
			if err != nil {
				emitLog(cb, "[ERR] Session ended: %v", err)
			}
			if wasConnected {
				attempt = 0
			}

			select {
			case <-localStop:
				emitState(cb, "DISCONNECTED")
				return
			default:
			}

			if rotated {
				emitLog(cb, "[SYS] Плановая ротация сокетов WinRM...")
				continue
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

			delayMs := 2000 + mathrand.Intn(4001)
			emitLog(cb, "[SYS] Повторная попытка через %.1f сек...", float64(delayMs)/1000.0)

			select {
			case <-localStop:
				emitState(cb, "DISCONNECTED")
				return
			case <-localReconn:
				attempt = 0
				_, _ = rand.Read(sessionID[:])
				emitLog(cb, "[SYS] Переключение сети — переподключение...")
			case <-time.After(time.Duration(delayMs) * time.Millisecond):
			}
		}
	}()

	return nil
}

func StopWinRMTunnel() {
	mu.Lock()
	if !running {
		mu.Unlock()
		return
	}
	running = false
	close(stopChan)
	rRaw := activeRecvRaw
	sRaw := activeSendRaw
	reconnectChan = nil
	mu.Unlock()

	if rRaw != nil {
		_ = rRaw.Close()
	}
	if sRaw != nil {
		_ = sRaw.Close()
	}
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

func dialWinRMChannel(
	serverAddr, psk, expectedPin string,
	sessionID [16]byte,
	role byte,
	protector SocketProtector,
	cb TunnelCallback,
	verbose bool,
) (net.Conn, *utls.UConn, *bufio.Reader, error) {
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
		return nil, nil, nil, errors.New("no server certificate")
	}
	h := sha256.Sum256(state.PeerCertificates[0].Raw)
	gotPin := hex.EncodeToString(h[:])
	if verbose {
		emitLog(cb, "[TLS] OK (%s), Cert CN=%s, Pin=%s...",
			tls.CipherSuiteName(state.CipherSuite), state.PeerCertificates[0].Subject.CommonName, gotPin[:12])
	}
	if expectedPin != "" && gotPin != expectedPin {
		gracefulTLSClose(uConn, rawConn)
		return nil, nil, nil, fmt.Errorf("Certificate Pin mismatch! Got %s...", gotPin[:12])
	}

	br := bufio.NewReader(uConn)
	soapBody := common.BuildSoapCreateShellXML(serverAddr)

	// Шаг 1/3: POST /wsman без Authorization
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

	// Шаг 2/3: NTLM Type 1
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

	// Шаг 3/3: NTLM Type 3 + SOAP
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
		return nil, nil, nil, fmt.Errorf("auth rejected (%d) — проверьте PSK или часы", resp2.StatusCode)
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
	protector SocketProtector,
	cb TunnelCallback,
	ensureTun func() (*os.File, error),
	tunRxCh <-chan []byte,
	localStop <-chan struct{},
) (wasConnected bool, rotated bool, err error) {
	emitLog(cb, "[HTTP] Открытие канала Receive...")
	recvRaw, recvU, recvBR, err := dialWinRMChannel(serverAddr, psk, expectedPin, sessionID, common.RoleRecv, protector, cb, true)
	if err != nil {
		return false, false, err
	}

	emitLog(cb, "[HTTP] Открытие канала Send...")
	sendRaw, sendU, sendBR, err := dialWinRMChannel(serverAddr, psk, expectedPin, sessionID, common.RoleSend, protector, cb, false)
	if err != nil {
		gracefulTLSClose(recvU, recvRaw)
		return false, false, err
	}

	mu.Lock()
	activeRecvRaw = recvRaw
	activeSendRaw = sendRaw
	mu.Unlock()

	tf, err := ensureTun()
	if err != nil {
		gracefulTLSClose(recvU, recvRaw)
		gracefulTLSClose(sendU, sendRaw)
		mu.Lock()
		activeRecvRaw, activeSendRaw = nil, nil
		mu.Unlock()
		return false, false, err
	}

	lastRxNano.Store(time.Now().UnixNano())
	emitLog(cb, "[VPN] 2-канальный WinRM туннель активен (Receive chunked + Send POST).")
	emitState(cb, "CONNECTED")

	sessionDone := make(chan struct{})
	errCh := make(chan error, 3)
	rotateCh := make(chan struct{}, 1)
	kaReqCh := make(chan struct{}, 4)
	kaAckCh := make(chan struct{}, 4)

	// Плановая ротация TCP+TLS сокетов раз в 10–15 минут (с чистым TLS close_notify)
	rotateTimer := time.NewTimer(time.Duration(10+mathrand.Intn(6)) * time.Minute)
	defer rotateTimer.Stop()

	// Канал 1: Receive (POST /wsman Receive -> 200 OK chunked)
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
				case errCh <- fmt.Errorf("recv write: %w", err):
				default:
				}
				return
			}
			_ = recvRaw.SetWriteDeadline(time.Time{})

			resp, err := http.ReadResponse(recvBR, nil)
			if err != nil {
				select {
				case errCh <- fmt.Errorf("recv header: %w", err):
				default:
				}
				return
			}
			if resp.StatusCode != 200 {
				_ = resp.Body.Close()
				select {
				case errCh <- fmt.Errorf("recv status %d", resp.StatusCode):
				default:
				}
				return
			}

			for {
				fType, pkts, err := common.DecodeBatchFrame(resp.Body)
				if err != nil {
					_ = resp.Body.Close()
					if errors.Is(err, io.EOF) {
						// Завершился 55-85с чанк ReceiveResponse -> открываем следующий Receive
						break
					}
					select {
					case errCh <- fmt.Errorf("recv chunk: %w", err):
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
			case <-localStop:
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
				case <-localStop:
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

	// Пассивный + WinRM-размерный Watchdog (без палевного ICMP ping)
	go func() {
		for {
			waitSec := 30 + mathrand.Intn(31)
			select {
			case <-sessionDone:
				return
			case <-localStop:
				return
			case <-time.After(time.Duration(waitSec) * time.Second):
			}

			if !checkConnEnabled.Load() {
				continue
			}

			lastRx := time.Unix(0, lastRxNano.Load())
			if time.Since(lastRx) < 30*time.Second {
				// Трафик активно идёт — ничего не шлём
				continue
			}

			// Дренируем старые ACK
			for len(kaAckCh) > 0 {
				<-kaAckCh
			}
			select {
			case kaReqCh <- struct{}{}:
			default:
			}

			gotReply := false
			select {
			case <-kaAckCh:
				gotReply = true
			case <-time.After(5 * time.Second):
			case <-sessionDone:
				return
			}
			if gotReply || time.Since(time.Unix(0, lastRxNano.Load())) < 10*time.Second {
				emitLog(cb, "[WATCHDOG] WinRM KeepAlive OK")
				continue
			}

			retrySec := 10 + mathrand.Intn(11)
			emitLog(cb, "[WATCHDOG] Нет ответа на KeepAlive. Повтор через %dс...", retrySec)
			select {
			case <-sessionDone:
				return
			case <-localStop:
				return
			case <-time.After(time.Duration(retrySec) * time.Second):
			}

			if !checkConnEnabled.Load() {
				continue
			}
			select {
			case kaReqCh <- struct{}{}:
			default:
			}

			gotReply = false
			select {
			case <-kaAckCh:
				gotReply = true
			case <-time.After(5 * time.Second):
			case <-sessionDone:
				return
			}
			if gotReply || time.Since(time.Unix(0, lastRxNano.Load())) < 10*time.Second {
				emitLog(cb, "[WATCHDOG] Повторный KeepAlive OK")
				continue
			}

			emitLog(cb, "[WATCHDOG] Повторный KeepAlive не прошёл! Перезапуск...")
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
	case <-localStop:
		emitLog(cb, "[VPN] Штатное отключение (TLS close_notify)...")
		close(sessionDone)
		gracefulTLSClose(recvU, recvRaw)
		gracefulTLSClose(sendU, sendRaw)
	case <-rotateTimer.C:
		isRotate = true
		close(sessionDone)
		gracefulTLSClose(recvU, recvRaw)
		gracefulTLSClose(sendU, sendRaw)
	case <-rotateCh:
		isRotate = true
		close(sessionDone)
		gracefulTLSClose(recvU, recvRaw)
		gracefulTLSClose(sendU, sendRaw)
	case retErr = <-errCh:
		close(sessionDone)
		_ = recvRaw.Close()
		_ = sendRaw.Close()
	}

	mu.Lock()
	activeRecvRaw = nil
	activeSendRaw = nil
	mu.Unlock()

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
