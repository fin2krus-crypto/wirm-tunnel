cat << 'EOF' > /tmp/patch_a.py
import re
from pathlib import Path

def patch(path, old, new):
    p = Path(path)
    txt = p.read_text(encoding="utf-8")
    assert old in txt, f"Pattern not found in {path}: {old[:60]}"
    p.write_text(txt.replace(old, new, 1), encoding="utf-8")

# 1. tls-front: 64 KB buffer in copy_bidirectional_with_sizes
p_rs = Path("tls-front/src/main.rs")
txt_rs = p_rs.read_text(encoding="utf-8")
txt_rs = txt_rs.replace("use tokio::io::copy_bidirectional;", "use tokio::io::copy_bidirectional_with_sizes;")
txt_rs = txt_rs.replace(
    "copy_bidirectional(&mut tls_stream, &mut back_stream).await;",
    "copy_bidirectional_with_sizes(&mut tls_stream, &mut back_stream, 65536, 65536).await;"
)
p_rs.write_text(txt_rs, encoding="utf-8")

# 2. cmd/server/netstack.go: 2048 channel + 4MB gVisor TCP buffers
p_ns = Path("cmd/server/netstack.go")
txt_ns = p_ns.read_text(encoding="utf-8")
txt_ns = txt_ns.replace("linkEP := channel.New(512, 1380, \"\")", "linkEP := channel.New(2048, 1380, \"\")")
old_opt = "modBuf := tcpip.TCPModerateReceiveBufferOption(true)\n\t_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &modBuf)"
new_opt = old_opt + "\n\tsndBuf := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 524288, Max: 4194304}\n\t_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndBuf)\n\trcvBuf := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 524288, Max: 4194304}\n\t_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvBuf)"
assert old_opt in txt_ns, "netstack options not found"
txt_ns = txt_ns.replace(old_opt, new_opt, 1)
p_ns.write_text(txt_ns, encoding="utf-8")

# 3. cmd/server/main.go: txCh 1024, 1ms/64KB batcher, chunked Send channel
p_mn = Path("cmd/server/main.go")
txt_mn = p_mn.read_text(encoding="utf-8")
txt_mn = txt_mn.replace("txCh:         make(chan []byte, 256),", "txCh:         make(chan []byte, 1024),")
txt_mn = txt_mn.replace("time.NewTimer(3 * time.Millisecond)", "time.NewTimer(1 * time.Millisecond)")
txt_mn = txt_mn.replace("for len(pkts) < 24 && batchBytes < 32768 {", "for len(pkts) < 64 && batchBytes < 65536 {")
txt_mn = txt_mn.replace("pkts := make([][]byte, 1, 24)", "pkts := make([][]byte, 1, 64)")

old_send = '''		frameType, pkts, err := common.DecodeBatchFrame(req.Body)
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		if err != nil {
			writeHttpSys400(conn)
			return
		}

		if frameType == common.FrameKeepAlive {
			select {
			case sess.keepAliveCh <- struct{}{}:
			default:
			}
		} else {
			for _, pkt := range pkts {
				if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
					statsMgr.AddRx(matchedPSK_MISSING, len(pkt))
				}
			}
		}'''

# Безопасная замена тела handleSendChannel по сигнатуре функции
idx_start = txt_mn.index("func handleSendChannel(")
idx_end = txt_mn.index("func httpDate()")
new_send_fn = '''func handleSendChannel(conn net.Conn, br *bufio.Reader, sess *ClientSession, psk string, statsMgr *StatsManager) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(150 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})

		if !strings.EqualFold(req.URL.Path, "/wsman") || req.Method != http.MethodPost {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			writeHttpSys404(conn)
			return
		}

		for {
			_ = conn.SetReadDeadline(time.Now().Add(120 * time.Second))
			frameType, pkts, err := common.DecodeBatchFrame(req.Body)
			if err != nil {
				_ = conn.SetReadDeadline(time.Time{})
				if errors.Is(err, io.EOF) {
					break
				}
				_, _ = io.Copy(io.Discard, req.Body)
				_ = req.Body.Close()
				writeHttpSys400(conn)
				return
			}
			_ = conn.SetReadDeadline(time.Time{})

			if frameType == common.FrameKeepAlive {
				select {
				case sess.keepAliveCh <- struct{}{}:
				default:
				}
			} else {
				for _, pkt := range pkts {
					if len(pkt) >= 20 && (pkt[0]>>4) == 4 {
						statsMgr.AddRx(psk, len(pkt))
						sess.netstack.InjectPacket(pkt)
					}
				}
			}
			sess.Touch()
		}
		_ = req.Body.Close()

		soapResp := common.BuildSoapSendResponseXML(req.Host)
		resp := fmt.Sprintf("HTTP/1.1 200 OK\\r\\n"+
			"Content-Type: application/soap+xml;charset=UTF-8\\r\\n"+
			"Server: %s\\r\\n"+
			"Date: %s\\r\\n"+
			"Content-Length: %d\\r\\n\\r\\n%s",
			common.ServerHeader, httpDate(), len(soapResp), soapResp)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(conn, resp); err != nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Time{})
	}
}

'''
txt_mn = txt_mn[:idx_start] + new_send_fn + txt_mn[idx_end:]
p_mn.write_text(txt_mn, encoding="utf-8")

# 4. Массовое обновление версий 0.4.0 / 0.4.1 / 0.2.0 -> 0.4.2
targets = [
    "cmd/server/main.go", "cmd/server/web.go", "tls-front/Cargo.toml",
    "cmd/mac-helper/main.go", "cmd/linux-helper/main.go",
    "android/app/build.gradle", "android/app/src/main/java/com/example/winrmvpn/WinRmVpnService.kt",
    "macos/Info.plist", "macos/WinRMVPNApp.swift", "linux-gui/main.go",
    "install.sh", "README.md", ".github/workflows/build.yml",
]
for t in targets:
    p = Path(t)
    if not p.exists():
        continue
    s = p.read_text(encoding="utf-8")
    s = s.replace("0.4.1", "0.4.2").replace("0.4.0", "0.4.2").replace("0.2.0", "0.4.2")
    s = re.sub(r"versionCode \d+", "versionCode 42", s)
    s = s.replace("<string>41</string>", "<string>42</string>").replace("<string>20</string>", "<string>42</string>")
    p.write_text(s, encoding="utf-8")

print("[+] Patch A applied (server speed + OpenSSL3 64KB + v0.4.2 versions)!")
EOF
python3 /tmp/patch_a.py