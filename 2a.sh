cat << 'EOF' > /tmp/patch_b1.py
from pathlib import Path

SEND_TMPL = '''\t// Канал 2: Send (Transfer-Encoding: chunked POST /wsman, ротация 55-85с / 20МБ + 1мс батчер)
\tgo func() {
\t\tconst maxSendChunkedBytes = 20 * 1024 * 1024
\t\tfor {
\t\t\tselect {
\t\t\tcase <-sessionDone:
\t\t\t\treturn
\t\t\tcase <-__STOP__:
\t\t\t\treturn
\t\t\tdefault:
\t\t\t}
\t\t\thdr := fmt.Sprintf("POST %s HTTP/1.1\\r\\nHost: %s\\r\\nUser-Agent: %s\\r\\nAccept-Encoding: gzip, deflate\\r\\nAccept: */*\\r\\nConnection: keep-alive\\r\\nContent-Type: application/soap+xml;charset=UTF-8\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n",
\t\t\t\tcommon.WinRMPath, serverAddr, common.WinRMUserAgent)
\t\t\t_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
\t\t\tif _, err := io.WriteString(sendU, hdr); err != nil {
\t\t\t\tselect { case errCh <- err: default: }
\t\t\t\treturn
\t\t\t}
\t\t\t_ = sendRaw.SetWriteDeadline(time.Time{})
\t\t\trolloverTimer := time.NewTimer(time.Duration(55+mathrand.Intn(31)) * time.Second)
\t\t\tsentBytes, rolloverNow := 0, false
\t\t\tfor !rolloverNow {
\t\t\t\tselect {
\t\t\t\tcase <-sessionDone:
\t\t\t\t\trolloverTimer.Stop(); return
\t\t\t\tcase <-__STOP__:
\t\t\t\t\trolloverTimer.Stop(); return
\t\t\t\tcase <-rolloverTimer.C:
\t\t\t\t\trolloverNow = true
\t\t\t\tcase <-kaReqCh:
\t\t\t\t\tframe := common.EncodeBatchFrame(nil, common.FrameKeepAlive)
\t\t\t\t\t_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
\t\t\t\t\tif err := common.WriteHTTPChunk(sendU, frame); err != nil {
\t\t\t\t\t\trolloverTimer.Stop(); select { case errCh <- err: default: }; return
\t\t\t\t\t}
\t\t\t\t\t_ = sendRaw.SetWriteDeadline(time.Time{}); sentBytes += len(frame)
\t\t\t\tcase firstPkt := <-tunRxCh:
\t\t\t\t\tpkts := make([][]byte, 1, 64); pkts[0] = firstPkt; batchBytes := len(firstPkt)
\t\t\t\t\tcTimer := time.NewTimer(1 * time.Millisecond)
\t\t\t\tdrain:
\t\t\t\t\tfor len(pkts) < 64 && batchBytes < 65536 {
\t\t\t\t\t\tselect {
\t\t\t\t\t\tcase p := <-tunRxCh: pkts = append(pkts, p); batchBytes += len(p)
\t\t\t\t\t\tcase <-cTimer.C: break drain
\t\t\t\t\t\t}
\t\t\t\t\t}
\t\t\t\t\tif !cTimer.Stop() { select { case <-cTimer.C: default: } }
\t\t\t\t\tframe := common.EncodeBatchFrame(pkts, common.FrameData)
\t\t\t\t\t_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
\t\t\t\t\tif err := common.WriteHTTPChunk(sendU, frame); err != nil {
\t\t\t\t\t\trolloverTimer.Stop(); select { case errCh <- err: default: }; return
\t\t\t\t\t}
\t\t\t\t\t_ = sendRaw.SetWriteDeadline(time.Time{}); sentBytes += len(frame)
\t\t\t\t}
\t\t\t\tif sentBytes >= maxSendChunkedBytes { rolloverTimer.Stop(); rolloverNow = true }
\t\t\t}
\t\t\t_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
\t\t\tif _, err := io.WriteString(sendU, "0\\r\\n\\r\\n"); err != nil { select { case errCh <- err: default: }; return }
\t\t\t_ = sendRaw.SetWriteDeadline(time.Time{}); _ = sendRaw.SetReadDeadline(time.Now().Add(10 * time.Second))
\t\t\tresp, err := http.ReadResponse(sendBR, nil)
\t\t\tif err != nil { select { case errCh <- err: default: }; return }
\t\t\t_, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close(); _ = sendRaw.SetReadDeadline(time.Time{})
\t\t\tif resp.StatusCode != 200 { select { case errCh <- fmt.Errorf("send %d", resp.StatusCode): default: }; return }
\t\t}
\t}()

'''

def patch_client(path, start_anchor, end_anchor, stop_var):
    p = Path(path)
    s = p.read_text(encoding="utf-8").replace("make(chan []byte, 256)", "make(chan []byte, 1024)")
    i1, i2 = s.index(start_anchor), s.index(end_anchor)
    p.write_text(s[:i1] + SEND_TMPL.replace("__STOP__", stop_var) + s[i2:], encoding="utf-8")

patch_client("mobile/mobile.go", "\t// Канал 2: Send", "\t// Пассивный + WinRM-размерный Watchdog", "localStop")
patch_client("cmd/mac-helper/main.go", "\tgo func() {\n\t\tsendBatchHTTP := func", "\tgo func() {\n\t\tfor {\n\t\t\twaitSec := 30", "stopCh")
patch_client("cmd/linux-helper/main.go", "\tgo func() {\n\t\tsendBatchHTTP := func", "\tgo func() {\n\t\tfor {\n\t\t\twaitSec := 30", "stopCh")
print("[+] Patch B1 applied!")
EOF
python3 /tmp/patch_b1.py