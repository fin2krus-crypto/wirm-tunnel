cat << 'EOF' > /tmp/patch_b.py
import re
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
\t\t\t\tselect {
\t\t\t\tcase errCh <- fmt.Errorf("send header: %w", err):
\t\t\t\tdefault:
\t\t\t\t}
\t\t\t\treturn
\t\t\t}
\t\t\t_ = sendRaw.SetWriteDeadline(time.Time{})

\t\t\trolloverTimer := time.NewTimer(time.Duration(55+mathrand.Intn(31)) * time.Second)
\t\t\tsentBytes := 0
\t\t\trolloverNow := false

\t\t\tfor !rolloverNow {
\t\t\t\tselect {
\t\t\t\tcase <-sessionDone:
\t\t\t\t\trolloverTimer.Stop()
\t\t\t\t\treturn
\t\t\t\tcase <-__STOP__:
\t\t\t\t\trolloverTimer.Stop()
\t\t\t\t\treturn
\t\t\t\tcase <-rolloverTimer.C:
\t\t\t\t\trolloverNow = true
\t\t\t\tcase <-kaReqCh:
\t\t\t\t\tframe := common.EncodeBatchFrame(nil, common.FrameKeepAlive)
\t\t\t\t\t_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
\t\t\t\t\tif err := common.WriteHTTPChunk(sendU, frame); err != nil {
\t\t\t\t\t\trolloverTimer.Stop()
\t\t\t\t\t\tselect {
\t\t\t\t\t\tcase errCh <- fmt.Errorf("send ka: %w", err):
\t\t\t\t\t\tdefault:
\t\t\t\t\t\t}
\t\t\t\t\t\treturn
\t\t\t\t\t}
\t\t\t\t\t_ = sendRaw.SetWriteDeadline(time.Time{})
\t\t\t\t\tsentBytes += len(frame)
\t\t\t\tcase firstPkt := <-tunRxCh:
\t\t\t\t\tpkts := make([][]byte, 1, 64)
\t\t\t\t\tpkts[0] = firstPkt
\t\t\t\t\tbatchBytes := len(firstPkt)
\t\t\t\t\tcTimer := time.NewTimer(1 * time.Millisecond)
\t\t\t\tdrain:
\t\t\t\t\tfor len(pkts) < 64 && batchBytes < 65536 {
\t\t\t\t\t\tselect {
\t\t\t\t\t\tcase p := <-tunRxCh:
\t\t\t\t\t\t\tpkts = append(pkts, p)
\t\t\t\t\t\t\tbatchBytes += len(p)
\t\t\t\t\t\tcase <-cTimer.C:
\t\t\t\t\t\t\tbreak drain
\t\t\t\t\t\t}
\t\t\t\t\t}
\t\t\t\t\tif !cTimer.Stop() {
\t\t\t\t\t\tselect {
\t\t\t\t\t\tcase <-cTimer.C:
\t\t\t\t\t\tdefault:
\t\t\t\t\t\t}
\t\t\t\t\t}
\t\t\t\t\tframe := common.EncodeBatchFrame(pkts, common.FrameData)
\t\t\t\t\t_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
\t\t\t\t\tif err := common.WriteHTTPChunk(sendU, frame); err != nil {
\t\t\t\t\t\trolloverTimer.Stop()
\t\t\t\t\t\tselect {
\t\t\t\t\t\tcase errCh <- fmt.Errorf("send chunk: %w", err):
\t\t\t\t\t\tdefault:
\t\t\t\t\t\t}
\t\t\t\t\t\treturn
\t\t\t\t\t}
\t\t\t\t\t_ = sendRaw.SetWriteDeadline(time.Time{})
\t\t\t\t\tsentBytes += len(frame)
\t\t\t\t}
\t\t\t\tif sentBytes >= maxSendChunkedBytes {
\t\t\t\t\trolloverTimer.Stop()
\t\t\t\t\trolloverNow = true
\t\t\t\t}
\t\t\t}

\t\t\t_ = sendRaw.SetWriteDeadline(time.Now().Add(10 * time.Second))
\t\t\tif _, err := io.WriteString(sendU, "0\\r\\n\\r\\n"); err != nil {
\t\t\t\tselect {
\t\t\t\tcase errCh <- fmt.Errorf("send eof: %w", err):
\t\t\t\tdefault:
\t\t\t\t}
\t\t\t\treturn
\t\t\t}
\t\t\t_ = sendRaw.SetWriteDeadline(time.Time{})
\t\t\t_ = sendRaw.SetReadDeadline(time.Now().Add(10 * time.Second))
\t\t\tresp, err := http.ReadResponse(sendBR, nil)
\t\t\tif err != nil {
\t\t\t\tselect {
\t\t\t\tcase errCh <- fmt.Errorf("send resp: %w", err):
\t\t\t\tdefault:
\t\t\t\t}
\t\t\t\treturn
\t\t\t}
\t\t\t_, _ = io.Copy(io.Discard, resp.Body)
\t\t\t_ = resp.Body.Close()
\t\t\t_ = sendRaw.SetReadDeadline(time.Time{})
\t\t\tif resp.StatusCode != 200 {
\t\t\t\tselect {
\t\t\t\tcase errCh <- fmt.Errorf("send status %d", resp.StatusCode):
\t\t\t\tdefault:
\t\t\t\t}
\t\t\t\treturn
\t\t\t}
\t\t}
\t}()

'''

def patch_client(path, start_anchor, end_anchor, stop_var):
    p = Path(path)
    s = p.read_text(encoding="utf-8").replace("make(chan []byte, 256)", "make(chan []byte, 1024)")
    i1 = s.index(start_anchor)
    i2 = s.index(end_anchor)
    s = s[:i1] + SEND_TMPL.replace("__STOP__", stop_var) + s[i2:]
    p.write_text(s, encoding="utf-8")

patch_client("mobile/mobile.go", "\t// Канал 2: Send", "\t// Пассивный + WinRM-размерный Watchdog", "localStop")
patch_client("cmd/mac-helper/main.go", "\tgo func() {\n\t\tsendBatchHTTP := func", "\tgo func() {\n\t\tfor {\n\t\t\twaitSec := 30", "stopCh")
patch_client("cmd/linux-helper/main.go", "\tgo func() {\n\t\tsendBatchHTTP := func", "\tgo func() {\n\t\tfor {\n\t\t\twaitSec := 30", "stopCh")

# Патч Android MainActivity.kt (версия 0.4.2 + кнопки "Вставить")
p_act = Path("android/app/src/main/java/com/example/winrmvpn/MainActivity.kt")
act = p_act.read_text(encoding="utf-8")
act = re.sub(r"v0\.\d+\.\d+", "v0.4.2", act)
if "pasteFromClipboard" not in act:
    act = act.replace("import android.app.AlertDialog", "import android.app.AlertDialog\nimport android.content.ClipboardManager", 1)
    old_inputs = '''        pskInput = EditText(this).apply {
            hint = "Pre-Shared Key (PSK)"
            setText(prefs.getString("psk", ""))
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#78909C"))
        }
        pinInput = EditText(this).apply {
            hint = "Cert SHA-256 Pin (64 hex, optional)"
            setText(prefs.getString("pin", ""))
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#78909C"))
        }'''
    new_inputs = '''        val pskRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        pskInput = EditText(this).apply {
            hint = "Pre-Shared Key (PSK)"
            setText(prefs.getString("psk", ""))
            setTextColor(Color.WHITE); setHintTextColor(Color.parseColor("#78909C"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        pskRow.addView(pskInput); pskRow.addView(createSmallPasteButton { pasteFromClipboard(pskInput) })

        val pinRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        pinInput = EditText(this).apply {
            hint = "Cert SHA-256 Pin (64 hex, optional)"
            setText(prefs.getString("pin", ""))
            setTextColor(Color.WHITE); setHintTextColor(Color.parseColor("#78909C"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        pinRow.addView(pinInput); pinRow.addView(createSmallPasteButton { pasteFromClipboard(pinInput) })'''
    assert old_inputs in act, "old_inputs not found in MainActivity.kt"
    act = act.replace(old_inputs, new_inputs, 1)
    act = act.replace("layout.addView(pskInput)\n        layout.addView(pinInput)", "layout.addView(pskRow)\n        layout.addView(pinRow)", 1)
    paste_helpers = '''    private fun createSmallPasteButton(onClick: () -> Unit): Button {
        return Button(this).apply {
            text = "Вставить"; textSize = 11f
            minWidth = 0; minHeight = 0; minimumWidth = 0; minimumHeight = 0
            setPadding(22, 14, 22, 14)
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { leftMargin = 10 }
            setOnClickListener { onClick() }
        }
    }

    private fun pasteFromClipboard(target: EditText) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip
        val text = if (cm.hasPrimaryClip() && clip != null && clip.itemCount > 0) clip.getItemAt(0)?.coerceToText(this)?.toString()?.trim() else null
        if (text.isNullOrEmpty()) { showValidationError("Буфер обмена пуст."); return }
        target.setText(text); target.setSelection(text.length); errorText.visibility = View.GONE
    }

'''
    act = act.replace("    override fun onDestroy()", 