cat << 'EOF' > /tmp/patch_b2.py
import re
from pathlib import Path

p = Path("android/app/src/main/java/com/example/winrmvpn/MainActivity.kt")
s = re.sub(r"v0\.\d+\.\d+", "v0.4.2", p.read_text(encoding="utf-8"))

if "pasteFromClipboard" not in s:
    s = s.replace("import android.app.AlertDialog", "import android.app.AlertDialog\nimport android.content.ClipboardManager", 1)
    old_in = '''        pskInput = EditText(this).apply {
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
    new_in = '''        val pskRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
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
    assert old_in in s, "inputs block not found"
    s = s.replace(old_in, new_in, 1)
    s = s.replace("layout.addView(pskInput)\n        layout.addView(pinInput)", "layout.addView(pskRow)\n        layout.addView(pinRow)", 1)
    helpers = '''    private fun createSmallPasteButton(onClick: () -> Unit): Button {
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
    s = s.replace("    override fun onDestroy()", helpers + "    override fun onDestroy()", 1)

p.write_text(s, encoding="utf-8")
print("[+] Patch B2 applied (Android paste buttons + v0.4.2)!")
EOF
python3 /tmp/patch_b2.py
git add -A
git commit -m "Release v0.4.2: chunked Send (40+ Mbps), 1ms batcher, 4MB gVisor buffers, Android paste buttons"
git push origin main