package com.example.winrmvpn

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.widget.Button
import android.graphics.Canvas
import android.graphics.ColorFilter
import android.graphics.Paint
import android.graphics.PixelFormat
import android.graphics.drawable.Drawable
import android.widget.ImageButton
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import mobile.Mobile
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : Activity() {

    private lateinit var serverInput: EditText
    private lateinit var pskInput: EditText
    private lateinit var pinInput: EditText
    private lateinit var checkConnSwitch: Switch

    private lateinit var errorText: TextView
    private lateinit var statusText: TextView
    private lateinit var btnPingTest: Button
    private lateinit var btnCheckIp: Button
    private lateinit var pingResultText: TextView
    private lateinit var ipResultText: TextView
    private lateinit var logText: TextView
    private lateinit var logScroll: ScrollView

    @Volatile private var autoScrollEnabled: Boolean = true

    private val logListener: (String) -> Unit = { line ->
        runOnUiThread {
            if (logText.text.isNotEmpty()) {
                logText.append("\n$line")
            } else {
                logText.text = line
            }
        }
    }

    private val stateListener: (String) -> Unit = { state ->
        runOnUiThread {
            applyStateUi(state)
        }
    }

    private val asciiLogo = """
__        ___       ____  __  __    __     ______  _   _
\ \      / (_)_ __ |  _ \|  \/  |   \ \   / /  _ \| \ | |
 \ \ /\ / /| | '_ \| |_) | |\/| |____\ \ / /| |_) |  \| |
  \ V  V / | | | | |  _ <| |  | |_____\ V / |  __/| |\  |
   \_/\_/  |_|_| |_|_| \_\_|  |_|      \_/  |_|   |_| \_|
    """.trimIndent()

    @SuppressLint("ClickableViewAccessibility")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences("winrm_cfg", Context.MODE_PRIVATE)
        val savedCheckConn = prefs.getBoolean("check_conn", false)
        VpnStateBus.checkConnectionEnabled = savedCheckConn
        Mobile.setCheckConnection(savedCheckConn)

        val rootScroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#121212"))
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 36, 36, 48)
        }

        val logoView = TextView(this).apply {
            text = asciiLogo
            typeface = Typeface.MONOSPACE
            textSize = 8.5f
            setTextColor(Color.parseColor("#00E676"))
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, 8, 0, 8)
        }

        val versionView = TextView(this).apply {
            text = "v0.4.5  |  Should looks like Ansible"
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextColor(Color.parseColor("#90A4AE"))
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, 0, 0, 24)
        }

        val serverRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        serverInput = EditText(this).apply {
            hint = "Server IP:Port (e.g. 203.0.113.10:5986)"
            setText(prefs.getString("server", ""))
            setTextColor(Color.WHITE); setHintTextColor(Color.parseColor("#78909C"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        serverRow.addView(serverInput); serverRow.addView(createClipboardPasteButton { pasteFromClipboard(serverInput) })
        val pskRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        pskInput = EditText(this).apply {
            hint = "Pre-Shared Key (PSK)"
            setText(prefs.getString("psk", ""))
            setTextColor(Color.WHITE); setHintTextColor(Color.parseColor("#78909C"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        pskRow.addView(pskInput); pskRow.addView(createClipboardPasteButton { pasteFromClipboard(pskInput) })

        val pinRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        pinInput = EditText(this).apply {
            hint = "Cert SHA-256 Pin (64 hex, optional)"
            setText(prefs.getString("pin", ""))
            setTextColor(Color.WHITE); setHintTextColor(Color.parseColor("#78909C"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        pinRow.addView(pinInput); pinRow.addView(createClipboardPasteButton { pasteFromClipboard(pinInput) })

        val checkRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 14, 0, 6)
        }

        checkConnSwitch = Switch(this).apply {
            text = "Проверять соединение"
            textSize = 14f
            setTextColor(Color.WHITE)
            isChecked = savedCheckConn
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean("check_conn", isChecked).apply()
                VpnStateBus.checkConnectionEnabled = isChecked
                Mobile.setCheckConnection(isChecked)
                VpnStateBus.log("[UI] Проверка соединения (Watchdog): ${if (isChecked) "ВКЛ" else "ВЫКЛ"}")
            }
        }

        val btnCheckInfo = Button(this).apply {
            text = "(?)"
            textSize = 13f
            setTextColor(Color.parseColor("#80D8FF"))
            setBackgroundColor(Color.TRANSPARENT)
            setPadding(16, 4, 8, 4)
            setOnClickListener {
                showCheckConnectionInfoDialog()
            }
        }

        checkRow.addView(checkConnSwitch)
        checkRow.addView(btnCheckInfo)

        errorText = TextView(this).apply {
            setTextColor(Color.parseColor("#FF5252"))
            textSize = 13f
            setPadding(0, 12, 0, 8)
            visibility = View.GONE
        }

        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 12, 0, 12)
        }

        val btnConnect = Button(this).apply {
            text = "Connect"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                if (validateInputs()) {
                    autoScrollEnabled = true
                    prefs.edit()
                        .putString("server", serverInput.text.toString().trim())
                        .putString("psk", pskInput.text.toString().trim())
                        .putString("pin", pinInput.text.toString().trim())
                        .putBoolean("check_conn", checkConnSwitch.isChecked)
                        .apply()
                    VpnStateBus.checkConnectionEnabled = checkConnSwitch.isChecked
                    Mobile.setCheckConnection(checkConnSwitch.isChecked)
                    prepareAndStartVpn()
                }
            }
        }

        val btnDisconnect = Button(this).apply {
            text = "Disconnect"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                val i = Intent(this@MainActivity, WinRmVpnService::class.java).apply { action = "STOP" }
                startService(i)
                pingResultText.text = ""
                ipResultText.text = ""
            }
        }

        btnRow.addView(btnConnect)
        btnRow.addView(btnDisconnect)

        statusText = TextView(this).apply {
            text = "Статус: Отключено"
            textSize = 14f
            setTextColor(Color.parseColor("#CFD8DC"))
            setPadding(0, 8, 0, 12)
        }

        val toolsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 4, 0, 8)
        }

        btnPingTest = Button(this).apply {
            text = "Тест ping 8.8.8.8"
            textSize = 12f
            isEnabled = false
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                runPingTest()
            }
        }

        btnCheckIp = Button(this).apply {
            text = "Проверить IP и страну"
            textSize = 12f
            isEnabled = false
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                checkIpAndCountry()
            }
        }

        toolsRow.addView(btnPingTest)
        toolsRow.addView(btnCheckIp)

        pingResultText = TextView(this).apply {
            text = ""
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setPadding(0, 4, 0, 6)
        }

        ipResultText = TextView(this).apply {
            text = ""
            textSize = 14f
            setTextColor(Color.parseColor("#80D8FF"))
            setPadding(0, 4, 0, 16)
        }

        val logHeaderRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val logTitle = TextView(this).apply {
            text = "Логи подключения:"
            textSize = 13f
            setTextColor(Color.parseColor("#B0BEC5"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val btnClearLog = Button(this).apply {
            text = "Очистить"
            textSize = 11f
            setOnClickListener {
                VpnStateBus.clearLogs()
                logText.text = ""
                autoScrollEnabled = true
            }
        }
        logHeaderRow.addView(logTitle)
        logHeaderRow.addView(btnClearLog)

        logText = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 10.5f
            setTextColor(Color.parseColor("#C9D1D9"))
            setPadding(16, 16, 16, 16)
            text = VpnStateBus.logs.joinToString("\n")
        }

        logScroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#0D1117"))
            isVerticalScrollBarEnabled = true
            isScrollbarFadingEnabled = false
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                600
            )
            setOnTouchListener { v, event ->
                when (event.actionMasked) {
                    MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE ->
                        v.parent?.requestDisallowInterceptTouchEvent(true)
                    MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL ->
                        v.parent?.requestDisallowInterceptTouchEvent(false)
                }
                false
            }
            setOnScrollChangeListener { v, _, scrollY, _, _ ->
                val child = (v as ScrollView).getChildAt(0)
                if (child != null) {
                    val diff = child.bottom - (v.height + scrollY)
                    autoScrollEnabled = (diff <= 60)
                }
            }
            addView(logText)
        }

        // Гарантированный автоскролл вниз сразу после перерасчёта высоты текста
        logText.addOnLayoutChangeListener { _, _, _, _, bottom, _, _, _, oldBottom ->
            if (bottom > oldBottom && autoScrollEnabled) {
                logScroll.post {
                    logScroll.scrollTo(0, bottom)
                }
            }
        }

        layout.addView(logoView)
        layout.addView(versionView)
        layout.addView(serverRow)
        layout.addView(pskRow)
        layout.addView(pinRow)
        layout.addView(checkRow)
        layout.addView(errorText)
        layout.addView(btnRow)
        layout.addView(statusText)
        layout.addView(toolsRow)
        layout.addView(pingResultText)
        layout.addView(ipResultText)
        layout.addView(logHeaderRow)
        layout.addView(logScroll)

        rootScroll.addView(layout)
        setContentView(rootScroll)

        VpnStateBus.logListeners.add(logListener)
        VpnStateBus.stateListeners.add(stateListener)

        applyStateUi(VpnStateBus.currentState)
        logScroll.post { logScroll.scrollTo(0, logText.bottom) }
    }

    private fun createClipboardPasteButton(onClick: () -> Unit): ImageButton {
        val sizePx = (22 * resources.displayMetrics.density).toInt().coerceAtLeast(32)
        val icon = object : Drawable() {
            private val p = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = Color.parseColor("#CFD8DC"); style = Paint.Style.STROKE
                strokeWidth = (2.0f * resources.displayMetrics.density).coerceAtLeast(3f)
                strokeCap = Paint.Cap.ROUND; strokeJoin = Paint.Join.ROUND
            }
            override fun getIntrinsicWidth(): Int = sizePx
            override fun getIntrinsicHeight(): Int = sizePx
            override fun draw(c: Canvas) {
                val sx = bounds.width() / 24f; val sy = bounds.height() / 24f
                c.drawRoundRect(5f * sx, 4f * sy, 19f * sx, 21f * sy, 2f * sx, 2f * sy, p)
                c.drawRoundRect(9f * sx, 2f * sy, 15f * sx, 5.5f * sy, 1f * sx, 1f * sy, p)
                c.drawLine(8.5f * sx, 10.5f * sy, 15.5f * sx, 10.5f * sy, p)
                c.drawLine(8.5f * sx, 14.5f * sy, 15.5f * sx, 14.5f * sy, p)
            }
            override fun setAlpha(alpha: Int) { p.alpha = alpha }
            override fun setColorFilter(cf: ColorFilter?) { p.colorFilter = cf }
            @Deprecated("Deprecated in Java") override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
        }
        return ImageButton(this).apply {
            setImageDrawable(icon); contentDescription = "Вставить"
            setBackgroundColor(Color.parseColor("#21262D")); setPadding(22, 16, 22, 16)
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

    override fun onDestroy() {
        VpnStateBus.logListeners.remove(logListener)
        VpnStateBus.stateListeners.remove(stateListener)
        super.onDestroy()
    }

    private fun showCheckConnectionInfoDialog() {
        AlertDialog.Builder(this)
            .setTitle("Проверка соединения (Watchdog)")
            .setMessage(
                "При включённом переключателе и активном VPN-туннеле приложение автоматически отслеживает его работоспособность:\n\n" +
                "1. Пассивный контроль: если в течение последних 30–60 секунд через туннель уже приходили данные, лишних проверок не отправляется.\n\n" +
                "2. В простое отправляется служебный WinRM KeepAlive фрейм (размером под SOAP-ответ).\n\n" +
                "3. Если ответа нет, через 10–20 секунд выполняется повторная проверка, и при повторной неудаче VPN автоматически переподключается."
            )
            .setPositiveButton("Понятно", null)
            .show()
    }

    private fun validateInputs(): Boolean {
        val server = serverInput.text.toString().trim()
        val psk = pskInput.text.toString().trim()
        val pin = pinInput.text.toString().trim().replace(":", "")

        if (server.isEmpty()) {
            showValidationError("Ошибка: не указан адрес сервера (IP:Port).")
            return false
        }
        val parts = server.split(":")
        val port = parts.getOrNull(1)?.toIntOrNull()
        if (parts.size != 2 || parts[0].isBlank() || port == null || port !in 1..65535) {
            showValidationError("Ошибка: неверный формат сервера. Укажите IP:Port.")
            return false
        }
        if (psk.isEmpty()) {
            showValidationError("Ошибка: не указан Pre-Shared Key (PSK).")
            return false
        }
        if (pin.isNotEmpty() && !pin.matches(Regex("^[0-9a-fA-F]{64}$"))) {
            showValidationError("Ошибка: SHA-256 Pin введён неверно.")
            return false
        }

        errorText.visibility = View.GONE
        return true
    }

    private fun showValidationError(msg: String) {
        errorText.text = msg
        errorText.visibility = View.VISIBLE
        VpnStateBus.log("[VALIDATION] $msg")
    }

    private fun applyStateUi(state: String) {
        when (state) {
            "CONNECTING" -> {
                statusText.text = "Статус: Подключение к серверу..."
                statusText.setTextColor(Color.parseColor("#FFD54F"))
                pingResultText.text = ""
                ipResultText.text = ""
                btnPingTest.isEnabled = false
                btnCheckIp.isEnabled = false
            }
            "CONNECTED" -> {
                statusText.text = "Статус: Подключено"
                statusText.setTextColor(Color.parseColor("#00E676"))
                btnPingTest.isEnabled = true
                btnCheckIp.isEnabled = true
                errorText.visibility = View.GONE
            }
            "ERROR" -> {
                statusText.text = "Статус: Не удалось подключиться — VPN выключен (см. логи)"
                statusText.setTextColor(Color.parseColor("#FF5252"))
                btnPingTest.isEnabled = false
                btnCheckIp.isEnabled = false
            }
            else -> {
                statusText.text = "Статус: Отключено"
                statusText.setTextColor(Color.parseColor("#CFD8DC"))
                btnPingTest.isEnabled = false
                btnCheckIp.isEnabled = false
            }
        }
    }

    private fun runPingTest() {
        pingResultText.setTextColor(Color.parseColor("#FFD54F"))
        pingResultText.text = "Выполняется тестовый ping 8.8.8.8..."
        VpnStateBus.log("[PING] Running ping -c 1 -W 3 8.8.8.8 ...")

        Thread {
            try {
                val proc = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "3", "8.8.8.8")
                    .redirectErrorStream(true)
                    .start()
                val output = BufferedReader(InputStreamReader(proc.inputStream)).readText()
                val exitCode = proc.waitFor()

                val rttMatch = Regex("time=([0-9.]+\\s*ms)").find(output)
                val rttStr = rttMatch?.groupValues?.get(1) ?: ""

                runOnUiThread {
                    if (exitCode == 0) {
                        val suffix = if (rttStr.isNotEmpty()) " ($rttStr)" else ""
                        pingResultText.setTextColor(Color.parseColor("#00E676"))
                        pingResultText.text = "✓ Тестовый пинг 8.8.8.8 прошел$suffix"
                        VpnStateBus.log("[PING] SUCCESS: 8.8.8.8 reachable$suffix")
                    } else {
                        pingResultText.setTextColor(Color.parseColor("#FF5252"))
                        pingResultText.text = "✗ Ошибка: тестовый пинг 8.8.8.8 не прошел (код $exitCode)"
                        VpnStateBus.log("[PING] FAILED (exit=$exitCode): ${output.trim().replace("\n", " | ")}")
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    pingResultText.setTextColor(Color.parseColor("#FF5252"))
                    pingResultText.text = "✗ Ошибка пинга 8.8.8.8: ${e.message}"
                    VpnStateBus.log("[PING] EXCEPTION: ${e.message}")
                }
            }
        }.start()
    }

    private fun checkIpAndCountry() {
        ipResultText.setTextColor(Color.parseColor("#FFD54F"))
        ipResultText.text = "Запрос IP и страны через ifconfig.io..."
        VpnStateBus.log("[IP-CHECK] Fetching http://ifconfig.io/country_code & /host ...")

        Thread {
            try {
                val countryCode = httpGetCurl("http://ifconfig.io/country_code").trim().uppercase()
                val hostOrIp = httpGetCurl("http://ifconfig.io/host").trim()
                val flag = countryCodeToFlag(countryCode)

                runOnUiThread {
                    ipResultText.setTextColor(Color.parseColor("#00E676"))
                    ipResultText.text = "$flag $countryCode  |  IP/Host: $hostOrIp"
                    VpnStateBus.log("[IP-CHECK] Result: $flag $countryCode | $hostOrIp")
                }
            } catch (e: Exception) {
                runOnUiThread {
                    ipResultText.setTextColor(Color.parseColor("#FF5252"))
                    ipResultText.text = "✗ Ошибка проверки IP: ${e.message}"
                    VpnStateBus.log("[IP-CHECK] ERROR: ${e.message}")
                }
            }
        }.start()
    }

    private fun httpGetCurl(urlStr: String): String {
        val conn = URL(urlStr).openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.connectTimeout = 5000
        conn.readTimeout = 5000
        conn.setRequestProperty("User-Agent", "curl/8.5.0")
        conn.setRequestProperty("Accept", "*/*")
        try {
            val code = conn.responseCode
            if (code !in 200..299) {
                throw Exception("HTTP $code from $urlStr")
            }
            return conn.inputStream.bufferedReader().use { it.readText() }
        } finally {
            conn.disconnect()
        }
    }

    private fun countryCodeToFlag(code: String): String {
        val clean = code.trim().uppercase()
        if (clean.length != 2 || !clean.all { it in 'A'..'Z' }) return "🏳️"
        val first = Character.toChars(0x1F1E6 + (clean[0] - 'A'))
        val second = Character.toChars(0x1F1E6 + (clean[1] - 'A'))
        return String(first) + String(second)
    }

    private fun prepareAndStartVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, 100)
        } else {
            onActivityResult(100, RESULT_OK, null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == 100 && resultCode == RESULT_OK) {
            val svc = Intent(this, WinRmVpnService::class.java).apply {
                putExtra("server", serverInput.text.toString().trim())
                putExtra("psk", pskInput.text.toString().trim())
                putExtra("pin", pinInput.text.toString().trim())
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(svc)
            } else {
                startService(svc)
            }
        } else if (requestCode == 100) {
            showValidationError("Ошибка: пользователь отклонил разрешение на создание VPN.")
        }
    }
}
