package com.example.winrmvpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : Activity() {

    private lateinit var serverInput: EditText
    private lateinit var pskInput: EditText
    private lateinit var pinInput: EditText

    private lateinit var errorText: TextView
    private lateinit var statusText: TextView
    private lateinit var pingResultText: TextView
    private lateinit var ipResultText: TextView
    private lateinit var btnCheckIp: Button
    private lateinit var logText: TextView
    private lateinit var logScroll: ScrollView

    private val asciiLogo = """
__        ___       ____  __  __    __     ______  _   _
\ \      / (_)_ __ |  _ \|  \/  |   \ \   / /  _ \| \ | |
 \ \ /\ / /| | '_ \| |_) | |\/| |____\ \ / /| |_) |  \| |
  \ V  V / | | | | |  _ <| |  | |_____\ V / |  __/| |\  |
   \_/\_/  |_|_| |_|_| \_\_|  |_|      \_/  |_|   |_| \_|
    """.trimIndent()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences("winrm_cfg", Context.MODE_PRIVATE)

        val rootScroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#121212"))
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 36, 36, 48)
        }

        // 1. ASCII-логотип
        val logoView = TextView(this).apply {
            text = asciiLogo
            typeface = Typeface.MONOSPACE
            textSize = 8.5f
            setTextColor(Color.parseColor("#00E676"))
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, 8, 0, 8)
        }

        // 2. Версия приложения 0.0.3
        val versionView = TextView(this).apply {
            text = "v0.0.3  |  Ansible OpenSSL 3.x -> WinRM 5986"
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextColor(Color.parseColor("#90A4AE"))
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, 0, 0, 24)
        }

        // Поля ввода
        serverInput = EditText(this).apply {
            hint = "Server IP:Port (e.g. 203.0.113.10:5986)"
            setText(prefs.getString("server", ""))
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#78909C"))
        }
        pskInput = EditText(this).apply {
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
        }

        // Поле ошибок валидации
        errorText = TextView(this).apply {
            setTextColor(Color.parseColor("#FF5252"))
            textSize = 13f
            setPadding(0, 12, 0, 8)
            visibility = View.GONE
        }

        // Кнопки Connect / Disconnect
        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 12, 0, 12)
        }

        val btnConnect = Button(this).apply {
            text = "Connect"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                if (validateInputs()) {
                    prefs.edit()
                        .putString("server", serverInput.text.toString().trim())
                        .putString("psk", pskInput.text.toString().trim())
                        .putString("pin", pinInput.text.toString().trim())
                        .apply()
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

        // Статус подключения
        statusText = TextView(this).apply {
            text = "Статус: Отключено"
            textSize = 14f
            setTextColor(Color.parseColor("#CFD8DC"))
            setPadding(0, 8, 0, 8)
        }

        // Результат автоматического пинга 8.8.8.8
        pingResultText = TextView(this).apply {
            text = ""
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setPadding(0, 4, 0, 12)
        }

        // Кнопка проверки IP и страны
        btnCheckIp = Button(this).apply {
            text = "Проверить IP и страну (ifconfig.io)"
            isEnabled = false
            setOnClickListener {
                checkIpAndCountry()
            }
        }

        ipResultText = TextView(this).apply {
            text = ""
            textSize = 14f
            setTextColor(Color.parseColor("#80D8FF"))
            setPadding(0, 8, 0, 16)
        }

        // Заголовок и окно подробных логов
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
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                520
            )
            addView(logText)
        }

        layout.addView(logoView)
        layout.addView(versionView)
        layout.addView(serverInput)
        layout.addView(pskInput)
        layout.addView(pinInput)
        layout.addView(errorText)
        layout.addView(btnRow)
        layout.addView(statusText)
        layout.addView(pingResultText)
        layout.addView(btnCheckIp)
        layout.addView(ipResultText)
        layout.addView(logHeaderRow)
        layout.addView(logScroll)

        rootScroll.addView(layout)
        setContentView(rootScroll)

        // Подписка на события из WinRmVpnService
        VpnStateBus.onLogListener = { line ->
            runOnUiThread {
                if (logText.text.isNotEmpty()) {
                    logText.append("\n$line")
                } else {
                    logText.text = line
                }
                logScroll.post { logScroll.fullScroll(View.FOCUS_DOWN) }
            }
        }

        VpnStateBus.onStateListener = { state ->
            runOnUiThread {
                applyStateUi(state)
            }
        }

        applyStateUi(VpnStateBus.currentState)
    }

    override fun onDestroy() {
        VpnStateBus.onLogListener = null
        VpnStateBus.onStateListener = null
        super.onDestroy()
    }

    // Валидация введённых данных
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
            showValidationError("Ошибка: неверный формат сервера. Укажите IP:Port (например, 203.0.113.10:5986).")
            return false
        }
        if (psk.isEmpty()) {
            showValidationError("Ошибка: не указан Pre-Shared Key (PSK).")
            return false
        }
        if (pin.isNotEmpty() && !pin.matches(Regex("^[0-9a-fA-F]{64}$"))) {
            showValidationError("Ошибка: SHA-256 Pin введён неверно (нужно ровно 64 hex-символа или оставьте пустым).")
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
                statusText.text = "Статус: Подключение к WinRM..."
                statusText.setTextColor(Color.parseColor("#FFD54F"))
                pingResultText.text = ""
                btnCheckIp.isEnabled = false
            }
            "CONNECTED" -> {
                statusText.text = "Статус: Подключено (WinRM HTTPS)"
                statusText.setTextColor(Color.parseColor("#00E676"))
                btnCheckIp.isEnabled = true
                errorText.visibility = View.GONE
                runPingTest()
            }
            "ERROR" -> {
                statusText.text = "Статус: Ошибка подключения (см. логи ниже)"
                statusText.setTextColor(Color.parseColor("#FF5252"))
                btnCheckIp.isEnabled = false
            }
            else -> {
                statusText.text = "Статус: Отключено"
                statusText.setTextColor(Color.parseColor("#CFD8DC"))
                btnCheckIp.isEnabled = false
            }
        }
    }

    // Автоматическая проверка ping 8.8.8.8 после установления соединения
    private fun runPingTest() {
        pingResultText.setTextColor(Color.parseColor("#FFD54F"))
        pingResultText.text = "Выполняется тестовый ping 8.8.8.8..."
        VpnStateBus.log("[PING] Running ping -c 1 -W 3 8.8.8.8 ...")

        Thread {
            try {
                Thread.sleep(700) // Даём Android применить таблицу маршрутизации TUN
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

    // Проверка IP и страны через http://ifconfig.io/country_code и http://ifconfig.io/host
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
        // User-Agent curl гарантирует ответ в виде чистого текста (без HTML)
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
