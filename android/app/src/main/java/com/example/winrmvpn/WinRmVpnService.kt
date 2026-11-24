package com.example.winrmvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import mobile.Mobile
import mobile.SocketProtector
import mobile.TunnelCallback
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.random.Random

object VpnStateBus {
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    val logs = CopyOnWriteArrayList<String>()
    @Volatile var currentState: String = "DISCONNECTED"
    @Volatile var checkConnectionEnabled: Boolean = false

    val logListeners = CopyOnWriteArrayList<(String) -> Unit>()
    val stateListeners = CopyOnWriteArrayList<(String) -> Unit>()

    fun log(msg: String) {
        val line = "[${timeFmt.format(Date())}] $msg"
        logs.add(line)
        if (logs.size > 300) {
            logs.removeAt(0)
        }
        logListeners.forEach { it.invoke(line) }
    }

    fun updateState(state: String) {
        currentState = state
        stateListeners.forEach { it.invoke(state) }
    }

    fun clearLogs() {
        logs.clear()
    }
}

class WinRmVpnService : VpnService(), SocketProtector, TunnelCallback {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetwork: Network? = null

    @Volatile private var isStopping = false

    // Страховочный таймер на все 3 попытки (45 сек)
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile private var isConnectTimeoutArmed = false
    private val connectTimeoutRunnable = Runnable {
        if (!isStopping && VpnStateBus.currentState != "CONNECTED") {
            VpnStateBus.log("[TIMEOUT] Превышено общее время подключения. Выключение сервиса...")
            stopVpn(dueToError = true)
        }
    }

    // Поток периодической проверки соединения (ping 1.1.1.1)
    @Volatile private var healthCheckRunning = false
    private var healthCheckThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            VpnStateBus.log("[ANDROID] Stopping VPN service...")
            stopVpn(dueToError = false)
            return START_NOT_STICKY
        }

        val serverAddr = intent?.getStringExtra("server") ?: return START_NOT_STICKY
        val psk = intent.getStringExtra("psk") ?: return START_NOT_STICKY
        val certPin = intent.getStringExtra("pin") ?: ""

        val prefs = getSharedPreferences("winrm_cfg", Context.MODE_PRIVATE)
        VpnStateBus.checkConnectionEnabled = prefs.getBoolean("check_conn", false)

        isStopping = false
        startForegroundNotification()
        setupNetworkMonitor()
        startHealthCheckLoop()
        armConnectTimeoutIfNeeded()

        VpnStateBus.log("[ANDROID] Подключение к серверу (TUN поднимется только после успеха)...")
        try {
            Mobile.startWinRMTunnel(serverAddr, psk, certPin, this, this)
        } catch (e: Exception) {
            if (e.message?.contains("already running") == true) {
                VpnStateBus.log("[ANDROID] Туннель уже запущен.")
                return START_STICKY
            }
            VpnStateBus.log("[ERR] StartWinRMTunnel exception: ${e.message}")
            stopVpn(dueToError = true)
        }

        return START_STICKY
    }

    // Вызывается из Go только ПОСЛЕ успешной авторизации (200 OK)
    @Synchronized
    override fun openTun(): Long {
        if (isStopping) return -1L
        if (vpnInterface == null) {
            VpnStateBus.log("[ANDROID] Соединение успешно! Поднимаю TUN интерфейс (10.88.0.2/24, MTU 1380)...")
            val builder = Builder()
                .setSession("WinRM-VPN")
                .setMtu(1380)
                .addAddress("10.88.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addAddress("fd00:88::2", 128)
                .addRoute("::", 0)

            vpnInterface = builder.establish()
        }

        val pfd = vpnInterface
        if (pfd == null) {
            VpnStateBus.log("[ERR] Failed to establish Android VpnService TUN!")
            return -1L
        }
        VpnStateBus.log("[ANDROID] TUN fd=${pfd.fd} активен.")
        return pfd.fd.toLong()
    }

    private fun armConnectTimeoutIfNeeded() {
        mainHandler.post {
            if (!isStopping && !isConnectTimeoutArmed) {
                isConnectTimeoutArmed = true
                mainHandler.postDelayed(connectTimeoutRunnable, 45_000L)
            }
        }
    }

    private fun cancelConnectTimeout() {
        mainHandler.post {
            isConnectTimeoutArmed = false
            mainHandler.removeCallbacks(connectTimeoutRunnable)
        }
    }

    private fun startHealthCheckLoop() {
        if (healthCheckRunning) return
        healthCheckRunning = true
        healthCheckThread = Thread {
            while (healthCheckRunning) {
                if (!VpnStateBus.checkConnectionEnabled || VpnStateBus.currentState != "CONNECTED") {
                    try {
                        Thread.sleep(1000L)
                    } catch (_: InterruptedException) {
                        break
                    }
                    continue
                }

                // 1. Случайный интервал 30–60 секунд
                val waitSec = Random.nextInt(30, 61)
                if (!interruptibleSleepSec(waitSec)) continue

                if (pingTarget("1.1.1.1")) {
                    VpnStateBus.log("[WATCHDOG] ping 1.1.1.1 OK (след. через 30-60с)")
                    continue
                }

                // 2. Первая неудача -> повтор через случайные 10–20 секунд
                val retrySec = Random.nextInt(10, 21)
                VpnStateBus.log("[WATCHDOG] ping 1.1.1.1 не прошёл! Повтор через ${retrySec}с...")
                if (!interruptibleSleepSec(retrySec)) continue

                if (pingTarget("1.1.1.1")) {
                    VpnStateBus.log("[WATCHDOG] Повторный ping 1.1.1.1 OK")
                } else {
                    // 3. Повторная неудача -> перезапуск VPN соединения
                    VpnStateBus.log("[WATCHDOG] Повторный ping 1.1.1.1 не прошёл! Перезапуск VPN...")
                    Mobile.triggerReconnect()
                    try {
                        Thread.sleep(2000L)
                    } catch (_: InterruptedException) {
                        break
                    }
                }
            }
        }.apply {
            isDaemon = true
            start()
        }
    }

    private fun stopHealthCheckLoop() {
        healthCheckRunning = false
        healthCheckThread?.interrupt()
        healthCheckThread = null
    }

    private fun interruptibleSleepSec(seconds: Int): Boolean {
        for (i in 0 until seconds) {
            if (!healthCheckRunning || !VpnStateBus.checkConnectionEnabled || VpnStateBus.currentState != "CONNECTED") {
                return false
            }
            try {
                Thread.sleep(1000L)
            } catch (_: InterruptedException) {
                return false
            }
        }
        return healthCheckRunning && VpnStateBus.checkConnectionEnabled && VpnStateBus.currentState == "CONNECTED"
    }

    private fun pingTarget(host: String): Boolean {
        return try {
            val proc = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "3", host)
                .redirectErrorStream(true)
                .start()
            BufferedReader(InputStreamReader(proc.inputStream)).use { it.readText() }
            proc.waitFor() == 0
        } catch (_: Exception) {
            false
        }
    }

    private fun setupNetworkMonitor() {
        if (networkCallback != null) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (lastNetwork == null) {
                    // Первичная фиксация текущей сети без лишнего сброса соединения
                    lastNetwork = network
                    VpnStateBus.log("[NETWORK] Active network detected ($network).")
                } else if (lastNetwork != network) {
                    VpnStateBus.log("[NETWORK] Validated network changed ($network). Forcing reconnect...")
                    lastNetwork = network
                    Mobile.triggerReconnect()
                }
            }

            override fun onLost(network: Network) {
                if (network == lastNetwork) {
                    VpnStateBus.log("[NETWORK] Current validated network lost. Waiting...")
                    lastNetwork = null
                    Mobile.triggerReconnect()
                }
            }
        }

        cm.registerNetworkCallback(request, networkCallback!!)
    }

    private fun stopNetworkMonitor() {
        networkCallback?.let {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            try {
                cm.unregisterNetworkCallback(it)
            } catch (_: Exception) {}
        }
        networkCallback = null
        lastNetwork = null
    }

    override fun protect(fd: Long): Boolean {
        return super.protect(fd.toInt())
    }

    override fun onLog(msg: String?) {
        if (!msg.isNullOrEmpty()) {
            VpnStateBus.log(msg)
        }
    }

    override fun onStateChanged(state: String?) {
        if (isStopping || state.isNullOrEmpty()) return

        when (state) {
            "CONNECTED" -> cancelConnectTimeout()
            "CONNECTING" -> armConnectTimeoutIfNeeded()
            "ERROR" -> {
                mainHandler.post { stopVpn(dueToError = true) }
                return
            }
        }
        VpnStateBus.updateState(state)
    }

    @Synchronized
    private fun stopVpn(dueToError: Boolean = false) {
        if (isStopping) return
        isStopping = true
        cancelConnectTimeout()
        stopHealthCheckLoop()
        stopNetworkMonitor()
        Mobile.stopWinRMTunnel()
        try {
            vpnInterface?.close()
        } catch (_: Exception) {}
        vpnInterface = null
        VpnStateBus.updateState(if (dueToError) "ERROR" else "DISCONNECTED")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        if (!isStopping) {
            stopVpn(dueToError = false)
        }
        super.onDestroy()
    }

    private fun startForegroundNotification() {
        val channelId = "winrm_vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val chan = NotificationChannel(channelId, "WinRM-VPN Tunnel", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(chan)
        }
        val notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
                .setContentTitle("WinRM-VPN v0.1.1")
                .setContentText("Should looks like Ansible")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("WinRM-VPN v0.1.1")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .build()
        }

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, notification)
        }
    }
}
