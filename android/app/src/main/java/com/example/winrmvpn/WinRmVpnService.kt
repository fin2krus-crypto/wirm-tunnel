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
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import mobile.Mobile
import mobile.SocketProtector
import mobile.TunnelCallback
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

object VpnStateBus {
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    val logs = CopyOnWriteArrayList<String>()
    @Volatile var currentState: String = "DISCONNECTED"
    @Volatile var onLogListener: ((String) -> Unit)? = null
    @Volatile var onStateListener: ((String) -> Unit)? = null

    fun log(msg: String) {
        val line = "[${timeFmt.format(Date())}] $msg"
        logs.add(line)
        if (logs.size > 300) {
            logs.removeAt(0)
        }
        onLogListener?.invoke(line)
    }

    fun updateState(state: String) {
        currentState = state
        onStateListener?.invoke(state)
    }

    fun clearLogs() {
        logs.clear()
    }
}

class WinRmVpnService : VpnService(), SocketProtector, TunnelCallback {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetwork: Network? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            VpnStateBus.log("[ANDROID] Stopping VPN service...")
            stopVpn()
            return START_NOT_STICKY
        }

        val serverAddr = intent?.getStringExtra("server") ?: return START_NOT_STICKY
        val psk = intent.getStringExtra("psk") ?: return START_NOT_STICKY
        val certPin = intent.getStringExtra("pin") ?: ""

        startForegroundNotification()
        setupNetworkMonitor()
        VpnStateBus.log("[ANDROID] Initializing TUN interface (10.88.0.2/24, MTU 1380)...")

        if (vpnInterface == null) {
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
            VpnStateBus.updateState("ERROR")
            stopVpn()
            return START_NOT_STICKY
        }

        VpnStateBus.log("[ANDROID] TUN fd=${pfd.fd} ready. Starting Go core...")
        try {
            Mobile.startWinRMTunnel(pfd.fd.toLong(), serverAddr, psk, certPin, this, this)
        } catch (e: Exception) {
            VpnStateBus.log("[ERR] StartWinRMTunnel exception: ${e.message}")
            VpnStateBus.updateState("ERROR")
            stopVpn()
        }

        return START_STICKY
    }

    private fun setupNetworkMonitor() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network)
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) return

                if (lastNetwork != null && lastNetwork != network) {
                    VpnStateBus.log("[NETWORK] Default network changed. Forcing reconnect...")
                    Mobile.triggerReconnect()
                } else if (lastNetwork == null) {
                    VpnStateBus.log("[NETWORK] System default network is available.")
                }
                lastNetwork = network
                
                // ВАЖНО: мы убрали setUnderlyingNetworks(arrayOf(network)), 
                // чтобы не ломать системную проверку Wi-Fi на наличие интернета.
                // Android автоматически проложит маршрут VPN через текущую сеть.
                setUnderlyingNetworks(null)
            }

            override fun onLost(network: Network) {
                val caps = cm.getNetworkCapabilities(network)
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) return

                if (network == lastNetwork) {
                    VpnStateBus.log("[NETWORK] Default network lost. Waiting for new connection...")
                    Mobile.triggerReconnect()
                    lastNetwork = null
                    setUnderlyingNetworks(null)
                }
            }
        }
        
        // Слушаем только успешную смену главной системной сети
        cm.registerDefaultNetworkCallback(networkCallback!!)
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
        setUnderlyingNetworks(null)
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
        if (!state.isNullOrEmpty()) {
            VpnStateBus.updateState(state)
        }
    }

    private fun stopVpn() {
        stopNetworkMonitor()
        Mobile.stopWinRMTunnel()
        try {
            vpnInterface?.close()
        } catch (_: Exception) {}
        vpnInterface = null
        VpnStateBus.updateState("DISCONNECTED")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
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
                .setContentTitle("WinRM-VPN v0.0.9")
                .setContentText("Should looks like Ansible")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("WinRM-VPN v0.0.9")
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
