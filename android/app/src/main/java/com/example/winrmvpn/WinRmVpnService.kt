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

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (lastNetwork != network) {
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
