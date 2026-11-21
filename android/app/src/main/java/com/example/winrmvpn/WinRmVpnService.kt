package com.example.winrmvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import mobile.Mobile
import mobile.SocketProtector

class WinRmVpnService : VpnService(), SocketProtector {

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        val serverAddr = intent?.getStringExtra("server") ?: return START_NOT_STICKY
        val psk = intent.getStringExtra("psk") ?: return START_NOT_STICKY
        val certPin = intent.getStringExtra("pin") ?: ""

        startForegroundNotification()

        if (vpnInterface == null) {
            val builder = Builder()
                .setSession("Ansible-WinRM")
                .setMtu(1380)
                .addAddress("10.88.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addAddress("fd00:88::2", 128)
                .addRoute("::", 0)

            vpnInterface = builder.establish()
        }

        val pfd = vpnInterface ?: return START_NOT_STICKY
        try {
            Mobile.startWinRMTunnel(pfd.fd.toLong(), serverAddr, psk, certPin, this)
        } catch (e: Exception) {
            stopVpn()
        }

        return START_STICKY
    }

    override fun protect(fd: Long): Boolean {
        return super.protect(fd.toInt())
    }

    private fun stopVpn() {
        Mobile.stopWinRMTunnel()
        try {
            vpnInterface?.close()
        } catch (_: Exception) {}
        vpnInterface = null
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
            val chan = NotificationChannel(channelId, "WinRM Tunnel", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(chan)
        }
        val notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
                .setContentTitle("Ansible WinRM Tunnel")
                .setContentText("OpenSSL 3.x -> WinRM 5986/TCP")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Ansible WinRM Tunnel")
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
