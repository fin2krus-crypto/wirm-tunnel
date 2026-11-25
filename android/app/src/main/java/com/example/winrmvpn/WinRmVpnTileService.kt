package com.example.winrmvpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class WinRmVpnTileService : TileService() {

    private val stateListener: (String) -> Unit = { state ->
        updateTileState(state)
    }

    override fun onStartListening() {
        super.onStartListening()
        VpnStateBus.stateListeners.add(stateListener)
        updateTileState(VpnStateBus.currentState)
    }

    override fun onStopListening() {
        VpnStateBus.stateListeners.remove(stateListener)
        super.onStopListening()
    }

    private fun updateTileState(state: String) {
        val tile = qsTile ?: return
        when (state) {
            "CONNECTED" -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Подключено"
                }
            }
            "CONNECTING" -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Подключение..."
                }
            }
            "ERROR" -> {
                tile.state = Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Ошибка"
                }
            }
            else -> {
                tile.state = Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Отключено"
                }
            }
        }
        tile.label = "WinRM-VPN"
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        val state = VpnStateBus.currentState

        if (state == "CONNECTED" || state == "CONNECTING") {
            val i = Intent(this, WinRmVpnService::class.java).apply { action = "STOP" }
            startService(i)
        } else {
            val prefs = getSharedPreferences("winrm_cfg", Context.MODE_PRIVATE)
            val server = prefs.getString("server", "") ?: ""
            val psk = prefs.getString("psk", "") ?: ""

            if (server.isEmpty() || psk.isEmpty()) {
                launchApp()
                return
            }

            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent != null) {
                launchApp()
            } else {
                val pin = prefs.getString("pin", "") ?: ""
                val svc = Intent(this, WinRmVpnService::class.java).apply {
                    putExtra("server", server)
                    putExtra("psk", psk)
                    putExtra("pin", pin)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(svc)
                } else {
                    startService(svc)
                }
            }
        }
    }

    private fun launchApp() {
        val intent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        @Suppress("DEPRECATION")
        startActivityAndCollapse(intent)
    }
}
