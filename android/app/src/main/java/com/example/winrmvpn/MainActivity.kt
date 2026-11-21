package com.example.winrmvpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {

    private lateinit var serverInput: EditText
    private lateinit var pskInput: EditText
    private lateinit var pinInput: EditText
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences("winrm_cfg", Context.MODE_PRIVATE)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        serverInput = EditText(this).apply {
            hint = "Server IP:Port (e.g. 203.0.113.10:5986)"
            setText(prefs.getString("server", ""))
        }
        pskInput = EditText(this).apply {
            hint = "Pre-Shared Key (PSK)"
            setText(prefs.getString("psk", ""))
        }
        pinInput = EditText(this).apply {
            hint = "Cert SHA-256 Fingerprint (optional pin)"
            setText(prefs.getString("pin", ""))
        }
        statusText = TextView(this).apply {
            text = "Status: Idle (Profile: Ansible / Linux OpenSSL 3.x)"
            setPadding(0, 24, 0, 24)
        }

        val btnConnect = Button(this).apply {
            text = "Connect (Ansible WinRM HTTPS)"
            setOnClickListener {
                prefs.edit()
                    .putString("server", serverInput.text.toString().trim())
                    .putString("psk", pskInput.text.toString().trim())
                    .putString("pin", pinInput.text.toString().trim())
                    .apply()
                prepareAndStartVpn()
            }
        }

        val btnDisconnect = Button(this).apply {
            text = "Disconnect"
            setOnClickListener {
                val i = Intent(this@MainActivity, WinRmVpnService::class.java).apply { action = "STOP" }
                startService(i)
                statusText.text = "Status: Disconnected"
            }
        }

        layout.addView(serverInput)
        layout.addView(pskInput)
        layout.addView(pinInput)
        layout.addView(btnConnect)
        layout.addView(btnDisconnect)
        layout.addView(statusText)
        setContentView(layout)
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
            statusText.text = "Status: Running (Ansible OpenSSL 3.x -> 5986)"
        }
    }
}
