package com.example.torchatv2

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.example.torchatv2.transport.GuardianTorManager
import com.example.torchatv2.transport.GuardianOnionServiceManager
import com.example.torchatv2.transport.TorManager
import com.example.torchatv2.transport.OnionServiceManager

class TorForegroundService : Service() {
    private lateinit var torManager: TorManager
    private lateinit var onionManager: OnionServiceManager

    override fun onCreate() {
        super.onCreate()
        torManager = GuardianTorManager(this)
        onionManager = GuardianOnionServiceManager(this)
        
        createNotificationChannel()
        startForeground(1, createNotification("Tor is starting..."))
        
        torManager.start()
        onionManager.startService()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY
    }

    override fun onDestroy() {
        torManager.stop()
        onionManager.stopService()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            "tor_channel",
            "Tor Service",
            NotificationManager.IMPORTANCE_LOW
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun createNotification(content: String): Notification {
        return NotificationCompat.Builder(this, "tor_channel")
            .setContentTitle("TorChatV2")
            .setContentText(content)
            .setSmallIcon(R.mipmap.ic_launcher)
            .build()
    }
}
