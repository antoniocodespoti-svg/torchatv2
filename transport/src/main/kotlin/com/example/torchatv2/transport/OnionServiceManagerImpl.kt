package com.example.torchatv2.transport

import android.content.Context
import java.io.File
import java.util.concurrent.Executors

/**
 * Implementation of [OnionServiceManager] using local torrc configuration.
 */
class GuardianOnionServiceManager(
    private val context: Context,
    private val torDataDir: File = File(context.filesDir, "tor"),
    private val serviceDir: File = File(torDataDir, "hidden_service")
) : OnionServiceManager {
    private val executor = Executors.newSingleThreadExecutor()

    override fun startService() {
        if (!serviceDir.exists()) {
            serviceDir.mkdirs()
            // In a real environment, we'd set permissions: serviceDir.setReadable(false, false), etc.
        }
        
        // The actual service start is handled by Tor daemon reading the torrc.
        // We ensure the torrc contains the HiddenServiceDir and HiddenServicePort.
        updateTorrc()
    }

    override fun stopService() {
        // To stop, we would remove the lines from torrc and HUP tor.
        // For V1 Step 8A, we assume service stops when Tor stops.
    }

    override fun getLocalEndpoint(): OnionEndpoint? {
        val hostnameFile = File(serviceDir, "hostname")
        return if (hostnameFile.exists()) {
            OnionEndpoint(hostnameFile.readText().trim())
        } else {
            null
        }
    }

    private fun updateTorrc() {
        val torrc = File(torDataDir, "torrc")
        val serviceConfig = "HiddenServiceDir ${serviceDir.absolutePath}\nHiddenServicePort 80 127.0.0.1:8080\n"
        
        if (!torrc.exists()) {
            torrc.writeText(serviceConfig)
        } else {
            val content = torrc.readText()
            if (!content.contains("HiddenServiceDir")) {
                torrc.appendText(serviceConfig)
            }
        }
    }
}
