package com.example.torchatv2.transport

import android.content.Context
import android.content.Intent
import net.freehaven.tor.control.TorControlConnection
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.Executors

/**
 * Implementation of [TorManager] using Guardian Project's TorService and jtorctl for bootstrap monitoring.
 */
class GuardianTorManager(
    private val context: Context
) : TorManager {
    private val state = AtomicReference<TorState>(TorState.Idle)
    private val executor = Executors.newSingleThreadExecutor()
    private val bootstrapExecutor = Executors.newSingleThreadExecutor()

    override fun start() {
        if (state.get() != TorState.Idle) return
        
        executor.execute {
            try {
                state.set(TorState.Bootstrapping(0))
                
                val intent = Intent()
                intent.setClassName("org.torproject.jni", "org.torproject.jni.TorService")
                intent.action = "org.torproject.jni.TorService.ACTION_START"
                context.startService(intent)
                
                // Start monitoring in a separate thread to avoid blocking the main executor
                monitorBootstrap()
            } catch (e: Exception) {
                state.set(TorState.Error(e))
            }
        }
    }

    private fun monitorBootstrap() {
        bootstrapExecutor.execute {
            val start = System.currentTimeMillis()
            val timeout = 90_000L
            var connected = false
            
            while (System.currentTimeMillis() - start < timeout) {
                if (state.get() == TorState.Idle) return@execute // Stop called

                try {
                    val socket = Socket("127.0.0.1", 9051)
                    val conn = TorControlConnection(socket)
                    conn.authenticate(ByteArray(0))
                    
                    connected = true
                    
                    // Polling bootstrap progress
                    while (System.currentTimeMillis() - start < timeout) {
                        val phase = conn.getInfo("status/bootstrap-phase") ?: ""
                        // NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"
                        val progress = extractProgress(phase)
                        state.set(TorState.Bootstrapping(progress))
                        
                        if (progress == 100) {
                            state.set(TorState.Ready)
                            socket.close()
                            return@execute
                        }
                        Thread.sleep(1000)
                    }
                } catch (e: Exception) {
                    // Port might not be open yet, retry
                    Thread.sleep(1000)
                }
            }
            
            if (!connected || state.get() != TorState.Ready) {
                state.set(TorState.Error(TimeoutException("Tor bootstrap timed out after 90s")))
                stop()
            }
        }
    }

    private fun extractProgress(msg: String): Int {
        val regex = "PROGRESS=(\\d+)".toRegex()
        val match = regex.find(msg)
        return match?.groupValues?.get(1)?.toInt() ?: 0
    }

    override fun stop() {
        val intent = Intent()
        intent.setClassName("org.torproject.jni", "org.torproject.jni.TorService")
        intent.action = "org.torproject.jni.TorService.ACTION_STOP"
        context.stopService(intent)
        
        state.set(TorState.Idle)
    }

    override fun getState(): TorState = state.get()
    
    private class TimeoutException(message: String) : Exception(message)
}
