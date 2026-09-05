package com.example.torchatv2.transport

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Implementation of [TransportConnection] for Tor streams via SOCKS5 proxy.
 */
class TorTransportConnection(
    private val host: String,
    private val port: Int,
    private val socksProxyHost: String?,
    private val socksProxyPort: Int?,
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
) : TransportConnection {
    private var listener: TransportListener? = null
    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    private val isClosed = AtomicBoolean(false)

    /**
     * Secondary constructor for accepted sockets from Onion Service.
     */
    constructor(acceptedSocket: Socket) : this("", 0, null, null) {
        this.socket = acceptedSocket
        this.inputStream = acceptedSocket.getInputStream()
        this.outputStream = acceptedSocket.getOutputStream()
    }

    @Synchronized
    fun connect() {
        if (isClosed.get()) return
        if (socket != null) return

        executor.execute {
            try {
                val proxy = if (socksProxyHost != null && socksProxyPort != null) {
                    Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksProxyHost, socksProxyPort))
                } else {
                    Proxy.NO_PROXY
                }

                val s = Socket(proxy)
                s.connect(InetSocketAddress(host, port), 30000) // 30s timeout
                
                synchronized(this) {
                    socket = s
                    inputStream = s.getInputStream()
                    outputStream = s.getOutputStream()
                }
                
                startReadLoop()
            } catch (e: Exception) {
                listener?.onError(e)
                close()
            }
        }
    }

    override fun send(data: ByteArray) {
        if (isClosed.get()) throw IllegalStateException("Connection closed")
        
        executor.execute {
            try {
                synchronized(this) {
                    outputStream?.write(data)
                    outputStream?.flush()
                }
            } catch (e: Exception) {
                listener?.onError(e)
                close()
            }
        }
    }

    override fun setListener(listener: TransportListener) {
        this.listener = listener
        // If we already have a socket (e.g. accepted), start read loop
        if (socket != null) {
            startReadLoop()
        }
    }

    override fun close() {
        if (isClosed.getAndSet(true)) return
        
        executor.execute {
            try {
                socket?.close()
            } catch (e: Exception) {
                // Ignore
            } finally {
                listener?.onDisconnected()
                executor.shutdown()
            }
        }
    }

    private fun startReadLoop() {
        executor.execute {
            val buffer = ByteArray(4096)
            try {
                while (!isClosed.get()) {
                    val read = inputStream?.read(buffer) ?: -1
                    if (read == -1) break
                    
                    val received = buffer.copyOfRange(0, read)
                    listener?.onDataReceived(received)
                }
            } catch (e: Exception) {
                if (!isClosed.get()) {
                    listener?.onError(e)
                }
            } finally {
                close()
            }
        }
    }
}
