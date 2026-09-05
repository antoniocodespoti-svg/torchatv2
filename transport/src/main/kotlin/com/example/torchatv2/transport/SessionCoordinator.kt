package com.example.torchatv2.transport

import com.example.torchatv2.protocol.SecureSession
import com.example.torchatv2.protocol.SessionEvent
import com.example.torchatv2.protocol.SessionState

/**
 * Coordinates the interaction between [TransportConnection], [MessageFramer], and [SecureSession].
 * It manages the [FramingMode] transitions and propagates events.
 */
class SessionCoordinator(
    private val session: SecureSession,
    private val framer: MessageFramer,
    private val connection: TransportConnection,
    private val isInitiator: Boolean,
    private val onMessageReceived: (ByteArray) -> Unit,
    private val onStateChanged: (SessionState) -> Unit,
    private val onSessionError: (Throwable) -> Unit
) : TransportListener {

    init {
        connection.setListener(this)
        if (isInitiator) {
            framer.setMode(FramingMode.HANDSHAKE_M2)
        } else {
            framer.setMode(FramingMode.HANDSHAKE_M1)
        }
    }

    /**
     * Alice starts the handshake.
     */
    fun startHandshake() {
        if (!isInitiator) throw IllegalStateException("Only initiator can start handshake")
        try {
            val event = session.startInitiator()
            handleSessionEvent(event)
        } catch (e: Exception) {
            handleFailure(e)
        }
    }

    override fun onDataReceived(data: ByteArray) {
        try {
            val frames = framer.onBytesReceived(data)
            for (frame in frames) {
                val events = session.handleIncoming(frame)
                events.forEach { handleSessionEvent(it) }
            }
        } catch (e: Exception) {
            handleFailure(e)
        }
    }

    override fun onDisconnected() {
        session.destroy()
        onStateChanged(SessionState.CLOSED)
    }

    override fun onError(throwable: Throwable) {
        handleFailure(throwable)
    }

    /**
     * Sends encrypted data.
     */
    fun send(plaintext: ByteArray) {
        try {
            val encrypted = session.send(plaintext)
            connection.send(encrypted)
        } catch (e: Exception) {
            handleFailure(e)
        }
    }

    private fun handleSessionEvent(event: SessionEvent) {
        when (event) {
            is SessionEvent.HandshakeProduced -> {
                connection.send(event.data)
                // If Bob just sent M2, he now expects M3
                if (!isInitiator && session.getState() == SessionState.NEGOTIATING) {
                    framer.setMode(FramingMode.HANDSHAKE_M3)
                }
            }
            is SessionEvent.PlaintextReceived -> {
                onMessageReceived(event.data)
            }
            is SessionEvent.StateChanged -> {
                if (event.state == SessionState.ESTABLISHED) {
                    framer.setMode(FramingMode.DATA)
                }
                onStateChanged(event.state)
            }
            is SessionEvent.Error -> {
                handleFailure(event.throwable)
            }
        }
    }

    private fun handleFailure(e: Throwable) {
        onSessionError(e)
        session.destroy()
        connection.close()
    }
}
