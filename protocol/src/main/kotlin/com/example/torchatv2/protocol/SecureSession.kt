package com.example.torchatv2.protocol

import com.example.torchatv2.crypto.*
import com.example.torchatv2.domain.Identity
import com.example.torchatv2.domain.PeerIdentity
import com.example.torchatv2.ratchet.RatchetEngine
import java.util.Arrays

sealed class SessionEvent {
    data class HandshakeProduced(val data: ByteArray) : SessionEvent()
    data class PlaintextReceived(val data: ByteArray) : SessionEvent()
    data class StateChanged(val state: SessionState) : SessionEvent()
    data class Error(val throwable: Throwable) : SessionEvent()
}

enum class SessionState {
    NEGOTIATING,
    ESTABLISHED,
    FAILED,
    CLOSED
}

class SecureSession(
    private val localIdentity: Identity,
    private val keyGenerator: CryptoKeyGenerator,
    private val signatureProvider: SignatureProvider,
    private val hkdfProvider: HkdfProvider,
    private val keyAgreement: KeyAgreementProvider,
    private val aeadProvider: AeadProvider
) {
    private var state = SessionState.NEGOTIATING
    private var initiator: HandshakeInitiator? = null
    private var responder: HandshakeResponder? = null
    private var ratchetEngine: RatchetEngine? = null

    @Synchronized
    fun startInitiator(): SessionEvent {
        checkNotTerminal()
        if (initiator != null || responder != null) {
            return fail(IllegalStateException("Handshake already started"))
        }
        
        return try {
            initiator = HandshakeInitiator(localIdentity, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
            val m1 = initiator!!.start()
            SessionEvent.HandshakeProduced(m1)
        } catch (e: Exception) {
            fail(e)
        }
    }

    @Synchronized
    fun handleIncoming(data: ByteArray): List<SessionEvent> {
        checkNotTerminal()
        
        return when (state) {
            SessionState.NEGOTIATING -> handleHandshake(data)
            SessionState.ESTABLISHED -> handleData(data)
            else -> listOf(fail(IllegalStateException("Invalid session state: $state")))
        }
    }

    @Synchronized
    fun send(plaintext: ByteArray): ByteArray {
        if (state != SessionState.ESTABLISHED) {
            throw IllegalStateException("Session not established")
        }
        
        return try {
            val ratchetMsg = ratchetEngine!!.encrypt(plaintext)
            MessageCodec.encode(ratchetMsg)
        } catch (e: Exception) {
            fail(e)
            throw e
        }
    }

    private fun handleHandshake(data: ByteArray): List<SessionEvent> {
        return try {
            if (initiator != null) {
                // Alice processing M2
                val m3 = initiator!!.processM2(data)
                val result = initiator!!.getResult()
                initializeRatchet(result, isInitiator = true)
                listOf(
                    SessionEvent.HandshakeProduced(m3),
                    SessionEvent.StateChanged(SessionState.ESTABLISHED)
                )
            } else {
                // Bob or uninitialized responder
                if (responder == null) {
                    responder = HandshakeResponder(localIdentity, keyGenerator, signatureProvider, hkdfProvider, keyAgreement)
                    val m2 = responder!!.processM1(data)
                    listOf(SessionEvent.HandshakeProduced(m2))
                } else {
                    // Bob processing M3
                    responder!!.processM3(data)
                    val result = responder!!.getResult()
                    initializeRatchet(result, isInitiator = false)
                    listOf(SessionEvent.StateChanged(SessionState.ESTABLISHED))
                }
            }
        } catch (e: Exception) {
            listOf(fail(e))
        }
    }

    private fun handleData(data: ByteArray): List<SessionEvent> {
        return try {
            val ratchetMsg = MessageCodec.decode(data)
            val plaintext = ratchetEngine!!.decrypt(ratchetMsg)
            listOf(SessionEvent.PlaintextReceived(plaintext))
        } catch (e: Exception) {
            listOf(fail(e))
        }
    }

    private fun initializeRatchet(result: HandshakeResult, isInitiator: Boolean) {
        ratchetEngine = RatchetEngine(
            sessionId = result.sessionId,
            rootKey = result.rootKey,
            localHandshakeKeyPair = result.localHandshakeKeyPair,
            remoteHandshakePubKey = result.initialRemoteRatchetKey,
            isInitiator = isInitiator,
            keyGenerator = keyGenerator,
            keyAgreement = keyAgreement,
            hkdfProvider = hkdfProvider,
            aeadProvider = aeadProvider
        )
        // HandshakeResult data is now owned by RatchetEngine or no longer needed.
        // We zero the rootKey in result as a best-effort.
        Arrays.fill(result.rootKey, 0)
        
        state = SessionState.ESTABLISHED
        initiator = null
        responder = null
    }

    @Synchronized
    fun destroy() {
        if (state == SessionState.CLOSED || state == SessionState.FAILED) return
        
        ratchetEngine?.destroy()
        ratchetEngine = null
        initiator = null
        responder = null
        
        state = SessionState.CLOSED
    }

    private fun fail(e: Throwable): SessionEvent {
        state = SessionState.FAILED
        ratchetEngine?.destroy()
        ratchetEngine = null
        initiator = null
        responder = null
        return SessionEvent.Error(e)
    }

    private fun checkNotTerminal() {
        if (state == SessionState.FAILED) throw IllegalStateException("Session FAILED")
        if (state == SessionState.CLOSED) throw IllegalStateException("Session CLOSED")
    }

    fun getState(): SessionState = state
}
