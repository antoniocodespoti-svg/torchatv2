package com.example.torchatv2.protocol

import com.example.torchatv2.crypto.*
import com.example.torchatv2.domain.Identity
import com.example.torchatv2.domain.PeerIdentity
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

sealed class HandshakeError : Exception() {
    object InvalidVersion : HandshakeError()
    object InvalidRole : HandshakeError()
    object InvalidMessageLength : HandshakeError()
    object InvalidIdentityBinding : HandshakeError()
    object InvalidSignature : HandshakeError()
    object CryptoFailure : HandshakeError()
    object InvalidState : HandshakeError()
}

data class HandshakeResult(
    val rootKey: ByteArray,
    val sessionId: ByteArray,
    val remotePeerIdentity: PeerIdentity,
    val initialRemoteRatchetKey: X25519PublicKey
)

private const val VERSION: Byte = 0x01
private const val ROLE_ALICE: Byte = 0x01
private const val ROLE_BOB: Byte = 0x02

private const val M1_LENGTH = 178
private const val M2_LENGTH = 242
private const val M3_LENGTH = 66

class HandshakeInitiator(
    private val identity: Identity,
    private val keyGenerator: CryptoKeyGenerator,
    private val signatureProvider: SignatureProvider,
    private val hkdfProvider: HkdfProvider,
    private val keyAgreement: KeyAgreementProvider
) {
    private enum class State { START, M1_SENT, M2_RECEIVED, ESTABLISHED, FAILED }
    private var state = State.START
    
    private var na: ByteArray? = null
    private var eka: X25519KeyPair? = null
    private var m1: ByteArray? = null
    private var result: HandshakeResult? = null

    fun start(): ByteArray {
        if (state != State.START) throw HandshakeError.InvalidState
        
        val random = SecureRandom()
        val na = ByteArray(16).also { random.nextBytes(it) }
        this.na = na
        
        val eka = keyGenerator.generateX25519KeyPair()
        this.eka = eka
        
        val m1 = ByteArray(M1_LENGTH)
        m1[0] = VERSION
        m1[1] = ROLE_ALICE
        System.arraycopy(na, 0, m1, 2, 16)
        System.arraycopy(eka.publicKey.copyBytes(), 0, m1, 18, 32)
        System.arraycopy(identity.ikPublic.copyBytes(), 0, m1, 50, 32)
        System.arraycopy(identity.skPublic.copyBytes(), 0, m1, 82, 32)
        System.arraycopy(identity.signature, 0, m1, 114, 64)
        
        this.m1 = m1
        state = State.M1_SENT
        return m1
    }

    fun processM2(m2: ByteArray): ByteArray {
        if (state != State.M1_SENT) throw HandshakeError.InvalidState
        if (m2.size != M2_LENGTH) { state = State.FAILED; throw HandshakeError.InvalidMessageLength }
        if (m2[0] != VERSION) { state = State.FAILED; throw HandshakeError.InvalidVersion }
        if (m2[1] != ROLE_BOB) { state = State.FAILED; throw HandshakeError.InvalidRole }

        try {
            val nb = m2.copyOfRange(2, 18)
            val ekbPub = X25519PublicKey(m2.copyOfRange(18, 50))
            val ikbPub = Ed25519PublicKey(m2.copyOfRange(50, 82))
            val skbPub = X25519PublicKey(m2.copyOfRange(82, 114))
            val idSigB = m2.copyOfRange(114, 178)
            val sigB = m2.copyOfRange(178, 242)

            val peer = PeerIdentity(ikbPub, skbPub, idSigB)
            if (!peer.verifyBinding(signatureProvider)) throw HandshakeError.InvalidIdentityBinding

            val m1 = this.m1!!
            val m2Pre = m2.copyOfRange(0, 178)
            
            val md = MessageDigest.getInstance("SHA-256")
            val th2 = md.digest(m1 + m2Pre)
            
            val sigBPayload = "TC-V1-Handshake-B".toByteArray(Charsets.UTF_8) + th2
            if (!signatureProvider.verify(ikbPub, sigBPayload, sigB)) throw HandshakeError.InvalidSignature

            // 3DH
            val dh1 = keyAgreement.calculateX25519SharedSecret(eka!!.privateKey, ekbPub)
            val dh2 = keyAgreement.calculateX25519SharedSecret(eka!!.privateKey, skbPub)
            val dh3 = keyAgreement.calculateX25519SharedSecret(identity.sk.privateKey, ekbPub)
            val ikm = dh1 + dh2 + dh3
            
            // KDF
            val handshakeSecret = hkdfProvider.extract(th2, ikm)
            
            // M3 preparation
            val m3Pre = byteArrayOf(VERSION, ROLE_ALICE)
            val th3Input = m1 + m2 + m3Pre
            val th3 = md.digest(th3Input)
            
            val sigAPayload = "TC-V1-Handshake-A".toByteArray(Charsets.UTF_8) + th3
            val sigA = signatureProvider.sign(identity.ik.privateKey, sigAPayload)
            
            val m3 = m3Pre + sigA
            val finalTh3 = md.digest(m1 + m2 + m3)

            val sessionSecret = hkdfProvider.expand(handshakeSecret, "TC-V1-SessionSecret".toByteArray(Charsets.UTF_8) + finalTh3, 32)
            val rootKey = hkdfProvider.expand(sessionSecret, "TC-V1-RootKey".toByteArray(Charsets.UTF_8), 32)
            val sessionId = hkdfProvider.expand(sessionSecret, "TC-V1-SessionID".toByteArray(Charsets.UTF_8), 16)

            this.result = HandshakeResult(rootKey, sessionId, peer, ekbPub)
            
            // Zeroization
            Arrays.fill(dh1, 0)
            Arrays.fill(dh2, 0)
            Arrays.fill(dh3, 0)
            Arrays.fill(ikm, 0)
            Arrays.fill(handshakeSecret, 0)
            Arrays.fill(sessionSecret, 0)

            state = State.ESTABLISHED
            return m3
        } catch (e: Exception) {
            state = State.FAILED
            if (e is HandshakeError) throw e
            throw HandshakeError.CryptoFailure
        }
    }

    fun getResult(): HandshakeResult {
        if (state != State.ESTABLISHED) throw HandshakeError.InvalidState
        return result!!
    }
}

class HandshakeResponder(
    private val identity: Identity,
    private val keyGenerator: CryptoKeyGenerator,
    private val signatureProvider: SignatureProvider,
    private val hkdfProvider: HkdfProvider,
    private val keyAgreement: KeyAgreementProvider
) {
    private enum class State { START, M1_RECEIVED, M2_SENT, ESTABLISHED, FAILED }
    private var state = State.START
    
    private var m1: ByteArray? = null
    private var m2: ByteArray? = null
    private var nb: ByteArray? = null
    private var ekb: X25519KeyPair? = null
    private var result: HandshakeResult? = null
    private var handshakeSecret: ByteArray? = null
    private var peer: PeerIdentity? = null
    private var ekaPub: X25519PublicKey? = null

    fun processM1(m1: ByteArray): ByteArray {
        if (state != State.START) throw HandshakeError.InvalidState
        if (m1.size != M1_LENGTH) { state = State.FAILED; throw HandshakeError.InvalidMessageLength }
        if (m1[0] != VERSION) { state = State.FAILED; throw HandshakeError.InvalidVersion }
        if (m1[1] != ROLE_ALICE) { state = State.FAILED; throw HandshakeError.InvalidRole }

        try {
            val na = m1.copyOfRange(2, 18)
            val ekaPub = X25519PublicKey(m1.copyOfRange(18, 50))
            val ikaPub = Ed25519PublicKey(m1.copyOfRange(50, 82))
            val skaPub = X25519PublicKey(m1.copyOfRange(82, 114))
            val idSigA = m1.copyOfRange(114, 178)
            
            val peer = PeerIdentity(ikaPub, skaPub, idSigA)
            if (!peer.verifyBinding(signatureProvider)) throw HandshakeError.InvalidIdentityBinding
            this.peer = peer
            this.ekaPub = ekaPub

            val random = SecureRandom()
            val nb = ByteArray(16).also { random.nextBytes(it) }
            this.nb = nb
            
            val ekb = keyGenerator.generateX25519KeyPair()
            this.ekb = ekb
            
            val m2Pre = ByteArray(M1_LENGTH) // M2_pre has same length as M1
            m2Pre[0] = VERSION
            m2Pre[1] = ROLE_BOB
            System.arraycopy(nb, 0, m2Pre, 2, 16)
            System.arraycopy(ekb.publicKey.copyBytes(), 0, m2Pre, 18, 32)
            System.arraycopy(identity.ikPublic.copyBytes(), 0, m2Pre, 50, 32)
            System.arraycopy(identity.skPublic.copyBytes(), 0, m2Pre, 82, 32)
            System.arraycopy(identity.signature, 0, m2Pre, 114, 64)
            
            val md = MessageDigest.getInstance("SHA-256")
            val th2 = md.digest(m1 + m2Pre)
            
            val sigBPayload = "TC-V1-Handshake-B".toByteArray(Charsets.UTF_8) + th2
            val sigB = signatureProvider.sign(identity.ik.privateKey, sigBPayload)
            
            val m2 = m2Pre + sigB
            this.m1 = m1
            this.m2 = m2
            
            // 3DH
            val dh1 = keyAgreement.calculateX25519SharedSecret(ekb.privateKey, ekaPub)
            val dh2 = keyAgreement.calculateX25519SharedSecret(identity.sk.privateKey, ekaPub)
            val dh3 = keyAgreement.calculateX25519SharedSecret(ekb.privateKey, skaPub)
            val ikm = dh1 + dh2 + dh3
            
            this.handshakeSecret = hkdfProvider.extract(th2, ikm)
            
            // Zeroization
            Arrays.fill(dh1, 0)
            Arrays.fill(dh2, 0)
            Arrays.fill(dh3, 0)
            Arrays.fill(ikm, 0)

            state = State.M2_SENT
            return m2
        } catch (e: Exception) {
            state = State.FAILED
            if (e is HandshakeError) throw e
            throw HandshakeError.CryptoFailure
        }
    }

    fun processM3(m3: ByteArray) {
        if (state != State.M2_SENT) throw HandshakeError.InvalidState
        if (m3.size != M3_LENGTH) { state = State.FAILED; throw HandshakeError.InvalidMessageLength }
        if (m3[0] != VERSION) { state = State.FAILED; throw HandshakeError.InvalidVersion }
        if (m3[1] != ROLE_ALICE) { state = State.FAILED; throw HandshakeError.InvalidRole }

        try {
            val sigA = m3.copyOfRange(2, 66)
            val m1 = this.m1!!
            val m2 = this.m2!!
            val m3Pre = m3.copyOfRange(0, 2)
            
            val md = MessageDigest.getInstance("SHA-256")
            val th3Payload = md.digest(m1 + m2 + m3Pre)
            
            val sigAPayload = "TC-V1-Handshake-A".toByteArray(Charsets.UTF_8) + th3Payload
            if (!signatureProvider.verify(peer!!.ikPublic, sigAPayload, sigA)) throw HandshakeError.InvalidSignature
            
            val finalTh3 = md.digest(m1 + m2 + m3)
            val sessionSecret = hkdfProvider.expand(handshakeSecret!!, "TC-V1-SessionSecret".toByteArray(Charsets.UTF_8) + finalTh3, 32)
            val rootKey = hkdfProvider.expand(sessionSecret, "TC-V1-RootKey".toByteArray(Charsets.UTF_8), 32)
            val sessionId = hkdfProvider.expand(sessionSecret, "TC-V1-SessionID".toByteArray(Charsets.UTF_8), 16)
            
            this.result = HandshakeResult(rootKey, sessionId, peer!!, ekaPub!!)
            
            // Zeroization
            Arrays.fill(handshakeSecret!!, 0)
            Arrays.fill(sessionSecret, 0)
            handshakeSecret = null

            state = State.ESTABLISHED
        } catch (e: Exception) {
            state = State.FAILED
            if (e is HandshakeError) throw e
            throw HandshakeError.CryptoFailure
        }
    }

    fun getResult(): HandshakeResult {
        if (state != State.ESTABLISHED) throw HandshakeError.InvalidState
        return result!!
    }
}
