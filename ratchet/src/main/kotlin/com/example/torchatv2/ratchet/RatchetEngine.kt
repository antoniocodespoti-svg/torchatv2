package com.example.torchatv2.ratchet

import com.example.torchatv2.crypto.*
import java.nio.ByteBuffer
import java.util.Arrays

class RatchetException(message: String) : Exception(message)

class RatchetEngine(
    private val sessionId: ByteArray,
    private val rootKey: ByteArray,
    private val localHandshakeKeyPair: X25519KeyPair,
    private val remoteHandshakePubKey: X25519PublicKey?,
    private val isInitiator: Boolean,
    private val keyGenerator: CryptoKeyGenerator,
    private val keyAgreement: KeyAgreementProvider,
    private val hkdfProvider: HkdfProvider,
    private val aeadProvider: AeadProvider
) {
    private val state: RatchetState
    private var isFailed = false
    private var isDestroyed = false

    init {
        val rk = rootKey.copyOf()
        if (isInitiator) {
            // Alice (Initiator)
            // initialRemoteRatchetKey is Bob's EKB
            val dhs = keyGenerator.generateX25519KeyPair()
            val shared = keyAgreement.calculateX25519SharedSecret(dhs.privateKey, remoteHandshakePubKey!!)
            
            val (rkNew, cks) = kdfRoot(rk, shared)
            Arrays.fill(shared, 0)
            
            state = RatchetState(
                rootKey = rkNew,
                dhs = dhs,
                dhr = remoteHandshakePubKey,
                cks = cks,
                ckr = null,
                ns = 0,
                nr = 0,
                pn = 0
            )
            Arrays.fill(rk, 0)
        } else {
            // Bob (Responder)
            // localHandshakeKeyPair is Bob's EKB
            state = RatchetState(
                rootKey = rk,
                dhs = localHandshakeKeyPair,
                dhr = null,
                cks = null,
                ckr = null,
                ns = 0,
                nr = 0,
                pn = 0
            )
        }
    }

    @Synchronized
    fun encrypt(plaintext: ByteArray): RatchetMessage {
        checkState()
        val cks = state.cks ?: throw RatchetException("Sending chain not initialized")
        
        val mk = kdfChain(cks, 0x01)
        state.cks = kdfChain(cks, 0x02)
        Arrays.fill(cks, 0)

        val header = RatchetHeader(
            sessionId = sessionId,
            ratchetPubKey = state.dhs.publicKey.copyBytes(),
            pn = state.pn,
            n = state.ns
        )

        try {
            val nonceBytes = createNonce(state.ns)
            val ad = createAD(header)
            
            // AEAD key is MK
            val aeadKey = AeadKey(mk)
            val nonce = Nonce(nonceBytes)
            
            val ciphertextWithTag = aeadProvider.encrypt(aeadKey, nonce, plaintext, ad)
            
            // ChaCha20Poly1305 in BC returns ciphertext + 16 byte tag
            val tagSize = 16
            val ciphertext = ciphertextWithTag.copyOfRange(0, ciphertextWithTag.size - tagSize)
            val authTag = ciphertextWithTag.copyOfRange(ciphertextWithTag.size - tagSize, ciphertextWithTag.size)
            
            state.ns++
            Arrays.fill(mk, 0)
            
            return RatchetMessage(header, ciphertext, authTag)
        } catch (e: Exception) {
            fail()
            throw RatchetException("Encryption failed: ${e.message}")
        }
    }

    @Synchronized
    fun decrypt(message: RatchetMessage): ByteArray {
        checkState()
        if (!message.header.sessionId.contentEquals(sessionId)) {
            throw RatchetException("SessionID mismatch")
        }

        try {
            // 1. Check skipped keys
            val mkIndex = MessageKeyIndex(ByteArrayKey(message.header.ratchetPubKey), message.header.n)
            val skippedMK = state.skippedKeys[mkIndex]
            if (skippedMK != null) {
                val plaintext = decryptWithKey(skippedMK.key, message)
                state.skippedKeys.remove(mkIndex)
                skippedMK.destroy()
                return plaintext
            }

            // 2. DH Ratchet?
            val isNewRatchetKey = state.dhr == null || !state.dhr!!.copyBytes().contentEquals(message.header.ratchetPubKey)
            if (isNewRatchetKey) {
                skipMessageKeys(message.header.pn)
                dhRatchet(X25519PublicKey(message.header.ratchetPubKey))
            }

            // 3. Normal chain advancement
            skipMessageKeys(message.header.n)
            val ckr = state.ckr!!
            val mk = kdfChain(ckr, 0x01)
            state.ckr = kdfChain(ckr, 0x02)
            Arrays.fill(ckr, 0)
            
            val plaintext = decryptWithKey(mk, message)
            state.nr++
            Arrays.fill(mk, 0)
            return plaintext
        } catch (e: Exception) {
            if (e is RatchetException) throw e
            fail()
            throw RatchetException("Decryption failed: ${e.message}")
        }
    }

    private fun decryptWithKey(mk: ByteArray, message: RatchetMessage): ByteArray {
        val aeadKey = AeadKey(mk)
        val nonce = Nonce(createNonce(message.header.n))
        val ad = createAD(message.header)
        val ciphertextWithTag = message.ciphertext + message.authTag
        
        return aeadProvider.decrypt(aeadKey, nonce, ciphertextWithTag, ad)
    }

    private fun skipMessageKeys(until: Int) {
        if (state.nr + 100 < until) {
            throw RatchetException("MAX_SKIP exceeded")
        }
        
        while (state.nr < until) {
            val ckr = state.ckr ?: throw RatchetException("Cannot skip without receiving chain")
            val mk = kdfChain(ckr, 0x01)
            val nextCkr = kdfChain(ckr, 0x02)
            Arrays.fill(ckr, 0)
            state.ckr = nextCkr
            
            val index = MessageKeyIndex(ByteArrayKey(state.dhr!!.copyBytes()), state.nr)
            state.skippedKeys[index] = SkippedMessageKey(mk)
            state.nr++
            
            if (state.skippedKeys.size > 100) {
                throw RatchetException("Too many skipped keys")
            }
        }
        // Cleanup expired
        val now = System.currentTimeMillis()
        val toRemove = state.skippedKeys.filter { now - it.value.createdAt > 60000 }.keys
        toRemove.forEach {
            state.skippedKeys[it]?.destroy()
            state.skippedKeys.remove(it)
        }
    }

    private fun dhRatchet(newRemotePub: X25519PublicKey) {
        state.pn = state.ns
        state.ns = 0
        state.nr = 0
        state.dhr = newRemotePub
        
        val shared1 = keyAgreement.calculateX25519SharedSecret(state.dhs.privateKey, state.dhr!!)
        val (rk1, ckr) = kdfRoot(state.rootKey, shared1)
        Arrays.fill(state.rootKey, 0)
        state.rootKey = rk1
        state.ckr = ckr
        Arrays.fill(shared1, 0)
        
        val newDhs = keyGenerator.generateX25519KeyPair()
        state.dhs.privateKey.destroy()
        state.dhs = newDhs
        
        val shared2 = keyAgreement.calculateX25519SharedSecret(state.dhs.privateKey, state.dhr!!)
        val (rk2, cks) = kdfRoot(state.rootKey, shared2)
        Arrays.fill(state.rootKey, 0)
        state.rootKey = rk2
        state.cks = cks
        Arrays.fill(shared2, 0)
    }

    private fun kdfRoot(rk: ByteArray, shared: ByteArray): Pair<ByteArray, ByteArray> {
        val prk = hkdfProvider.extract(rk, shared)
        val output = hkdfProvider.expand(prk, "TC-V1-DR-Root".toByteArray(Charsets.UTF_8), 64)
        Arrays.fill(prk, 0)
        
        val rkNew = output.copyOfRange(0, 32)
        val ckNew = output.copyOfRange(32, 64)
        Arrays.fill(output, 0)
        return rkNew to ckNew
    }

    private fun kdfChain(ck: ByteArray, label: Byte): ByteArray {
        // MK = extract(CK, 0x01), CK_next = extract(CK, 0x02)
        return hkdfProvider.extract(ck, byteArrayOf(label))
    }

    private fun createNonce(n: Int): ByteArray {
        val buffer = ByteBuffer.allocate(12)
        buffer.putInt(0) // 4 byte padding
        buffer.putLong(n.toLong()) // 8 byte counter (Big-Endian by default in ByteBuffer)
        return buffer.array()
    }

    private fun createAD(header: RatchetHeader): ByteArray {
        val buffer = ByteBuffer.allocate(58)
        buffer.put(0x01.toByte()) // Version
        buffer.put(0x02.toByte()) // MessageType Data
        buffer.put(header.sessionId) // 16
        buffer.put(header.ratchetPubKey) // 32
        buffer.putInt(header.pn) // 4
        buffer.putInt(header.n) // 4
        return buffer.array()
    }

    private fun checkState() {
        if (isDestroyed) throw RatchetException("Engine destroyed")
        if (isFailed) throw RatchetException("Session failed")
    }

    fun destroy() {
        if (isDestroyed) return
        state.destroy()
        isDestroyed = true
    }

    private fun fail() {
        isFailed = true
        destroy()
    }
}
