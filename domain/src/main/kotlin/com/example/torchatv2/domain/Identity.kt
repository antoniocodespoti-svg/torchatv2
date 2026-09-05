package com.example.torchatv2.domain

import com.example.torchatv2.crypto.*
import java.security.MessageDigest

/**
 * Represents a TorChatV2 Identity as defined in docs/PROTOCOL_SPEC.md.
 * An identity consists of an Ed25519 key pair for signing and a separate
 * X25519 key pair for key agreement.
 */
class Identity(
    val ik: Ed25519KeyPair,
    val sk: X25519KeyPair,
    val signature: ByteArray
) {
    val ikPublic: Ed25519PublicKey get() = ik.publicKey
    val skPublic: X25519PublicKey get() = sk.publicKey

    val fingerprint: ByteArray by lazy {
        val md = MessageDigest.getInstance("SHA-256")
        md.digest(ikPublic.copyBytes())
    }

    /**
     * Verifies that the X25519 static key belongs to this Ed25519 identity.
     */
    fun verifyBinding(signatureProvider: SignatureProvider): Boolean {
        val payload = createBindingPayload(ikPublic.copyBytes(), skPublic.copyBytes())
        return signatureProvider.verify(ikPublic, payload, signature)
    }

    companion object {
        private const val DOMAIN_SEPARATOR = "TC-V1-IdBinding"

        /**
         * Generates a new identity with a valid binding signature.
         */
        fun generate(
            keyGenerator: CryptoKeyGenerator,
            signatureProvider: SignatureProvider
        ): Identity {
            val ik = keyGenerator.generateEd25519KeyPair()
            val sk = keyGenerator.generateX25519KeyPair()
            
            val payload = createBindingPayload(ik.publicKey.copyBytes(), sk.publicKey.copyBytes())
            val signature = signatureProvider.sign(ik.privateKey, payload)
            
            return Identity(ik, sk, signature)
        }

        private fun createBindingPayload(ikPub: ByteArray, skPub: ByteArray): ByteArray {
            val separatorBytes = DOMAIN_SEPARATOR.toByteArray(Charsets.UTF_8)
            val payload = ByteArray(separatorBytes.size + ikPub.size + skPub.size)
            
            System.arraycopy(separatorBytes, 0, payload, 0, separatorBytes.size)
            System.arraycopy(ikPub, 0, payload, separatorBytes.size, ikPub.size)
            System.arraycopy(skPub, 0, payload, separatorBytes.size + ikPub.size, skPub.size)
            
            return payload
        }
    }
}

/**
 * Represents a remote peer's public identity information.
 */
data class PeerIdentity(
    val ikPublic: Ed25519PublicKey,
    val skPublic: X25519PublicKey,
    val signature: ByteArray
) {
    val fingerprint: ByteArray by lazy {
        val md = MessageDigest.getInstance("SHA-256")
        md.digest(ikPublic.copyBytes())
    }

    fun verifyBinding(signatureProvider: SignatureProvider): Boolean {
        val separatorBytes = "TC-V1-IdBinding".toByteArray(Charsets.UTF_8)
        val ikBytes = ikPublic.copyBytes()
        val skBytes = skPublic.copyBytes()
        
        val payload = ByteArray(separatorBytes.size + ikBytes.size + skBytes.size)
        System.arraycopy(separatorBytes, 0, payload, 0, separatorBytes.size)
        System.arraycopy(ikBytes, 0, payload, separatorBytes.size, ikBytes.size)
        System.arraycopy(skBytes, 0, payload, separatorBytes.size + ikBytes.size, skBytes.size)
        
        return signatureProvider.verify(ikPublic, payload, signature)
    }
}
