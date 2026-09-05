package com.example.torchatv2.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.security.SecureRandom
import java.util.Arrays

class BouncyCastleKeyPairGenerator(
    private val random: SecureRandom = SecureRandom()
) : CryptoKeyGenerator {

    override fun generateEd25519KeyPair(): Ed25519KeyPair {
        val seed = ByteArray(32)
        random.nextBytes(seed)
        return generateEd25519KeyPairFromSeed(seed)
    }

    override fun generateEd25519KeyPairFromSeed(seed: ByteArray): Ed25519KeyPair {
        val publicKey = ByteArray(32)
        Ed25519.generatePublicKey(seed, 0, publicKey, 0)
        return Ed25519KeyPair(Ed25519PrivateKey(seed), Ed25519PublicKey(publicKey))
    }

    override fun generateX25519KeyPair(): X25519KeyPair {
        val privateKey = ByteArray(32)
        random.nextBytes(privateKey)
        return generateX25519KeyPairFromSeed(privateKey)
    }

    override fun generateX25519KeyPairFromSeed(seed: ByteArray): X25519KeyPair {
        // X25519PrivateKeyParameters handles clamping and derivation correctly
        val privParams = X25519PrivateKeyParameters(seed, 0)
        val pubParams = privParams.generatePublicKey()
        return X25519KeyPair(X25519PrivateKey(seed), X25519PublicKey(pubParams.encoded))
    }
}

class BouncyCastleKeyAgreementProvider : KeyAgreementProvider {
    override fun calculateX25519SharedSecret(
        privateKey: X25519PrivateKey,
        publicKey: X25519PublicKey
    ): ByteArray {
        return try {
            val privParams = X25519PrivateKeyParameters(privateKey.copyBytes(), 0)
            val pubParams = X25519PublicKeyParameters(publicKey.copyBytes(), 0)

            val agreement = X25519Agreement()
            agreement.init(privParams)
            val secret = ByteArray(agreement.agreementSize)
            agreement.calculateAgreement(pubParams, secret, 0)

            if (isAllZero(secret)) {
                Arrays.fill(secret, 0.toByte())
                throw CryptoError.KeyAgreementError
            }
            secret
        } catch (e: Exception) {
            if (e is CryptoError) throw e
            throw CryptoError.KeyAgreementError
        }
    }

    private fun isAllZero(bytes: ByteArray): Boolean {
        for (b in bytes) { if (b != 0.toByte()) return false }
        return true
    }
}

class BouncyCastleSignatureProvider : SignatureProvider {
    override fun sign(privateKey: Ed25519PrivateKey, message: ByteArray): ByteArray {
        val signature = ByteArray(64)
        Ed25519.sign(privateKey.copyBytes(), 0, message, 0, message.size, signature, 0)
        return signature
    }

    override fun verify(
        publicKey: Ed25519PublicKey,
        message: ByteArray,
        signature: ByteArray
    ): Boolean {
        return try {
            Ed25519.verify(signature, 0, publicKey.copyBytes(), 0, message, 0, message.size)
        } catch (e: Exception) {
            false
        }
    }
}
