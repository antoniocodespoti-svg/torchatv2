package com.example.torchatv2.crypto

import org.bouncycastle.util.encoders.Hex
import org.junit.Assert.*
import org.junit.Test
import java.util.Arrays

/**
 * Milestone 2 - Final Frozen RFC Known Answer Tests (KAT).
 * Verified against IETF RFC 5869, 7748, 8032, 8439.
 */
class CryptoTest {

    private val keyGenerator = BouncyCastleKeyPairGenerator()
    private val keyAgreement = BouncyCastleKeyAgreementProvider()
    private val signatureProvider = BouncyCastleSignatureProvider()
    private val hkdfProvider = BouncyCastleHkdfProvider()
    private val aeadProvider = BouncyCastleAeadProvider()

    // --- RFC 5869: HKDF-SHA-256 (Test Case 1) ---
    @Test
    fun testRFC5869_HKDF_SHA256() {
        val ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = Hex.decode("000102030405060708090a0b0c")
        val info = Hex.decode("f0f1f2f3f4f5f6f7f8f9")
        val expectedPrk = Hex.decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        val expectedOkm = Hex.decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

        val actualPrk = hkdfProvider.extract(salt, ikm)
        assertArrayEquals("HKDF PRK mismatch", expectedPrk, actualPrk)

        val actualOkm = hkdfProvider.expand(actualPrk, info, 42)
        assertArrayEquals("HKDF OKM mismatch", expectedOkm, actualOkm)
    }

    // --- RFC 7748: X25519 Section 6.1 ---
    @Test
    fun testRFC7748_X25519() {
        val aliceScalar = Hex.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bobPublicU = Hex.decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b75975309bbac44e2413036")
        val expectedAlicePub = Hex.decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val expectedSharedSecret = Hex.decode("4a5d9d5ba4ce2de1728e3bf480350f25e07a21c4593c447e452d699765063f5e")

        // 1. Test Public Key Derivation
        val aliceKeyPair = keyGenerator.generateX25519KeyPairFromSeed(aliceScalar)
        assertArrayEquals("Public key mismatch", expectedAlicePub, aliceKeyPair.publicKey.copyBytes())

        // 2. Test Shared Secret (Alice uses Bob's public key)
        val actualSecret = keyAgreement.calculateX25519SharedSecret(
            X25519PrivateKey(aliceScalar),
            X25519PublicKey(bobPublicU)
        )
        assertArrayEquals("Shared secret mismatch", expectedSharedSecret, actualSecret)

        // 3. Test Symmetry (Bob's side)
        val bobScalar = Hex.decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val actualSecretBobSide = keyAgreement.calculateX25519SharedSecret(
            X25519PrivateKey(bobScalar),
            X25519PublicKey(expectedAlicePub)
        )
        assertArrayEquals("Shared secret symmetry mismatch", actualSecret, actualSecretBobSide)
    }

    @Test(expected = CryptoError.KeyAgreementError::class)
    fun testX25519_AllZeroRejection() {
        val priv = X25519PrivateKey(ByteArray(32) { 1 })
        val zeroPub = X25519PublicKey(ByteArray(32) { 0 })
        keyAgreement.calculateX25519SharedSecret(priv, zeroPub)
    }

    // --- RFC 8032: Ed25519 Test Case 1 ---
    @Test
    fun testRFC8032_Ed25519() {
        val seed = Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val expectedPub = Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        val expectedSig = Hex.decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        val message = ByteArray(0)

        val keyPair = keyGenerator.generateEd25519KeyPairFromSeed(seed)
        assertArrayEquals("Public key mismatch", expectedPub, keyPair.publicKey.copyBytes())

        val signature = signatureProvider.sign(Ed25519PrivateKey(seed), message)
        assertArrayEquals("Signature mismatch", expectedSig, signature)
        assertTrue("Verification failed", signatureProvider.verify(keyPair.publicKey, message, signature))
    }

    // --- RFC 8439: ChaCha20-Poly1305 Section 2.8.2 ---
    @Test
    fun testRFC8439_ChaCha20Poly1305() {
        val key = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = Hex.decode("070000004041424344454647")
        val aad = Hex.decode("50515253c0c1c2c3c4c5c6c7")
        val plaintext = Hex.decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
        
        // Full output should be ciphertext || 16-byte tag
        val expectedOutput = Hex.decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")

        val actual = aeadProvider.encrypt(AeadKey(key), Nonce(nonce), plaintext, aad)
        assertArrayEquals("Encryption output mismatch", expectedOutput, actual)

        val decrypted = aeadProvider.decrypt(AeadKey(key), Nonce(nonce), actual, aad)
        assertArrayEquals("Decryption mismatch", plaintext, decrypted)
    }

    @Test(expected = CryptoError.AuthenticationFailed::class)
    fun testAEAD_CorruptionRejection() {
        val key = AeadKey(ByteArray(32) { 1 })
        val nonce = Nonce(ByteArray(12) { 2 })
        val data = aeadProvider.encrypt(key, nonce, "test".toByteArray(), "aad".toByteArray())
        data[0] = (data[0].toInt() xor 0xFF).toByte()
        aeadProvider.decrypt(key, nonce, data, "aad".toByteArray())
    }

    // --- Lifecycle and Security Invariants ---
    @Test
    fun testKeyMaterial_Lifecycle() {
        val source = ByteArray(32) { 0xA.toByte() }
        val key = AeadKey(source)
        source[0] = 0.toByte()
        assertNotEquals("Immutability violated", 0.toByte(), key.copyBytes()[0])

        key.destroy()
        assertTrue("Destroy state not reflected", key.isDestroyed())
        try {
            key.copyBytes()
            org.junit.Assert.fail("Expected KeyDestroyed error")
        } catch (e: CryptoError.KeyDestroyed) { /* Pass */ }
    }
}
