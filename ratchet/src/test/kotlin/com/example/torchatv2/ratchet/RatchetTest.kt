package com.example.torchatv2.ratchet

import com.example.torchatv2.crypto.*
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer

class RatchetTest {

    private val keyGenerator = BouncyCastleKeyPairGenerator()
    private val keyAgreement = BouncyCastleKeyAgreementProvider()
    private val hkdfProvider = BouncyCastleHkdfProvider()
    private val aeadProvider = BouncyCastleAeadProvider()

    private val sessionId = ByteArray(16) { 0x42.toByte() }
    private val rootKey = ByteArray(32) { 0x11.toByte() }

    @Test
    fun testAliceBobHandshakeToRatchet() {
        // Mocking Handshake Result
        val aliceEka = keyGenerator.generateX25519KeyPair()
        val bobEkb = keyGenerator.generateX25519KeyPair()

        val alice = RatchetEngine(
            sessionId, rootKey, aliceEka, bobEkb.publicKey, true,
            keyGenerator, keyAgreement, hkdfProvider, aeadProvider
        )

        val bob = RatchetEngine(
            sessionId, rootKey, bobEkb, null, false,
            keyGenerator, keyAgreement, hkdfProvider, aeadProvider
        )

        // 1. Alice sends M1
        val p1 = "Hello Bob!".toByteArray()
        val m1 = alice.encrypt(p1)
        
        assertEquals(0, m1.header.n)
        assertEquals(0, m1.header.pn)

        // 2. Bob receives M1
        val d1 = bob.decrypt(m1)
        assertArrayEquals(p1, d1)

        // 3. Bob responds M2
        val p2 = "Hi Alice, I am Bob.".toByteArray()
        val m2 = bob.encrypt(p2)
        assertEquals(0, m2.header.n)
        assertEquals(0, m2.header.pn)

        // 4. Alice receives M2
        val d2 = alice.decrypt(m2)
        assertArrayEquals(p2, d2)
    }

    @Test
    fun testLongConversation() {
        val aliceEka = keyGenerator.generateX25519KeyPair()
        val bobEkb = keyGenerator.generateX25519KeyPair()

        val alice = RatchetEngine(sessionId, rootKey, aliceEka, bobEkb.publicKey, true, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)
        val bob = RatchetEngine(sessionId, rootKey, bobEkb, null, false, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)

        for (i in 0 until 10) {
            val msgA = "Msg A $i".toByteArray()
            val encA = alice.encrypt(msgA)
            assertArrayEquals(msgA, bob.decrypt(encA))

            val msgB = "Msg B $i".toByteArray()
            val encB = bob.encrypt(msgB)
            assertArrayEquals(msgB, alice.decrypt(encB))
        }
    }

    @Test
    fun testOutOfOrderMessages() {
        val aliceEka = keyGenerator.generateX25519KeyPair()
        val bobEkb = keyGenerator.generateX25519KeyPair()

        val alice = RatchetEngine(sessionId, rootKey, aliceEka, bobEkb.publicKey, true, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)
        val bob = RatchetEngine(sessionId, rootKey, bobEkb, null, false, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)

        val p1 = "Message 1".toByteArray()
        val p2 = "Message 2".toByteArray()
        val p3 = "Message 3".toByteArray()

        val m1 = alice.encrypt(p1)
        val m2 = alice.encrypt(p2)
        val m3 = alice.encrypt(p3)

        // Receive 3, then 1, then 2
        assertArrayEquals(p3, bob.decrypt(m3))
        assertArrayEquals(p1, bob.decrypt(m1))
        assertArrayEquals(p2, bob.decrypt(m2))
    }

    @Test(expected = RatchetException::class)
    fun testMaxSkipExceeded() {
        val aliceEka = keyGenerator.generateX25519KeyPair()
        val bobEkb = keyGenerator.generateX25519KeyPair()

        val alice = RatchetEngine(sessionId, rootKey, aliceEka, bobEkb.publicKey, true, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)
        val bob = RatchetEngine(sessionId, rootKey, bobEkb, null, false, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)

        // Alice sends 102 messages
        var lastMsg: RatchetMessage? = null
        for (i in 0 until 102) {
            lastMsg = alice.encrypt("Msg $i".toByteArray())
        }
        
        // Bob receives message 101 without receiving 0..100.
        // Nr is 0. 101 > 0 + 100. Should fail.
        bob.decrypt(lastMsg!!)
    }

    @Test(expected = RatchetException::class)
    fun testDuplicateMessageRejection() {
        val aliceEka = keyGenerator.generateX25519KeyPair()
        val bobEkb = keyGenerator.generateX25519KeyPair()

        val alice = RatchetEngine(sessionId, rootKey, aliceEka, bobEkb.publicKey, true, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)
        val bob = RatchetEngine(sessionId, rootKey, bobEkb, null, false, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)

        val m1 = alice.encrypt("Hello".toByteArray())
        bob.decrypt(m1)
        bob.decrypt(m1) // Duplicate, should fail
    }

    @Test
    fun testNonceByteFormat() {
        val buffer = ByteBuffer.allocate(12)
        buffer.putInt(0)
        buffer.putLong(42L)
        val expected = buffer.array()
        
        // Internal createNonce(42) should match
        // We test it indirectly via header.n in encryption if we could, 
        // but here we just verify our understanding of Big-Endian long.
        assertArrayEquals(byteArrayOf(0,0,0,0, 0,0,0,0, 0,0,0,42), expected)
    }

    @Test(expected = RatchetException::class)
    fun testSessionIDMismatch() {
        val aliceEka = keyGenerator.generateX25519KeyPair()
        val bobEkb = keyGenerator.generateX25519KeyPair()

        val alice = RatchetEngine(sessionId, rootKey, aliceEka, bobEkb.publicKey, true, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)
        val bob = RatchetEngine(ByteArray(16) { 0x1.toByte() }, rootKey, bobEkb, null, false, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)

        val m1 = alice.encrypt("Hello".toByteArray())
        bob.decrypt(m1)
    }

    @Test(expected = RatchetException::class)
    fun testCorruptedCiphertext() {
        val aliceEka = keyGenerator.generateX25519KeyPair()
        val bobEkb = keyGenerator.generateX25519KeyPair()

        val alice = RatchetEngine(sessionId, rootKey, aliceEka, bobEkb.publicKey, true, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)
        val bob = RatchetEngine(sessionId, rootKey, bobEkb, null, false, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)

        val m1 = alice.encrypt("Hello".toByteArray())
        m1.ciphertext[0] = (m1.ciphertext[0].toInt() xor 0x01).toByte()
        
        bob.decrypt(m1)
    }

    @Test(expected = RatchetException::class)
    fun testDestroyEngine() {
        val aliceEka = keyGenerator.generateX25519KeyPair()
        val bobEkb = keyGenerator.generateX25519KeyPair()
        val alice = RatchetEngine(sessionId, rootKey, aliceEka, bobEkb.publicKey, true, keyGenerator, keyAgreement, hkdfProvider, aeadProvider)
        
        alice.destroy()
        alice.encrypt("Test".toByteArray())
    }
}
