package io.github.amandhakar.cryptolab.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class CryptoTest {

    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun `HKDF matches RFC 5869 test case 1`() {
        val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val prk = Hkdf.extract(salt, ikm)
        assertArrayEquals(hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk)
        assertArrayEquals(
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
            Hkdf.expand(prk, info, 42),
        )
    }

    @Test
    fun `every software suite works on the JVM`() {
        Suites.software.forEach { assertNull(it.label, it.supportProblem()) }
    }

    @Test
    fun `AEADs refuse changed ciphertext and associated data`() {
        for (aead in listOf(AesGcm, ChaCha20Poly1305)) {
            val key = ByteArray(aead.keySize) { 7 }
            val nonce = ByteArray(12) { 1 }
            val sealed = aead.seal(key, nonce, "aad".toByteArray(), "hello".toByteArray())
            assertArrayEquals("hello".toByteArray(), aead.open(key, nonce, "aad".toByteArray(), sealed))
            val flipped = sealed.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            assertThrows(Exception::class.java) { aead.open(key, nonce, "aad".toByteArray(), flipped) }
            assertThrows(Exception::class.java) { aead.open(key, nonce, "AAD".toByteArray(), sealed) }
        }
    }

    @Test
    fun `P-256 refuses a key from another curve`() {
        val other = java.security.KeyPairGenerator.getInstance("EC").run {
            initialize(java.security.spec.ECGenParameterSpec("secp384r1"))
            generateKeyPair()
        }
        assertThrows(SecurityException::class.java) { P256.decode(other.public.encoded) }
    }

    @Test
    fun `wire reader refuses truncated and trailing data`() {
        val msg = WireWriter().string("abc").u64(5).build()
        WireReader(msg).run {
            assertEquals("abc", string())
            assertEquals(5L, u64())
            end()
        }
        assertThrows(java.net.ProtocolException::class.java) { WireReader(msg.copyOf(msg.size - 1)).run { string(); u64() } }
        assertThrows(java.net.ProtocolException::class.java) { WireReader(msg + 0).run { string(); u64(); end() } }
    }
}
