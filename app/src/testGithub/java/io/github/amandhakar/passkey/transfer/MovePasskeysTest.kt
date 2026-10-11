package io.github.amandhakar.passkey.transfer

import io.github.amandhakar.passkey.data.Passkey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher

class MovePasskeysTest {
    private fun p256(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    private val rsa: KeyPair = KeyPairGenerator.getInstance("RSA").run {
        initialize(2048)
        generateKeyPair()
    }

    private fun rsaDecrypt(data: ByteArray): ByteArray = Cipher.getInstance(KeyWrap.RSA_TRANSFORMATION).run {
        init(Cipher.DECRYPT_MODE, rsa.private, KeyWrap.OAEP)
        doFinal(data)
    }

    private fun passkey(id: String) = Passkey(
        credentialId = id,
        rpId = "example.com",
        rpName = "Example",
        userId = "dXNlcg",
        userName = "alice",
        displayName = "Alice",
        createdAt = 1,
        lastUsedAt = 2,
        label = "Work",
        movable = true,
        backedUp = true,
        wrappedKey = "c2VjcmV0",
    )

    @Test
    fun `self-signed certificate holds the public key and verifies`() {
        val pair = p256()
        val cert = SelfSignedCertificate.create(pair.public, pair.private)
        assertArrayEquals(pair.public.encoded, cert.publicKey.encoded)
        cert.verify(pair.public)
        assertEquals("SHA256withECDSA", cert.sigAlgName)
    }

    @Test
    fun `wrapped key opens only with the right credential id and intact bytes`() {
        val secret = ByteArray(138) { it.toByte() }
        val aad = "credential-1".toByteArray()
        val blob = KeyWrap.wrap(rsa.public, secret, aad)
        assertArrayEquals(secret, KeyWrap.unwrap(blob, aad, ::rsaDecrypt))
        assertThrows(Exception::class.java) { KeyWrap.unwrap(blob, "credential-2".toByteArray(), ::rsaDecrypt) }
        val tampered = blob.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { KeyWrap.unwrap(tampered, aad, ::rsaDecrypt) }
    }

    @Test
    fun `wrapped key records which vault wrapped it, and both versions open`() {
        val aad = "credential-1".toByteArray()
        val v2 = KeyWrap.wrap(rsa.public, byteArrayOf(1, 2, 3), aad)
        assertEquals(KeyWrap.VAULT_V2, KeyWrap.vault(v2))
        val v1 = KeyWrap.wrap(rsa.public, byteArrayOf(4, 5), aad, vault = KeyWrap.VAULT_V1)
        assertEquals(KeyWrap.VAULT_V1, KeyWrap.vault(v1))
        assertArrayEquals(byteArrayOf(4, 5), KeyWrap.unwrap(v1, aad, ::rsaDecrypt))
        assertThrows(IllegalArgumentException::class.java) { KeyWrap.vault(byteArrayOf(9, 0, 0, 0)) }
    }

    @Test
    fun `payload round-trips and never carries this phone's wrapped copy`() {
        val pair = p256()
        val id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 bytes
        val bytes = TransferPayload.encode(listOf(MovingPasskey(passkey(id), pair.public.encoded, pair.private.encoded)))
        assertTrue(!String(bytes).contains("c2VjcmV0"))
        val decoded = TransferPayload.decode(bytes).single()
        assertEquals(id, decoded.passkey.credentialId)
        assertEquals("Work", decoded.passkey.label)
        assertEquals(2L, decoded.passkey.lastUsedAt)
        assertTrue(!decoded.passkey.movable && !decoded.passkey.backedUp && decoded.passkey.wrappedKey.isEmpty())
        val (publicKey, privateKey) = TransferPayload.keyPair(decoded)
        assertArrayEquals(pair.public.encoded, publicKey.encoded)
        assertArrayEquals(pair.private.encoded, privateKey.encoded)
    }

    @Test
    fun `payload refuses mismatched keys, other formats and bad sites`() {
        val id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        val mismatched = TransferPayload.decode(
            TransferPayload.encode(listOf(MovingPasskey(passkey(id), p256().public.encoded, p256().private.encoded))),
        ).single()
        assertThrows(IllegalArgumentException::class.java) { TransferPayload.keyPair(mismatched) }
        assertThrows(IllegalArgumentException::class.java) {
            TransferPayload.decode("""{"format":"something-else","version":1,"passkeys":[]}""".toByteArray())
        }
        val pair = p256()
        val badSite = TransferPayload.encode(
            listOf(MovingPasskey(passkey(id).copy(rpId = "192.168.1.1"), pair.public.encoded, pair.private.encoded)),
        )
        assertThrows(IllegalArgumentException::class.java) { TransferPayload.decode(badSite) }
    }
}
