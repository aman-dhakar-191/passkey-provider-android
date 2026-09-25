package io.github.amandhakar.passkey.webauthn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class WebAuthnEncodingTest {
    private val x = ByteArray(32) { 1 }
    private val y = ByteArray(32) { 2 }

    @Test fun coseKeyLayout() {
        val cose = WebAuthnEncoding.coseEs256PublicKey(x, y)
        assertEquals(77, cose.size)
        // map(5) 1:2 3:-7 -1:1 -2:bstr(32)
        assertArrayEquals(
            byteArrayOf(0xa5.toByte(), 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20),
            cose.copyOfRange(0, 10),
        )
        assertArrayEquals(x, cose.copyOfRange(10, 42))
        assertArrayEquals(byteArrayOf(0x22, 0x58, 0x20), cose.copyOfRange(42, 45))
        assertArrayEquals(y, cose.copyOfRange(45, 77))
    }

    @Test fun authenticatorDataWithoutAttestedData() {
        val data = WebAuthnEncoding.authenticatorData("example.com", 0x05, 0)
        assertEquals(37, data.size)
        assertArrayEquals(WebAuthnEncoding.sha256("example.com".toByteArray()), data.copyOfRange(0, 32))
        assertEquals(0x05, data[32].toInt())
        assertArrayEquals(ByteArray(4), data.copyOfRange(33, 37))
    }

    @Test fun authenticatorDataWithAttestedData() {
        val credId = ByteArray(32) { it.toByte() }
        val cose = WebAuthnEncoding.coseEs256PublicKey(x, y)
        val attested = WebAuthnEncoding.attestedCredentialData(credId, cose)
        val data = WebAuthnEncoding.authenticatorData("example.com", 0x05, 0, attested)
        assertEquals(37 + 16 + 2 + 32 + 77, data.size)
        assertEquals(0x45, data[32].toInt()) // UP | UV | AT
        assertArrayEquals(WebAuthnEncoding.AAGUID, data.copyOfRange(37, 53))
        assertArrayEquals(byteArrayOf(0, 32), data.copyOfRange(53, 55))
        assertArrayEquals(credId, data.copyOfRange(55, 87))
    }

    @Test fun noneAttestationObject() {
        val att = WebAuthnEncoding.noneAttestationObject(byteArrayOf(9))
        val expected = CborWriter().map(3).text("fmt").text("none").text("attStmt").map(0)
            .text("authData").bytes(byteArrayOf(9)).toByteArray()
        assertArrayEquals(expected, att)
        assertEquals(0xa3, att[0].toInt() and 0xff)
    }

    @Test fun unsignedFixedPadsAndStripsSignByte() {
        assertEquals(32, WebAuthnEncoding.unsignedFixed(BigInteger.ONE).size)
        val big = BigInteger(1, ByteArray(32) { 0xff.toByte() }) // toByteArray() gives 33 bytes
        assertArrayEquals(ByteArray(32) { 0xff.toByte() }, WebAuthnEncoding.unsignedFixed(big))
    }

    @Test fun clientDataJson() {
        val json = String(WebAuthnEncoding.clientDataJson("webauthn.get", byteArrayOf(1, 2, 3), "https://a.example"))
        assertEquals(
            "{\"type\":\"webauthn.get\",\"challenge\":\"AQID\",\"origin\":\"https://a.example\",\"crossOrigin\":false}",
            json,
        )
    }

    @Test fun base64Url() {
        val bytes = byteArrayOf(-5, -1, 0, 62)
        assertEquals("-_8APg", Base64Url.encode(bytes))
        assertArrayEquals(bytes, Base64Url.decode("-_8APg"))
        assertArrayEquals(bytes, Base64Url.decode("+/8APg=="))
    }

    @Test fun versions() {
        assertTrue(AppVersion.isNewer("v1.2.10", "1.2.9"))
        assertTrue(AppVersion.isNewer("2.0.0", "1.99.99"))
        assertFalse(AppVersion.isNewer("1.2.3", "1.2.3"))
        assertFalse(AppVersion.isNewer("1.2.3", "1.3.0-debug"))
        assertTrue(AppVersion.isNewer("0.2", "0.1.0-debug"))
    }
}
