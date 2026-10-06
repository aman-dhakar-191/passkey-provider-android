package io.github.amandhakar.passkey.webauthn

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * Checks what the authenticator returns the way a relying party's server would (WebAuthn L3 §7), with its
 * own CBOR decoder instead of the app's encoder, so an encoding bug can't hide behind a matching decoder.
 * The responses are assembled exactly as Authenticator does, with a software P-256 key in place of the
 * Keystore one.
 */
class WebAuthnConformanceTest {
    private val rpId = "example.com"
    private val origin = "https://login.example.com"
    private val challenge = ByteArray(32) { (it * 7).toByte() }
    private val credentialId = ByteArray(32) { (it + 100).toByte() }
    private val userHandle = byteArrayOf(1, 2, 3, 4)
    private val keys: KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private fun sign(data: ByteArray) =
        Signature.getInstance("SHA256withECDSA").run { initSign(keys.private); update(data); sign() }

    private fun verify(data: ByteArray, signature: ByteArray) =
        Signature.getInstance("SHA256withECDSA").run { initVerify(keys.public); update(data); verify(signature) }

    private fun registrationResponse(): JSONObject {
        val publicKey = keys.public as ECPublicKey
        val cose = WebAuthnEncoding.coseEs256PublicKey(
            WebAuthnEncoding.unsignedFixed(publicKey.w.affineX),
            WebAuthnEncoding.unsignedFixed(publicKey.w.affineY),
        )
        val authData = WebAuthnEncoding.authenticatorData(
            rpId,
            WebAuthnEncoding.FLAG_USER_PRESENT or WebAuthnEncoding.FLAG_USER_VERIFIED,
            0,
            WebAuthnEncoding.attestedCredentialData(credentialId, cose),
        )
        return JSONObject(
            WebAuthnJson.registrationResponse(
                credentialId = credentialId,
                clientDataJson = WebAuthnEncoding.clientDataJson("webauthn.create", challenge, origin),
                attestationObject = WebAuthnEncoding.noneAttestationObject(authData),
                authenticatorData = authData,
                subjectPublicKeyInfo = publicKey.encoded,
            ),
        )
    }

    private fun authenticationResponse(): JSONObject {
        val authData = WebAuthnEncoding.authenticatorData(
            rpId,
            WebAuthnEncoding.FLAG_USER_PRESENT or WebAuthnEncoding.FLAG_USER_VERIFIED,
            0,
        )
        val clientData = WebAuthnEncoding.clientDataJson("webauthn.get", challenge, origin)
        return JSONObject(
            WebAuthnJson.authenticationResponse(
                credentialId = credentialId,
                clientDataJson = clientData,
                authenticatorData = authData,
                signature = sign(authData + WebAuthnEncoding.sha256(clientData)),
                userHandle = userHandle,
            ),
        )
    }

    /** §7.1 / §7.2 steps on clientDataJSON. */
    private fun checkClientData(encoded: String, type: String) {
        val clientData = JSONObject(String(Base64Url.decode(encoded), Charsets.UTF_8))
        assertEquals(type, clientData.getString("type"))
        assertEquals(Base64Url.encode(challenge), clientData.getString("challenge"))
        assertEquals(origin, clientData.getString("origin"))
        assertFalse(clientData.getBoolean("crossOrigin"))
    }

    /** Flags byte of authenticator data (§6.1). */
    private fun flags(authData: ByteArray) = authData[32].toInt() and 0xff

    @Test fun signInResponsePassesRelyingPartyChecks() {
        val json = authenticationResponse()
        val id = Base64Url.encode(credentialId)
        assertEquals(id, json.getString("id"))
        assertEquals(id, json.getString("rawId"))
        assertEquals("public-key", json.getString("type"))
        val response = json.getJSONObject("response")
        checkClientData(response.getString("clientDataJSON"), "webauthn.get")
        assertArrayEquals(userHandle, Base64Url.decode(response.getString("userHandle")))

        val authData = Base64Url.decode(response.getString("authenticatorData"))
        assertEquals("no attested data or extensions in a sign-in", 37, authData.size)
        assertArrayEquals(WebAuthnEncoding.sha256(rpId.toByteArray()), authData.copyOfRange(0, 32))
        val flags = flags(authData)
        assertTrue("UP", flags and 0x01 != 0)
        assertTrue("UV", flags and 0x04 != 0)
        assertEquals("BE/BS: device-bound, never backed up", 0, flags and 0x18)
        assertEquals("AT/ED", 0, flags and 0xc0)

        val clientData = Base64Url.decode(response.getString("clientDataJSON"))
        val signature = Base64Url.decode(response.getString("signature"))
        assertTrue(verify(authData + WebAuthnEncoding.sha256(clientData), signature))
        // The signature covers both parts: changing either must break it.
        val otherSite = authData.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(verify(otherSite + WebAuthnEncoding.sha256(clientData), signature))
        val otherChallenge = WebAuthnEncoding.clientDataJson("webauthn.get", ByteArray(32), origin)
        assertFalse(verify(authData + WebAuthnEncoding.sha256(otherChallenge), signature))
    }

    @Test fun registrationResponsePassesRelyingPartyChecks() {
        val json = registrationResponse()
        val id = Base64Url.encode(credentialId)
        assertEquals(id, json.getString("id"))
        assertEquals(id, json.getString("rawId"))
        assertEquals("public-key", json.getString("type"))
        val response = json.getJSONObject("response")
        checkClientData(response.getString("clientDataJSON"), "webauthn.create")

        // §7.1 steps 11-12: decode the attestation object; "none" has an empty statement.
        val attestation = CborReader(Base64Url.decode(response.getString("attestationObject"))).readFully() as Map<*, *>
        assertEquals(setOf("fmt", "attStmt", "authData"), attestation.keys)
        assertEquals("none", attestation["fmt"])
        assertEquals(emptyMap<Any, Any>(), attestation["attStmt"])
        val authData = attestation["authData"] as ByteArray
        assertArrayEquals(authData, Base64Url.decode(response.getString("authenticatorData")))

        assertArrayEquals(WebAuthnEncoding.sha256(rpId.toByteArray()), authData.copyOfRange(0, 32))
        val flags = flags(authData)
        assertEquals("UP | UV | AT, nothing else", 0x45, flags)
        assertArrayEquals(ByteArray(4), authData.copyOfRange(33, 37))

        // Attested credential data: AAGUID, length-prefixed credential ID, COSE key, and nothing after it.
        val input = DataInputStream(ByteArrayInputStream(authData, 37, authData.size - 37))
        val aaguid = ByteArray(16).also { input.readFully(it) }
        assertArrayEquals(WebAuthnEncoding.AAGUID, aaguid)
        val idLength = input.readUnsignedShort()
        assertArrayEquals(credentialId, ByteArray(idLength).also { input.readFully(it) })
        val coseBytes = input.readAllBytes()
        val reader = CborReader(coseBytes)
        val cose = reader.read() as Map<*, *>
        assertEquals("no bytes after the COSE key", coseBytes.size, reader.position)

        assertEquals(2L, cose[1L]) // kty EC2
        assertEquals(-7L, cose[3L]) // alg ES256
        assertEquals(1L, cose[-1L]) // crv P-256
        val publicKey = keys.public as ECPublicKey
        assertArrayEquals(WebAuthnEncoding.unsignedFixed(publicKey.w.affineX), cose[-2L] as ByteArray)
        assertArrayEquals(WebAuthnEncoding.unsignedFixed(publicKey.w.affineY), cose[-3L] as ByteArray)

        // The convenience fields (L3 §5.2.1) agree with the attestation object.
        assertEquals(-7, response.getInt("publicKeyAlgorithm"))
        val spki = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64Url.decode(response.getString("publicKey"))))
        assertEquals(keys.public, spki)
    }

    @Test fun originCannotInjectFieldsIntoClientData() {
        val hostile = listOf(
            "https://evil.com\",\"origin\":\"https://example.com",
            "https://evil.com\",\"type\":\"webauthn.create",
            "https://evil.com\\\",\"crossOrigin\":true,\"x\":\"",
            "https://evil.com\n\r\t\u0000\u001f",
            "https://evil.com  ",
            "https://exämple.com/😀",
        )
        for (origin in hostile) {
            val parsed = JSONObject(String(WebAuthnEncoding.clientDataJson("webauthn.get", challenge, origin), Charsets.UTF_8))
            assertEquals(setOf("type", "challenge", "origin", "crossOrigin"), parsed.keys().asSequence().toSet())
            assertEquals(origin, parsed.getString("origin"))
            assertEquals("webauthn.get", parsed.getString("type"))
            assertFalse(parsed.getBoolean("crossOrigin"))
        }
    }

    @Test fun hostileRequestsAreParsedSafely() {
        // Unusable allowCredentials entries are skipped, not trusted.
        val options = AssertionOptions.parse(
            """{"challenge":"AQID","rpId":"Example.COM","allowCredentials":[
                {"type":"public-key","id":"AQ"}, {"type":"public-key"}, {"id":null}, "x", null, {"id":"!!!"}]}""",
        )
        assertEquals("example.com", options.rpId)
        assertEquals(1, options.allowCredentialIds.size)
        // Required fields missing: parsing must fail rather than invent values.
        for (json in listOf(
            """{}""",
            """{"rpId":"example.com"}""",
            """not json""",
        )) {
            assertTrue(json, runCatching { AssertionOptions.parse(json) }.isFailure)
        }
        for (json in listOf(
            """{"rp":{"id":"example.com"},"user":{"name":"a"},"challenge":"AQID"}""", // no user.id
            """{"rp":{"id":"example.com"},"user":{"id":"AQ"}}""", // no challenge
            """{"user":{"id":"AQ"},"challenge":"AQID"}""", // no rp
        )) {
            assertTrue(json, runCatching { CreationOptions.parse(json) }.isFailure)
        }
        assertNull(CreationOptions.parse("""{"rp":{},"user":{"id":"AQ"},"challenge":"AQID"}""").rpId)
    }
}

/** Minimal CBOR decoder for the subset WebAuthn uses (RFC 8949: ints, byte/text strings, arrays, maps). */
private class CborReader(private val data: ByteArray) {
    var position = 0
        private set

    fun readFully(): Any = read().also { check(position == data.size) { "trailing bytes after CBOR item" } }

    fun read(): Any {
        val initial = next()
        val major = initial shr 5
        val length = argument(initial and 0x1f)
        return when (major) {
            0 -> length
            1 -> -1 - length
            2 -> bytes(length.toInt())
            3 -> String(bytes(length.toInt()), Charsets.UTF_8)
            4 -> List(length.toInt()) { read() }
            5 -> LinkedHashMap<Any, Any>().apply {
                repeat(length.toInt()) { val key = read(); check(put(key, read()) == null) { "duplicate key $key" } }
            }
            else -> error("unsupported CBOR major type $major")
        }
    }

    private fun next() = data[position++].toInt() and 0xff

    private fun argument(info: Int): Long = when {
        info < 24 -> info.toLong()
        info == 24 -> next().toLong()
        info == 25 -> ((next() shl 8) or next()).toLong()
        info == 26 -> (0 until 4).fold(0L) { acc, _ -> (acc shl 8) or next().toLong() }
        else -> error("unsupported CBOR length encoding $info")
    }

    private fun bytes(length: Int) = data.copyOfRange(position, position + length).also { position += length }
}
