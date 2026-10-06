package io.github.amandhakar.passkeydemo

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** The verifier is the demo's pass/fail judge, so it must accept good responses and catch each kind of bad one. */
class PasskeyVerifierTest {
    private val rpId = "demo.example.com"
    private val origin = "android:apk-key-hash:abc"
    private val challenge = ByteArray(32) { (it * 3).toByte() }
    private val credentialId = ByteArray(32) { (it + 50).toByte() }
    private val keys: KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val b64u = PasskeyVerifier::b64u

    private fun authData(rp: String = rpId, flags: Int = 0x05, attested: Boolean = false): ByteArray {
        val head = ByteBuffer.allocate(37).put(PasskeyVerifier.sha256(rp.toByteArray())).put(flags.toByte()).putInt(0).array()
        if (!attested) return head
        val aaguid = ByteArray(16)
        return head + aaguid + byteArrayOf(0, credentialId.size.toByte()) + credentialId + ByteArray(77)
    }

    private fun clientData(type: String, challenge: ByteArray = this.challenge, origin: String = this.origin) =
        """{"type":"$type","challenge":"${b64u(challenge)}","origin":"$origin","crossOrigin":false}""".toByteArray()

    private fun registration(
        authData: ByteArray = authData(flags = 0x45, attested = true),
        clientData: ByteArray = clientData("webauthn.create"),
        publicKey: ByteArray = keys.public.encoded,
    ) = JSONObject()
        .put("id", b64u(credentialId)).put("rawId", b64u(credentialId)).put("type", "public-key")
        .put(
            "response",
            JSONObject().put("clientDataJSON", b64u(clientData)).put("authenticatorData", b64u(authData))
                .put("publicKey", b64u(publicKey)),
        ).toString()

    private fun signIn(
        authData: ByteArray = authData(),
        clientData: ByteArray = clientData("webauthn.get"),
        signedClientData: ByteArray = clientData,
        signWith: KeyPair = keys,
    ): String {
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signWith.private); update(authData + PasskeyVerifier.sha256(signedClientData)); sign()
        }
        return JSONObject()
            .put("id", b64u(credentialId)).put("rawId", b64u(credentialId)).put("type", "public-key")
            .put(
                "response",
                JSONObject().put("clientDataJSON", b64u(clientData)).put("authenticatorData", b64u(authData))
                    .put("signature", b64u(signature)).put("userHandle", b64u(byteArrayOf(1, 2))),
            ).toString()
    }

    private fun failures(checks: List<Check>) = checks.filter { !it.ok }.map { it.name }

    @Test fun goodRegistrationPasses() {
        val result = PasskeyVerifier.verifyRegistration(rpId, challenge, registration(), origin)
        assertEquals(emptyList<String>(), failures(result.checks))
        assertEquals(b64u(credentialId), result.credentialId)
        assertNotNull(result.publicKey)
    }

    @Test fun goodSignInPasses() {
        val checks = PasskeyVerifier.verifySignIn(rpId, challenge, signIn(), origin) { keys.public.encoded }
        assertEquals(emptyList<String>(), failures(checks))
    }

    @Test fun anyOriginIsAcceptedAndReportedWhenNoneIsExpected() {
        val checks = PasskeyVerifier.verifySignIn(rpId, challenge, signIn(), null) { keys.public.encoded }
        assertEquals(emptyList<String>(), failures(checks))
        assertTrue(checks.any { it.detail == "origin: $origin" })
    }

    @Test fun signInIsRejectedWhenAnythingIsOff() {
        val key = { _: String -> keys.public.encoded }
        fun failed(json: String, expectedOrigin: String? = origin, challenge: ByteArray = this.challenge, rp: String = rpId, lookup: (String) -> ByteArray? = key) =
            failures(PasskeyVerifier.verifySignIn(rp, challenge, json, expectedOrigin, lookup))

        assertTrue("challenge", failed(signIn(), challenge = ByteArray(32)).any { it.startsWith("Challenge") })
        assertTrue("another site", failed(signIn(authData = authData(rp = "evil.com"))).any { it.startsWith("RP ID hash") })
        assertTrue("another origin", failed(signIn(), expectedOrigin = "android:apk-key-hash:other").any { it.startsWith("Origin") })
        assertTrue("wrong type", failed(signIn(clientData = clientData("webauthn.create"))).any { it.startsWith("clientDataJSON type") })
        assertTrue("no UV", failed(signIn(authData = authData(flags = 0x01))).any { it.startsWith("User verified") })
        assertTrue("no UP", failed(signIn(authData = authData(flags = 0x04))).any { it.startsWith("User present") })
        assertTrue("synced flag", failed(signIn(authData = authData(flags = 0x1d))).any { it.startsWith("Device-bound") })
        // The signature must cover the client data that was returned, and come from the registered key.
        assertTrue("signed other client data", failed(signIn(signedClientData = clientData("webauthn.get", ByteArray(32)))).any { it.startsWith("Signature") })
        val other = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        assertTrue("other key", failed(signIn(signWith = other)).any { it.startsWith("Signature") })
        assertTrue("unknown credential", failed(signIn(), lookup = { null }).any { it.startsWith("Passkey is known") })
    }

    @Test fun registrationIsRejectedWhenAnythingIsOff() {
        fun failed(json: String) = failures(PasskeyVerifier.verifyRegistration(rpId, challenge, json, origin).checks)
        assertTrue(failed(registration(authData = authData(flags = 0x05, attested = false))).any { it.startsWith("Authenticator data carries") })
        assertTrue(failed(registration(authData = authData(rp = "evil.com", flags = 0x45, attested = true))).any { it.startsWith("RP ID hash") })
        assertTrue(failed(registration(authData = authData(flags = 0x41, attested = true))).any { it.startsWith("User verified") })
        assertTrue(failed(registration(clientData = clientData("webauthn.create", ByteArray(32)))).any { it.startsWith("Challenge") })
        assertTrue(failed(registration(publicKey = ByteArray(10))).any { it.startsWith("Response could be read") })
    }

    @Test fun garbageIsReportedNotThrown() {
        for (json in listOf("", "not json", "{}", """{"response":{}}""")) {
            assertFalse(json, PasskeyVerifier.verifyRegistration(rpId, challenge, json, origin).ok)
            assertTrue(json, failures(PasskeyVerifier.verifySignIn(rpId, challenge, json, origin) { null }).isNotEmpty())
        }
    }

    @Test fun reportTextListsEachFailure() {
        val text = Report("Sign in", listOf(Check("a", true), Check("b", false, "why"))).toText()
        assertTrue(text.startsWith("Sign in: 1 of 2 checks FAILED"))
        assertTrue(text.contains("[FAIL] b") && text.contains("why") && text.contains("[ok] a"))
    }
}
