package io.github.amandhakar.passkey.webauthn

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class WebAuthnJsonTest {
    @Test fun parsesCreationOptions() {
        val o = CreationOptions.parse(
            """{"rp":{"id":"example.com","name":"Example"},
               "user":{"id":"AQID","name":"alice","displayName":"Alice"},
               "challenge":"BAUG","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
               "excludeCredentials":[{"type":"public-key","id":"BwgJ"}]}""",
        )
        assertEquals("example.com", o.rpId)
        assertEquals("Example", o.rpName)
        assertArrayEquals(byteArrayOf(1, 2, 3), o.userId)
        assertEquals("alice", o.userName)
        assertEquals(listOf(-7, -257), o.algorithms)
        assertArrayEquals(byteArrayOf(7, 8, 9), o.excludeCredentialIds.single())
    }

    @Test fun parsesAssertionOptionsWithoutRpId() {
        val o = AssertionOptions.parse("""{"challenge":"BAUG"}""")
        assertNull(o.rpId)
        assertEquals(0, o.allowCredentialIds.size)
    }

    @Test fun buildsAuthenticationResponse() {
        val json = JSONObject(
            WebAuthnJson.authenticationResponse(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(4), byteArrayOf(5)),
        )
        assertEquals("AQ", json.getString("id"))
        assertEquals("public-key", json.getString("type"))
        assertEquals("BQ", json.getJSONObject("response").getString("userHandle"))
    }
}
