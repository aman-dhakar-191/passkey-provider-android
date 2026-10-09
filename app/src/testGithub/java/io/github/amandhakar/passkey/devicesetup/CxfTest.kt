package io.github.amandhakar.passkey.devicesetup

import io.github.amandhakar.passkey.webauthn.Base64Url
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CxfTest {
    private val site: (String) -> String = { it }

    // A stand-in for a PKCS#8 key: 36 bytes starting with an ASN.1 SEQUENCE tag, all zero after it. Built at
    // run time so no key-like literal sits in the source.
    private val fakeKey = Base64Url.encode(byteArrayOf(0x30) + ByteArray(35))

    private val delivered = """
        {"version":{"major":1,"minor":0},"exporterRpId":"exporter.example","exporterDisplayName":"Other",
         "timestamp":1760000000,
         "accounts":[{"id":"YWNj","username":"","email":"alice@example.com","collections":[],"items":[
           {"id":"aXRlbTE","title":"Example","credentials":[
             {"type":"passkey","credentialId":"Y3JlZA","rpId":"example.com","username":"alice",
              "userDisplayName":"Alice","userHandle":"dXNlcg","key":"$fakeKey"}]},
           {"id":"aXRlbTI","title":"Broken","credentials":[
             {"type":"passkey","credentialId":"Y3JlZA","rpId":"example.org","username":"bob","userDisplayName":"Bob","userHandle":"dXNlcg"}]},
           {"id":"aXRlbTM","title":"Login","credentials":[{"type":"basic-auth","username":{"value":"bob"},"password":{"value":"hunter2"}}]}
         ]}]}
    """.trimIndent()

    @Test fun emptyExportIsAValidCxfHeaderWithNoAccounts() {
        val header = JSONObject(Cxf.emptyExport("vault.example", "Passkey Vault", 1_760_000_000))
        assertEquals(1, header.getJSONObject("version").getInt("major"))
        assertEquals(0, header.getJSONObject("version").getInt("minor"))
        assertEquals("vault.example", header.getString("exporterRpId"))
        assertEquals("Passkey Vault", header.getString("exporterDisplayName"))
        assertEquals(1_760_000_000L, header.getLong("timestamp"))
        assertEquals(0, header.getJSONArray("accounts").length())
        assertEquals(0, Cxf.read(header.toString()).passkeys.size)
    }

    @Test fun readsPasskeysAndCountsOtherTypes() {
        val d = Cxf.read(delivered)
        assertEquals("1.0", d.version)
        assertEquals(1, d.accounts)
        assertEquals(3, d.items)
        assertEquals(mapOf("basic-auth" to 1), d.otherCredentials)
        assertEquals(2, d.passkeys.size)
        val complete = d.passkeys[0]
        assertEquals("example.com", complete.rpId)
        assertTrue(complete.keyLooksLikePkcs8)
        assertEquals(36, complete.keyBytes)
        assertTrue(complete.complete)
        val missingKey = d.passkeys[1]
        assertEquals(null, missingKey.keyBytes)
        assertFalse(missingKey.complete)
    }

    @Test fun outlineNeverContainsCredentialValues() {
        val text = Cxf.outline(delivered, site).joinToString("\n")
        for (secret in listOf("alice", "Alice", "bob", "hunter2", fakeKey, "dXNlcg", "Y3JlZA", "Example", "exporter.example")) {
            assertFalse("outline leaked '$secret'", text.contains(secret))
        }
        assertTrue(text.contains("$.version.major = 1"))
        assertTrue(text.contains("type = passkey"))
        assertTrue(text.contains("rpId = example.com"))
        assertTrue(text.contains("key = <private key, 48 chars, not logged>"))
    }

    @Test fun outlineRunsRpIdThroughTheSiteCheck() {
        val text = Cxf.outline(delivered, { "checked" }).joinToString("\n")
        assertFalse(text.contains("example.com"))
        assertTrue(text.contains("rpId = checked"))
    }

    @Test fun outlineIsCutWhenLong() {
        val lines = Cxf.outline(delivered, site, maxLines = 5)
        assertEquals("(outline cut at 5 lines)", lines.last())
    }

    @Test fun passkeyOutlineRedactsNamesAndExplainsTheMissingKey() {
        val outline = Cxf.passkeyOutline("example.com", 43, 22, "StrongBox")
        assertTrue(outline.contains("username: <redacted>"))
        assertTrue(outline.contains("key: <not available: StrongBox, non-exportable>"))
    }
}
