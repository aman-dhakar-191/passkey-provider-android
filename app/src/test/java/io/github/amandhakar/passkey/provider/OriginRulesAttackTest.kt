package io.github.amandhakar.passkey.provider

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phishing attempts against the anti-phishing rules: a page or app trying to use another site's passkeys.
 * Every case here must be refused. (OriginRulesTest covers the rules working for legitimate callers.)
 */
class OriginRulesAttackTest {
    private fun refused(origin: String, rpId: String) =
        assertNotNull("$origin must not use passkeys for $rpId", OriginRules.browserOriginError(origin, rpId))

    @Test fun urlTricksDoNotChangeTheSite() {
        // Userinfo: the host is evil.com, whatever comes before the @.
        refused("https://example.com@evil.com", "example.com")
        refused("https://example.com:443@evil.com", "example.com")
        // The site's name in the path, query or fragment is not the host.
        refused("https://evil.com/example.com", "example.com")
        refused("https://evil.com?example.com", "example.com")
        refused("https://evil.com#.example.com", "example.com")
        // A backslash is not a valid URI character; must not be read as a path separator.
        refused("https://evil.com\\@example.com", "example.com")
        refused("https://evil.com\\.example.com", "example.com")
    }

    @Test fun lookalikeHostsAreRefused() {
        refused("https://example.com.evil.com", "example.com")
        refused("https://evilexample.com", "example.com")
        refused("https://example-com.evil.com", "example.com")
        refused("https://xexample.com", "example.com")
        // The page may not claim a sibling or child of its own site.
        refused("https://a.example.com", "b.example.com")
        refused("https://example.com", "a.example.com")
    }

    @Test fun publicSuffixesAndTopLevelDomainsAreRefused() {
        // A single label (a TLD) is never a valid RP ID; multi-label public suffixes such as github.io
        // are left to the browser, which rejects them before the request reaches us.
        refused("https://example.com", "com")
        refused("https://foo.co.uk", "uk")
        assertFalse(OriginRules.isValidDomain("com"))
    }

    @Test fun insecureSchemesAreRefused() {
        refused("http://example.com", "example.com")
        refused("ws://example.com", "example.com")
        refused("file://example.com/x", "example.com")
        refused("javascript://example.com", "example.com")
        refused("data:text/html,example.com", "example.com")
        refused("android:apk-key-hash:abc", "example.com")
        // http is only allowed for localhost itself, not hosts that end in localhost.
        refused("http://evil.localhost", "localhost")
        refused("http://localhost.evil.com", "localhost")
        refused("http://example.com", "localhost")
    }

    @Test fun malformedRpIdsAreRefused() {
        for (rpId in listOf(
            "Example.com", // uppercase: must be lowercased by the parser first
            "example.com.", // trailing dot
            ".example.com",
            "example..com",
            "example.com:443",
            "example.com/",
            "https://example.com",
            "*.example.com",
            "exa_mple.com",
            "bücher.example", // IDNs arrive as punycode
            "a".repeat(64) + ".com", // label over 63 characters
            "",
        )) {
            assertFalse("'$rpId' must be an invalid RP ID", OriginRules.isValidDomain(rpId))
            refused("https://example.com", rpId)
        }
        assertTrue(OriginRules.isValidDomain("xn--bcher-kva.example"))
    }

    @Test fun ipAddressesAreNotRpIds() {
        // WebAuthn RP IDs are domains. A numeric "parent" of an IP must never match.
        for (rpId in listOf("127.0.0.1", "0.1", "10.0.0.1", "192.168.1.1", "1.1")) {
            assertFalse("'$rpId' must be an invalid RP ID", OriginRules.isValidDomain(rpId))
        }
        refused("https://127.0.0.1", "127.0.0.1")
        refused("https://127.0.0.1", "0.1")
        refused("https://192.168.1.1", "168.1.1")
        // A numeric label that is not the last one is fine (e.g. 1password.com, 3m.com).
        assertNull(OriginRules.browserOriginError("https://my.1password.com", "1password.com"))
    }

    private val fp = "AA:BB:CC"
    private fun statement(
        relation: String = "\"${OriginRules.ASSET_LINKS_RELATION}\"",
        namespace: String = "android_app",
        pkg: String = "com.app",
        certs: String = "[\"$fp\"]",
    ) = """{"relation":[$relation],"target":{"namespace":"$namespace","package_name":"$pkg","sha256_cert_fingerprints":$certs}}"""

    private fun denied(statements: String) =
        assertFalse(statements, OriginRules.assetLinksAllow(statements, "com.app", fp))

    @Test fun assetLinksThatDoNotVouchForTheAppAreRefused() {
        // Web-site targets, other packages, other certificates, other relations.
        denied("[${statement(namespace = "web")}]")
        denied("[${statement(pkg = "COM.APP")}]")
        denied("[${statement(pkg = "com.app.evil")}]")
        denied("[${statement(certs = "[\"AA:BB:CC:DD\"]")}]")
        denied("[${statement(certs = "[\"AABBCC\"]")}]") // fingerprints must be colon-separated
        denied("[${statement(certs = "[]")}]")
        denied("[${statement(relation = "\"delegate_permission/common.handle_all_urls\"")}]")
        denied("[${statement(relation = "\"delegate_permission/common.get_login_creds.evil\"")}]")
        // Wrong JSON shapes must be refused, not crash.
        denied("[${statement(certs = "\"$fp\"")}]")
        denied("""[{"relation":"${OriginRules.ASSET_LINKS_RELATION}","target":{"namespace":"android_app","package_name":"com.app","sha256_cert_fingerprints":["$fp"]}}]""")
        denied(statement()) // an object, not an array
        denied("[null, 1, \"x\", []]")
        denied("")
        denied("<html>404</html>")
        // An "include" statement points at another file; it is not followed, so it vouches for nothing.
        denied("""[{"include":"https://evil.com/.well-known/assetlinks.json"}]""")
    }
}
