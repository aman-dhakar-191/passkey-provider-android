package io.github.amandhakar.passkey.provider

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OriginRulesTest {
    @Test fun rpIdMayBeTheHostOrAParentDomain() {
        assertNull(OriginRules.browserOriginError("https://example.com", "example.com"))
        assertNull(OriginRules.browserOriginError("https://login.example.com", "example.com"))
        assertNull(OriginRules.browserOriginError("https://a.b.example.com:8443", "b.example.com"))
        assertNull(OriginRules.browserOriginError("https://LOGIN.Example.com", "example.com"))
    }

    @Test fun rpIdOfAnotherSiteIsRejected() {
        assertNotNull(OriginRules.browserOriginError("https://evil.com", "example.com"))
        // Suffix match must be on a label boundary.
        assertNotNull(OriginRules.browserOriginError("https://notexample.com", "example.com"))
        assertNotNull(OriginRules.browserOriginError("https://example.com.evil.com", "example.com"))
        // A subdomain RP ID is not allowed from the parent.
        assertNotNull(OriginRules.browserOriginError("https://example.com", "login.example.com"))
    }

    @Test fun insecureOriginsAreRejected() {
        assertNotNull(OriginRules.browserOriginError("http://example.com", "example.com"))
        assertNotNull(OriginRules.browserOriginError("ftp://example.com", "example.com"))
        assertNull(OriginRules.browserOriginError("http://localhost:3000", "localhost"))
        assertNotNull(OriginRules.browserOriginError("not a url", "example.com"))
    }

    @Test fun rpIdMustBeAPlainLowercaseDomain() {
        assertTrue(OriginRules.isValidDomain("example.com"))
        assertTrue(OriginRules.isValidDomain("inkarp--uat.sandbox.my.salesforce.com"))
        assertTrue(OriginRules.isValidDomain("localhost"))
        assertFalse(OriginRules.isValidDomain("com"))
        assertFalse(OriginRules.isValidDomain("Example.com"))
        assertFalse(OriginRules.isValidDomain("example.com/path"))
        assertFalse(OriginRules.isValidDomain("exa mple.com"))
        assertFalse(OriginRules.isValidDomain("-bad.com"))
        assertFalse(OriginRules.isValidDomain(""))
        assertNotNull(OriginRules.browserOriginError("https://example.com", "com"))
    }

    @Test fun hostOf() {
        assertEquals("login.example.com", OriginRules.hostOf("https://Login.Example.com:443/x"))
        assertNull(OriginRules.hostOf("android:apk-key-hash:abc"))
    }

    private val fp = "AA:BB:CC"
    private fun statement(relation: String = OriginRules.ASSET_LINKS_RELATION, pkg: String = "com.app", cert: String = fp) =
        """{"relation":["$relation"],"target":{"namespace":"android_app","package_name":"$pkg","sha256_cert_fingerprints":["$cert"]}}"""

    @Test fun assetLinksMustNameThePackageCertificateAndRelation() {
        assertTrue(OriginRules.assetLinksAllow("[${statement()}]", "com.app", fp))
        assertTrue(OriginRules.assetLinksAllow("[${statement(cert = "aa:bb:cc")}]", "com.app", fp))
        assertFalse(OriginRules.assetLinksAllow("[${statement()}]", "com.other", fp))
        assertFalse(OriginRules.assetLinksAllow("[${statement()}]", "com.app", "AA:BB:CD"))
        assertFalse(
            OriginRules.assetLinksAllow("[${statement(relation = "delegate_permission/common.handle_all_urls")}]", "com.app", fp),
        )
        assertFalse(OriginRules.assetLinksAllow("not json", "com.app", fp))
        assertFalse(OriginRules.assetLinksAllow("[]", "com.app", fp))
        // Any matching statement is enough.
        assertTrue(OriginRules.assetLinksAllow("[${statement(pkg = "x")},${statement()}]", "com.app", fp))
    }

    @Test fun fingerprintFormat() {
        assertEquals("0A:FF:00", OriginRules.fingerprint(byteArrayOf(0x0a, -1, 0)))
    }
}
