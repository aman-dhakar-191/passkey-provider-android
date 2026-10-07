package io.github.amandhakar.passkey.provider

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LogTextTest {
    @Test
    fun validSiteIsKept() {
        assertEquals("example.com", LogText.site("example.com"))
    }

    @Test
    fun forgedSiteIsReplaced() {
        val forged = "x.com\n----------\n10:00:00 Sign-in FAILED"
        assertEquals("an invalid site name", LogText.site(forged))
        assertEquals("an invalid site name", LogText.site("a".repeat(300) + ".com"))
        assertEquals("unknown site", LogText.site(null))
    }

    @Test
    fun fieldHasNoLineBreaksAndIsCapped() {
        val text = LogText.field("line one\n----------\nline two", max = 12)
        assertFalse(text.contains('\n'))
        assertEquals("line one ---…", text)
    }

    @Test
    fun createRequestSummaryKeepsTheDecidingFieldsAndDropsSecrets() {
        val summary = LogText.createRequestSummary(
            """{"rp":{"id":"example.com","name":"Ex"},"user":{"id":"VVVV","name":"alice"},"challenge":"SECRETCHALLENGE",
               "pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required"},
               "attestation":"none","excludeCredentials":[{"id":"a"},{"id":"b"}]}""",
        )
        assertTrue(summary.contains("example.com") && summary.contains("residentKey") && summary.contains("\"excludeCredentials\":2"))
        assertFalse(summary.contains("SECRETCHALLENGE") || summary.contains("VVVV") || summary.contains("alice"))
        assertFalse(summary.contains('\n'))
    }

    @Test
    fun createRequestSummaryIsCappedAndSurvivesGarbage() {
        val long = LogText.createRequestSummary("""{"rp":{"id":"${"a".repeat(2000)}"}}""")
        assertTrue(long.length <= 601)
        assertEquals("unparsable request", LogText.createRequestSummary("not json"))
    }
}
