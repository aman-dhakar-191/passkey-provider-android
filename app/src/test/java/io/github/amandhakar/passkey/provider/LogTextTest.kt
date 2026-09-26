package io.github.amandhakar.passkey.provider

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
}
