package io.github.amandhakar.passkey.webauthn

import org.junit.Assert.assertArrayEquals
import org.junit.Test

class CborWriterTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun integers() {
        assertArrayEquals(hex("0a"), CborWriter().int(10).toByteArray())
        assertArrayEquals(hex("1818"), CborWriter().int(24).toByteArray())
        assertArrayEquals(hex("1903e8"), CborWriter().int(1000).toByteArray())
        assertArrayEquals(hex("1a000f4240"), CborWriter().int(1_000_000).toByteArray())
        assertArrayEquals(hex("20"), CborWriter().int(-1).toByteArray())
        assertArrayEquals(hex("26"), CborWriter().int(-7).toByteArray())
        assertArrayEquals(hex("3863"), CborWriter().int(-100).toByteArray())
    }

    @Test fun strings() {
        assertArrayEquals(hex("6449455446"), CborWriter().text("IETF").toByteArray())
        assertArrayEquals(hex("4401020304"), CborWriter().bytes(hex("01020304")).toByteArray())
        assertArrayEquals(hex("a0"), CborWriter().map(0).toByteArray())
    }
}
