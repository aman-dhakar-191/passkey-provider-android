package io.github.amandhakar.passkey.recovery

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class ShamirTest {
    private val random = SecureRandom()

    @Test
    fun `field arithmetic matches the AES field`() {
        // Worked example from FIPS-197 section 4.2: {57} x {83} = {c1}.
        assertEquals(0xc1, Shamir.mul(0x57, 0x83))
        for (a in 1..255) {
            assertEquals(1, Shamir.mul(a, Shamir.div(1, a)))
            for (b in listOf(1, 2, 3, 0x53, 0xca, 255)) assertEquals(a, Shamir.div(Shamir.mul(a, b), b))
        }
        assertEquals(0, Shamir.mul(0, 7))
    }

    @Test
    fun `any two of many pieces give back the secret`() {
        val secret = ByteArray(32).also { random.nextBytes(it) }
        val xs = listOf(1, 2, 3, 77, 200, 254, 255)
        val points = Shamir.split(secret, 2, xs, random)
        for (a in points) for (b in points) {
            if (a === b) continue
            assertArrayEquals(secret, Shamir.interpolate(listOf(a, b), 0))
            // ...and every other piece too.
            for (c in points) assertArrayEquals(c.y, Shamir.interpolate(listOf(a, b), c.x))
        }
    }

    @Test
    fun `three-of-five works the same way`() {
        val secret = ByteArray(32).also { random.nextBytes(it) }
        val points = Shamir.split(secret, 3, listOf(1, 2, 3, 4, 5), random)
        assertArrayEquals(secret, Shamir.interpolate(points.subList(0, 3), 0))
        assertArrayEquals(secret, Shamir.interpolate(listOf(points[4], points[1], points[2]), 0))
    }

    @Test
    fun `one piece says nothing about the secret`() {
        // For a fixed piece, every possible secret is equally consistent with it: for each candidate secret byte
        // there is exactly one second coefficient that produces the piece. Checked exhaustively for one byte.
        val x = 3
        val piece = 0x9a
        for (secret in 0..255) {
            val slopes = (0..255).count { a -> (secret xor Shamir.mul(a, x)) == piece }
            assertEquals(1, slopes)
        }
    }

    @Test
    fun `split is random and refuses bad input`() {
        val secret = ByteArray(32).also { random.nextBytes(it) }
        assertFalse(Shamir.split(secret, 2, listOf(1), random)[0].y.contentEquals(Shamir.split(secret, 2, listOf(1), random)[0].y))
        assertThrows(IllegalArgumentException::class.java) { Shamir.split(secret, 1, listOf(1), random) }
        assertThrows(IllegalArgumentException::class.java) { Shamir.split(secret, 2, listOf(0), random) }
        assertThrows(IllegalArgumentException::class.java) { Shamir.split(secret, 2, listOf(1, 1), random) }
        val p = Shamir.split(secret, 2, listOf(1, 2), random)
        assertThrows(IllegalArgumentException::class.java) { Shamir.interpolate(listOf(p[0], p[0]), 0) }
        assertThrows(IllegalArgumentException::class.java) { Shamir.interpolate(listOf(p[0], Shamir.Point(2, ByteArray(5))), 0) }
    }
}

class RecoveryShareTest {
    private val owner = RecoveryShare.newOwnerPoints()
    private val setId = ByteArray(16).also { SecureRandom().nextBytes(it) }
    private val shares = RecoveryShare.issue(setId, owner, listOf(1, 2, 3))

    @Test
    fun `any two pieces rebuild the owner's key and point`() {
        for (a in shares) for (b in shares) {
            if (a === b) continue
            val rebuilt = RecoveryShare.combine(listOf(a, b))
            assertEquals(0, rebuilt[0].x)
            assertArrayEquals(owner[0].y, rebuilt[0].y)
            assertArrayEquals(owner[1].y, rebuilt[1].y)
        }
        // The rebuilt points issue the same pieces as before, so keepers stay valid after a restore.
        val rebuilt = RecoveryShare.combine(listOf(shares[2], shares[0]))
        assertArrayEquals(shares[1].y, RecoveryShare.issue(setId, rebuilt, listOf(2))[0].y)
    }

    @Test
    fun `no piece equals the key, and pieces differ`() {
        shares.forEach { assertFalse(it.y.contentEquals(owner[0].y)) }
        assertFalse(shares[0].y.contentEquals(shares[1].y))
    }

    @Test
    fun `combine refuses mixed, repeated or too few pieces`() {
        val other = RecoveryShare.issue(ByteArray(16), RecoveryShare.newOwnerPoints(), listOf(2))[0]
        assertThrows(IllegalArgumentException::class.java) { RecoveryShare.combine(listOf(shares[0], other)) }
        assertThrows(IllegalArgumentException::class.java) { RecoveryShare.combine(listOf(shares[0], shares[0])) }
        assertThrows(IllegalArgumentException::class.java) { RecoveryShare.combine(listOf(shares[0])) }
    }

    @Test
    fun `a piece round-trips as text and as a QR code`() {
        val share = shares[1]
        val text = share.text()
        assertTrue(text, text.matches(Regex("PVS1-([A-Z2-9]{4}-){21}[A-Z2-9]{4}")))
        assertTrue(text.substring(5).none { it in "01IO" })
        for (form in listOf(text, share.qr(), text.lowercase(), text.removePrefix("PVS1-").replace('-', ' '), "Here it is: $text thanks")) {
            val parsed = RecoveryShare.parse(form)
            assertArrayEquals(form, share.setId, parsed.setId)
            assertEquals(form, share.x, parsed.x)
            assertArrayEquals(form, share.y, parsed.y)
        }
    }

    @Test
    fun `a typo in a piece is caught`() {
        val text = shares[0].text()
        for (i in 5 until text.length) {
            if (text[i] == '-') continue
            val other = if (text[i] == 'A') 'B' else 'A'
            val typo = text.substring(0, i) + other + text.substring(i + 1)
            assertThrows("char $i", IllegalArgumentException::class.java) { RecoveryShare.parse(typo) }
        }
        assertThrows(IllegalArgumentException::class.java) { RecoveryShare.parse("") }
        assertThrows(IllegalArgumentException::class.java) { RecoveryShare.parse(text.dropLast(1)) }
        assertThrows(IllegalArgumentException::class.java) { RecoveryShare.parse("passkeyvault-move:v1:whatever") }
    }

    @Test
    fun `a keeper with the piece passes the check`() {
        val share = shares[2]
        val challenge = ShareCheck.newChallenge(setId, share.x)
        val message = "Please check the backup piece you keep for me: ${challenge.text()} (from Passkey Vault)"
        val parsed = ShareCheck.parseChallenge(message)
        val answer = ShareCheck.answer(share, parsed)
        assertTrue(answer.matches(Regex("PVA1-[A-Z2-9]{4}-[A-Z2-9]{4}")))
        assertTrue(ShareCheck.verify(share.checkKey(), challenge, "My answer: $answer"))
        assertTrue(ShareCheck.verify(share.checkKey(), challenge, answer.lowercase()))
    }

    @Test
    fun `a wrong, old or other piece's answer fails the check`() {
        val share = shares[2]
        val challenge = ShareCheck.newChallenge(setId, share.x)
        val answer = ShareCheck.answer(share, challenge)
        // An answer to an earlier challenge can't be replayed.
        val next = ShareCheck.newChallenge(setId, share.x)
        assertFalse(ShareCheck.verify(share.checkKey(), next, answer))
        // Another piece's check key doesn't accept it.
        assertFalse(ShareCheck.verify(shares[1].checkKey(), challenge, answer))
        // Someone without the piece can't answer for it.
        val fake = RecoveryShare(setId, share.x, ByteArray(32))
        assertFalse(ShareCheck.verify(share.checkKey(), challenge, ShareCheck.answer(fake, challenge)))
        assertFalse(ShareCheck.verify(share.checkKey(), challenge, "nothing here"))
        assertFalse(ShareCheck.verify(share.checkKey(), challenge, "PVA1-AAAA-AAAA"))
        // A keeper refuses to answer a check meant for another piece.
        assertThrows(IllegalArgumentException::class.java) { ShareCheck.answer(shares[0], challenge) }
    }

    @Test
    fun `the check key does not reveal the piece and differs per piece`() {
        val keys = shares.map { it.checkKey() }
        shares.zip(keys).forEach { (s, k) -> assertFalse(k.contentEquals(s.y)) }
        assertNotEquals(keys[0].toList(), keys[1].toList())
    }

    @Test
    fun `challenges with junk are refused`() {
        for (junk in listOf("", "PVC1-", "PVC1-AAAA", "hello", "PVC1-" + "A".repeat(48))) {
            assertThrows(junk, IllegalArgumentException::class.java) { ShareCheck.parseChallenge(junk) }
        }
    }
}
