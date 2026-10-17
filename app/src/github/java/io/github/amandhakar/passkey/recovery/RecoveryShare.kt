package io.github.amandhakar.passkey.recovery

import io.github.amandhakar.securechannel.Hkdf
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * One piece of a backup's key, as held by a keeper (Google, a printed card, or someone's phone).
 *
 * [setId] names the backup the piece belongs to, [x] which piece it is. A piece alone tells nothing about the
 * key (see [Shamir]); any [THRESHOLD] pieces of the same set rebuild it.
 *
 * Written as text (on the card, and inside QR codes) as 88 letters and digits: version, set, x, the 32-byte
 * value and a 5-byte check that catches typos and mix-ups.
 */
internal class RecoveryShare(val setId: ByteArray, val x: Int, val y: ByteArray) {
    init {
        require(setId.size == SET_ID_SIZE) { "Invalid backup id" }
        require(x in 1..MAX_X) { "Invalid piece number" }
        require(y.size == SECRET_SIZE) { "Invalid piece" }
    }

    fun bytes(): ByteArray {
        val body = byteArrayOf(VERSION.toByte()) + setId + byteArrayOf(x.toByte()) + y
        return body + digest(body).copyOf(CHECK_SIZE)
    }

    /** For people: `PVS1-ABCD-EFGH-…`. */
    fun text(): String = TEXT_PREFIX + Base32.encode(bytes()).chunked(4).joinToString("-")

    /** For the card's QR code. */
    fun qr(): String = QR_PREFIX + Base32.encode(bytes())

    /**
     * The key a keeper proves it still has this piece with, by answering a [ShareCheck] challenge. The owner's
     * phone keeps only this, not the piece: it can't be turned back into the piece.
     */
    fun checkKey(): ByteArray =
        Hkdf.expand(Hkdf.extract(setId, y), "passkey-vault share check v1".toByteArray() + byteArrayOf(x.toByte()), 32)

    fun wipe() = y.fill(0)

    companion object {
        const val THRESHOLD = 2
        const val SECRET_SIZE = 32
        const val SET_ID_SIZE = 16
        /** x = 255 is kept on the owner's phone (with x = 0, the key) to make more pieces; never handed out. */
        const val MAX_X = 254
        const val OWNER_X = 255
        private const val VERSION = 1
        private const val CHECK_SIZE = 5
        private const val SIZE = 1 + SET_ID_SIZE + 1 + SECRET_SIZE + CHECK_SIZE
        const val TEXT_PREFIX = "PVS1-"
        const val QR_PREFIX = "passkeyvault-share:v1:"

        /** Reads a piece from typed text, a pasted message or a QR code. Throws IllegalArgumentException. */
        fun parse(text: String): RecoveryShare {
            val invalid = IllegalArgumentException("That isn't a valid backup piece. Check it for typos.")
            val trimmed = text.trim()
            val symbols = when {
                trimmed.startsWith(QR_PREFIX) -> trimmed.removePrefix(QR_PREFIX)
                else -> Base32.symbolsAfter(trimmed, TEXT_PREFIX, SIZE * 8 / 5) ?: Base32.clean(trimmed)
            }
            val bytes = Base32.decode(symbols) ?: throw invalid
            if (bytes.size != SIZE) throw invalid
            val body = bytes.copyOf(SIZE - CHECK_SIZE)
            if (!MessageDigest.isEqual(bytes.copyOfRange(SIZE - CHECK_SIZE, SIZE), digest(body).copyOf(CHECK_SIZE))) throw invalid
            if (body[0].toInt() != VERSION) throw IllegalArgumentException("This piece is from a newer Passkey Vault; update the app")
            val x = body[1 + SET_ID_SIZE].toInt() and 0xff
            if (x !in 1..MAX_X) throw invalid
            return RecoveryShare(body.copyOfRange(1, 1 + SET_ID_SIZE), x, body.copyOfRange(2 + SET_ID_SIZE, body.size))
        }

        /** Makes the pieces at [xs] from the owner's two stored points. */
        fun issue(setId: ByteArray, ownerPoints: List<Shamir.Point>, xs: List<Int>): List<RecoveryShare> =
            xs.map { RecoveryShare(setId, it, Shamir.interpolate(ownerPoints, it)) }

        /**
         * A new backup key and the two points the owner's phone keeps: x = 0 (the key itself) and [OWNER_X].
         */
        fun newOwnerPoints(random: SecureRandom = SecureRandom()): List<Shamir.Point> {
            val secret = ByteArray(SECRET_SIZE).also { random.nextBytes(it) }
            val ownerPoint = Shamir.split(secret, THRESHOLD, listOf(OWNER_X), random).single()
            return listOf(Shamir.Point(0, secret), ownerPoint)
        }

        /** Rebuilds the owner's two points from [THRESHOLD] pieces of one set. */
        fun combine(shares: List<RecoveryShare>): List<Shamir.Point> {
            require(shares.size == THRESHOLD) { "Needs exactly $THRESHOLD pieces" }
            require(shares.all { it.setId.contentEquals(shares[0].setId) }) { "These pieces belong to different backups" }
            require(shares.map { it.x }.toSet().size == shares.size) { "That's the same piece twice" }
            val points = shares.map { Shamir.Point(it.x, it.y) }
            return listOf(Shamir.Point(0, Shamir.interpolate(points, 0)), Shamir.Point(OWNER_X, Shamir.interpolate(points, OWNER_X)))
        }

        private fun digest(data: ByteArray) = MessageDigest.getInstance("SHA-256").digest(data)
    }
}

/**
 * Checking that a keeper still has its piece, without the piece travelling: the owner sends a challenge (any
 * messaging app will do), the keeper's Passkey Vault answers with a short code made from the piece, and the
 * owner's phone checks that code against the piece's [RecoveryShare.checkKey]. The challenge and the answer
 * are useless to anyone who sees them.
 */
internal object ShareCheck {
    private const val VERSION = 1
    private const val NONCE_SIZE = 12
    private const val CHALLENGE_SIZE = 1 + RecoveryShare.SET_ID_SIZE + 1 + NONCE_SIZE
    private const val ANSWER_SIZE = 5
    const val CHALLENGE_PREFIX = "PVC1-"
    const val ANSWER_PREFIX = "PVA1-"

    class Challenge(val setId: ByteArray, val x: Int, val nonce: ByteArray) {
        fun bytes(): ByteArray = byteArrayOf(VERSION.toByte()) + setId + byteArrayOf(x.toByte()) + nonce
        fun text(): String = CHALLENGE_PREFIX + Base32.encode(bytes()).chunked(4).joinToString("-")
    }

    fun newChallenge(setId: ByteArray, x: Int, random: SecureRandom = SecureRandom()) =
        Challenge(setId.copyOf(), x, ByteArray(NONCE_SIZE).also { random.nextBytes(it) })

    /** Finds a challenge in a pasted message. Throws IllegalArgumentException. */
    fun parseChallenge(message: String): Challenge {
        val invalid = IllegalArgumentException("No Passkey Vault check found in that text")
        val bytes = Base32.symbolsAfter(message, CHALLENGE_PREFIX, CHALLENGE_SIZE * 8 / 5)?.let { Base32.decode(it) } ?: throw invalid
        if (bytes.size != CHALLENGE_SIZE || bytes[0].toInt() != VERSION) throw invalid
        val x = bytes[1 + RecoveryShare.SET_ID_SIZE].toInt() and 0xff
        if (x !in 1..RecoveryShare.MAX_X) throw invalid
        return Challenge(
            bytes.copyOfRange(1, 1 + RecoveryShare.SET_ID_SIZE),
            x,
            bytes.copyOfRange(2 + RecoveryShare.SET_ID_SIZE, CHALLENGE_SIZE),
        )
    }

    /** The keeper's answer, `PVA1-ABCD-EFGH`. */
    fun answer(share: RecoveryShare, challenge: Challenge): String {
        require(share.setId.contentEquals(challenge.setId) && share.x == challenge.x) { "This check is for a different piece" }
        val key = share.checkKey()
        try {
            return ANSWER_PREFIX + Base32.encode(mac(key, challenge)).chunked(4).joinToString("-")
        } finally {
            key.fill(0)
        }
    }

    /** True if [message] contains the right answer to [challenge] for the piece whose check key is [checkKey]. */
    fun verify(checkKey: ByteArray, challenge: Challenge, message: String): Boolean {
        val symbols = Base32.symbolsAfter(message, ANSWER_PREFIX, ANSWER_SIZE * 8 / 5) ?: return false
        val given = Base32.decode(symbols) ?: return false
        return given.size == ANSWER_SIZE && MessageDigest.isEqual(given, mac(checkKey, challenge))
    }

    private fun mac(key: ByteArray, challenge: Challenge): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            update("passkey-vault check answer v1".toByteArray())
            doFinal(challenge.bytes())
        }.copyOf(ANSWER_SIZE)
}

/** Base32 without look-alike symbols (no 0, 1, I, O), for codes people read, type or paste. */
internal object Base32 {
    private const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    /** [data] must be a whole number of 5-bit symbols (its size a multiple of 5 bytes). */
    fun encode(data: ByteArray): String {
        require(data.size % 5 == 0) { "Length must be a multiple of 5 bytes" }
        val out = StringBuilder()
        var buffer = 0
        var bits = 0
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                out.append(ALPHABET[(buffer shr (bits - 5)) and 0x1f])
                bits -= 5
            }
        }
        return out.toString()
    }

    /** Null if a symbol isn't in the alphabet or the length doesn't make whole bytes. */
    fun decode(symbols: String): ByteArray? {
        if (symbols.isEmpty() || symbols.length % 8 != 0) return null
        val out = java.io.ByteArrayOutputStream()
        var buffer = 0
        var bits = 0
        for (symbol in symbols) {
            val value = ALPHABET.indexOf(symbol)
            if (value < 0) return null
            buffer = (buffer shl 5) or value
            bits += 5
            if (bits >= 8) {
                out.write((buffer shr (bits - 8)) and 0xff)
                bits -= 8
            }
        }
        return out.toByteArray()
    }

    /** Upper case, without spaces and dashes. */
    fun clean(text: String) = text.uppercase().filter { it != '-' && !it.isWhitespace() }

    /**
     * The first [count] symbols after [prefix] in a longer text (a pasted message), skipping dashes and spaces.
     * Case doesn't matter. Null if the prefix isn't there or another character comes first.
     */
    fun symbolsAfter(text: String, prefix: String, count: Int): String? {
        val upper = text.uppercase()
        val start = upper.indexOf(prefix.uppercase())
        if (start < 0) return null
        val out = StringBuilder()
        for (c in upper.substring(start + prefix.length)) {
            if (out.length == count) break
            when {
                c in ALPHABET -> out.append(c)
                c == '-' || c.isWhitespace() -> Unit
                else -> return null
            }
        }
        return if (out.length == count) out.toString() else null
    }
}
