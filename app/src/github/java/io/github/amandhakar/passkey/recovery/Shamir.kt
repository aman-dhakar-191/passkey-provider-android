package io.github.amandhakar.passkey.recovery

import java.security.SecureRandom

/**
 * Shamir secret sharing over GF(2^8), byte by byte (the field AES uses, polynomial x^8 + x^4 + x^3 + x + 1).
 *
 * A secret is the value at x = 0 of a random polynomial of degree threshold - 1; each share is the value at
 * another x. Any `threshold` shares give back the polynomial, and with it the secret; fewer give no
 * information at all about it, whatever computing power is used.
 */
internal object Shamir {
    /** One value of the polynomial: [y] has one byte per byte of the secret. x is 0..255. */
    class Point(val x: Int, val y: ByteArray) {
        init {
            require(x in 0..255) { "x must be 0..255" }
        }
    }

    private val EXP = IntArray(510)
    private val LOG = IntArray(256)

    init {
        // 3 generates the multiplicative group of GF(2^8) with the AES polynomial.
        var value = 1
        for (i in 0 until 255) {
            EXP[i] = value
            LOG[value] = i
            val doubled = (value shl 1) xor (if (value and 0x80 != 0) 0x11B else 0)
            value = doubled xor value
        }
        for (i in 255 until 510) EXP[i] = EXP[i - 255]
    }

    fun mul(a: Int, b: Int): Int = if (a == 0 || b == 0) 0 else EXP[LOG[a] + LOG[b]]

    fun div(a: Int, b: Int): Int {
        require(b != 0) { "Division by zero" }
        return if (a == 0) 0 else EXP[LOG[a] + 255 - LOG[b]]
    }

    /**
     * Picks a random polynomial through ([secret] at x = 0) of degree [threshold] - 1 and returns its values
     * at [xs] (each 1..255, all different).
     */
    fun split(secret: ByteArray, threshold: Int, xs: List<Int>, random: SecureRandom = SecureRandom()): List<Point> {
        require(threshold in 2..255) { "Threshold must be 2..255" }
        require(xs.all { it in 1..255 } && xs.toSet().size == xs.size) { "x values must be different and 1..255" }
        val coefficients = Array(threshold) { i ->
            if (i == 0) secret.copyOf() else ByteArray(secret.size).also { random.nextBytes(it) }
        }
        try {
            return xs.map { x ->
                Point(
                    x,
                    ByteArray(secret.size) { b ->
                        // Horner's rule, highest coefficient first.
                        var acc = 0
                        for (i in threshold - 1 downTo 0) acc = mul(acc, x) xor (coefficients[i][b].toInt() and 0xff)
                        acc.toByte()
                    },
                )
            }
        } finally {
            coefficients.forEach { it.fill(0) }
        }
    }

    /**
     * The polynomial's value at [x], from exactly as many points as its threshold (Lagrange interpolation).
     * With x = 0 that is the secret; with another x, a new share of the same secret.
     */
    fun interpolate(points: List<Point>, x: Int): ByteArray {
        require(points.isNotEmpty()) { "No points" }
        require(points.map { it.x }.toSet().size == points.size) { "The same piece was given twice" }
        val size = points.first().y.size
        require(points.all { it.y.size == size }) { "The pieces don't belong together" }
        require(x in 0..255) { "x must be 0..255" }
        // Weight of each point at x: the product of (x - xm) / (xj - xm) over the other points (- is xor here).
        val weights = points.map { pj ->
            points.filter { it !== pj }.fold(1) { acc, pm -> mul(acc, div(x xor pm.x, pj.x xor pm.x)) }
        }
        return ByteArray(size) { b ->
            var acc = 0
            points.forEachIndexed { j, p -> acc = acc xor mul(weights[j], p.y[b].toInt() and 0xff) }
            acc.toByte()
        }
    }
}
