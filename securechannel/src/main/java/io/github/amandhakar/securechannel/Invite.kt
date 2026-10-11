package io.github.amandhakar.securechannel

import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64

/**
 * What the receiver's QR code holds: how to reach it and a one-time secret for the handshake.
 * Text form: `<prefix>?t=tcp&a=192.168.1.9:47800,10.0.0.5:47800&k=<base64url secret>`
 * (`t=bt` with `a=<Bluetooth device name>` for Bluetooth). Each app uses its own prefix, so a QR code meant
 * for one app is refused by another (Crypto Lab: [CRYPTO_LAB]).
 */
class Invite(
    val transport: String,
    /** TCP: host:port candidates, best first. Bluetooth: the receiver's device name. */
    val targets: List<String>,
    val secret: ByteArray,
) {
    init {
        require(transport == TCP || transport == BLUETOOTH) { "Unknown transport $transport" }
        require(targets.isNotEmpty()) { "No address" }
        require(secret.size == Handshake.QR_SECRET_SIZE) { "Bad secret" }
    }

    fun encode(prefix: String = CRYPTO_LAB): String =
        "$prefix?t=$transport&a=" + targets.joinToString(",") { URLEncoder.encode(it, "UTF-8") } +
            "&k=" + Base64.getUrlEncoder().withoutPadding().encodeToString(secret)

    companion object {
        const val TCP = "tcp"
        const val BLUETOOTH = "bt"
        const val CRYPTO_LAB = "cryptolab:v1"
        private const val MAX_LENGTH = 1024

        /** Parses a scanned QR code; throws IllegalArgumentException if it isn't an invite with [prefix]. */
        fun parse(text: String, prefix: String = CRYPTO_LAB): Invite {
            require(text.length <= MAX_LENGTH && text.startsWith("$prefix?")) { "Not the right kind of QR code" }
            val params = text.removePrefix("$prefix?").split('&').associate {
                it.substringBefore('=') to it.substringAfter('=', "")
            }
            val secret = runCatching { Base64.getUrlDecoder().decode(params["k"].orEmpty()) }.getOrNull()
                ?: throw IllegalArgumentException("Bad secret in the QR code")
            return Invite(
                transport = params["t"].orEmpty(),
                targets = params["a"].orEmpty().split(',').filter { it.isNotEmpty() }.map { URLDecoder.decode(it, "UTF-8") },
                secret = secret,
            )
        }
    }
}
