package io.github.amandhakar.passkey.webauthn

import java.util.Base64

object Base64Url {
    fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    /** Accepts base64url with or without padding, and tolerates standard base64 sent by sloppy RPs. */
    fun decode(value: String): ByteArray =
        Base64.getUrlDecoder().decode(value.trim().trimEnd('=').replace('+', '-').replace('/', '_'))
}
