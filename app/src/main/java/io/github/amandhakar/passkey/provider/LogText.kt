package io.github.amandhakar.passkey.provider

/**
 * Makes text that came from a calling app safe to put in the activity log: another app must not be able to
 * forge log entries (newlines, the entry separator) or flood the log with long text.
 */
object LogText {
    private const val MAX_FIELD = 120

    /** A site name as it may appear in the log: the RP ID if it is a valid domain, otherwise a placeholder. */
    fun site(rpId: String?): String = when {
        rpId == null -> "unknown site"
        rpId.length <= 253 && OriginRules.isValidDomain(rpId) -> rpId
        else -> "an invalid site name"
    }

    /** One line of caller text: control characters become spaces, and it is cut to [max] characters. */
    fun field(text: String?, max: Int = MAX_FIELD): String {
        val clean = text.orEmpty().map { if (it.isISOControl()) ' ' else it }.joinToString("").trim()
        return if (clean.length > max) clean.take(max) + "…" else clean
    }
}
