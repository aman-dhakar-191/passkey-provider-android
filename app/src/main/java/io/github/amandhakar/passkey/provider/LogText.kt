package io.github.amandhakar.passkey.provider

import org.json.JSONObject

/**
 * Makes text that came from a calling app safe to put in the activity log: another app must not be able to
 * forge log entries (newlines, the entry separator) or flood the log with long text.
 */
object LogText {
    private const val MAX_FIELD = 120
    private const val SUMMARY_MAX = 600

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

    /**
     * The fields of a create request that decide whether a passkey can be made, as one safe log line: no
     * challenge or user id, and the caller's text is cleaned and capped like any other.
     */
    fun createRequestSummary(json: String): String = field(
        runCatching {
            val o = JSONObject(json)
            JSONObject()
                .put("rp", o.optJSONObject("rp"))
                .put("pubKeyCredParams", o.optJSONArray("pubKeyCredParams"))
                .put("authenticatorSelection", o.optJSONObject("authenticatorSelection"))
                .put("attestation", o.opt("attestation"))
                .put("excludeCredentials", o.optJSONArray("excludeCredentials")?.length() ?: 0)
                .put("extensions", o.optJSONObject("extensions"))
                .toString()
        }.getOrElse { "unparsable request" },
        max = SUMMARY_MAX,
    )
}
