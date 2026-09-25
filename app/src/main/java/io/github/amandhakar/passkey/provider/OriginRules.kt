package io.github.amandhakar.passkey.provider

import org.json.JSONArray
import java.net.URI

/**
 * The anti-phishing rules, free of Android types so they can be unit-tested:
 * which RP IDs a browser origin may use, and whether a site's assetlinks.json vouches for an app.
 */
object OriginRules {
    private val DOMAIN = Regex("^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
    const val ASSET_LINKS_RELATION = "delegate_permission/common.get_login_creds"

    /** A lowercase DNS name with at least two labels (or "localhost"). */
    fun isValidDomain(value: String) = DOMAIN.matches(value) && (value.contains('.') || value == "localhost")

    fun hostOf(origin: String): String? = runCatching { URI(origin).host?.lowercase() }.getOrNull()

    /**
     * Returns why a browser [origin] may not use [rpId], or null if it may. The RP ID must be the
     * origin's host or a parent domain of it, and the origin must be https (http only for localhost).
     * Browsers additionally reject public suffixes (e.g. "github.io") before the request reaches us.
     */
    fun browserOriginError(origin: String, rpId: String): String? {
        if (!isValidDomain(rpId)) return "Invalid RP ID: $rpId"
        val uri = runCatching { URI(origin) }.getOrNull() ?: return "Invalid origin: $origin"
        val host = uri.host?.lowercase() ?: return "Invalid origin: $origin"
        val secure = uri.scheme == "https" || (uri.scheme == "http" && host == "localhost")
        if (!secure) return "Passkeys need a secure origin, got $origin"
        if (host != rpId && !host.endsWith(".$rpId")) return "$origin may not use passkeys for $rpId"
        return null
    }

    /** SHA-256 certificate digest in assetlinks.json form: uppercase hex pairs separated by colons. */
    fun fingerprint(certSha256: ByteArray) = certSha256.joinToString(":") { "%02X".format(it) }

    /** True if the assetlinks.json [statements] let [packageName], signed with [fingerprint], use the site's passkeys. */
    fun assetLinksAllow(statements: String, packageName: String, fingerprint: String): Boolean {
        val array = runCatching { JSONArray(statements) }.getOrNull() ?: return false
        return (0 until array.length()).any { i ->
            val s = array.optJSONObject(i) ?: return@any false
            val relations = s.optJSONArray("relation") ?: return@any false
            val target = s.optJSONObject("target") ?: return@any false
            val fingerprints = target.optJSONArray("sha256_cert_fingerprints") ?: return@any false
            (0 until relations.length()).any { relations.optString(it) == ASSET_LINKS_RELATION } &&
                target.optString("namespace") == "android_app" &&
                target.optString("package_name") == packageName &&
                (0 until fingerprints.length()).any { fingerprints.optString(it).equals(fingerprint, ignoreCase = true) }
        }
    }
}
