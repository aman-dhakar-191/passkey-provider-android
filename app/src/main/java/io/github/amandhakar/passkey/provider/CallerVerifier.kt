package io.github.amandhakar.passkey.provider

import android.content.Context
import android.content.pm.SigningInfo
import androidx.credentials.provider.CallingAppInfo
import io.github.amandhakar.passkey.webauthn.Base64Url
import io.github.amandhakar.passkey.webauthn.WebAuthnEncoding
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URI
import java.util.concurrent.ConcurrentHashMap

/**
 * Works out *who* is asking for a passkey and whether they are allowed to use the requested RP ID.
 * This is the anti-phishing core of the provider:
 *  - Browsers are trusted to report the web origin only if they are on Google's privileged-browser
 *    allowlist; the RP ID must then be the origin's host or a parent domain of it.
 *  - Native apps get an "android:apk-key-hash:" origin and must be vouched for by the RP's
 *    /.well-known/assetlinks.json (Digital Asset Links, relation get_login_creds).
 */
class CallerVerifier(private val context: Context) {

    fun resolveOrigin(info: CallingAppInfo): String {
        if (info.isOriginPopulated()) {
            val origin = try {
                info.getOrigin(PrivilegedApps.allowlist(context))
            } catch (e: IllegalArgumentException) {
                null
            } catch (e: IllegalStateException) {
                null
            }
            return origin?.trimEnd('/')
                ?: throw SecurityException("${info.packageName} is not a recognised browser")
        }
        return "android:apk-key-hash:" + Base64Url.encode(WebAuthnEncoding.sha256(currentCertificate(info.signingInfo)))
    }

    fun verifyRpId(info: CallingAppInfo, origin: String, rpId: String) {
        if (!isValidDomain(rpId)) throw SecurityException("Invalid RP ID: $rpId")
        if (origin.startsWith("android:apk-key-hash:")) {
            // The in-app self-test: only this app itself may use the reserved test RP ID, and it has no
            // website to publish assetlinks.json on. Other apps cannot run under this package name.
            if (rpId == SELF_TEST_RP_ID && info.packageName == context.packageName) return
            val fingerprint = WebAuthnEncoding.sha256(currentCertificate(info.signingInfo))
            if (!DigitalAssetLinks.verify(rpId, info.packageName, fingerprint)) {
                throw SecurityException("$rpId does not allow ${info.packageName} to use its passkeys")
            }
            return
        }
        val uri = URI(origin)
        val host = uri.host?.lowercase() ?: throw SecurityException("Invalid origin: $origin")
        val secure = uri.scheme == "https" || (uri.scheme == "http" && host == "localhost")
        if (!secure) throw SecurityException("Passkeys need a secure origin, got $origin")
        if (host != rpId && !host.endsWith(".$rpId")) {
            throw SecurityException("$origin may not use passkeys for $rpId")
        }
    }

    companion object {
        /** Reserved RP ID for the self-test (.invalid can never be a real domain, RFC 2606). */
        const val SELF_TEST_RP_ID = "selftest.passkey-provider.invalid"

        private val DOMAIN = Regex("^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")

        fun isValidDomain(value: String) = DOMAIN.matches(value) && (value.contains('.') || value == "localhost")

        fun hostOf(origin: String): String? = runCatching { URI(origin).host?.lowercase() }.getOrNull()

        private fun currentCertificate(signingInfo: SigningInfo): ByteArray {
            val certs = if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners
            else signingInfo.signingCertificateHistory
            val cert = if (signingInfo.hasMultipleSigners()) certs.firstOrNull() else certs.lastOrNull()
            return cert?.toByteArray() ?: throw SecurityException("Calling app has no signing certificate")
        }
    }
}

/** Google's list of browsers allowed to assert web origins to credential providers. */
internal object PrivilegedApps {
    private const val URL = "https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json"
    private const val MAX_AGE_MS = 24 * 60 * 60 * 1000L
    private const val BUNDLED_ASSET = "privileged_browsers.json"

    fun allowlist(context: Context): String {
        val cache = File(context.filesDir, "privileged_apps.json")
        if (!cache.exists() || System.currentTimeMillis() - cache.lastModified() > MAX_AGE_MS) {
            runCatching {
                val text = Http.getText(URL, followRedirects = true)
                JSONObject(text).getJSONArray("apps") // validate before caching
                cache.writeText(text)
            }
        }
        if (cache.exists()) return cache.readText()
        return runCatching { context.assets.open(BUNDLED_ASSET).bufferedReader().use { it.readText() } }
            .getOrElse { throw SecurityException("Browser allowlist unavailable; check your internet connection") }
    }
}

internal object DigitalAssetLinks {
    private const val RELATION = "delegate_permission/common.get_login_creds"
    private val cache = ConcurrentHashMap<String, Boolean>()

    fun verify(domain: String, packageName: String, certSha256: ByteArray): Boolean {
        val fingerprint = certSha256.joinToString(":") { "%02X".format(it) }
        val key = "$domain|$packageName|$fingerprint"
        cache[key]?.let { return it }
        val statements = JSONArray(Http.getText("https://$domain/.well-known/assetlinks.json"))
        val ok = (0 until statements.length()).any { i ->
            val s = statements.optJSONObject(i) ?: return@any false
            val relations = s.optJSONArray("relation") ?: return@any false
            val target = s.optJSONObject("target") ?: return@any false
            val fingerprints = target.optJSONArray("sha256_cert_fingerprints") ?: return@any false
            (0 until relations.length()).any { relations.optString(it) == RELATION } &&
                target.optString("namespace") == "android_app" &&
                target.optString("package_name") == packageName &&
                (0 until fingerprints.length()).any { fingerprints.optString(it).equals(fingerprint, ignoreCase = true) }
        }
        cache[key] = ok
        return ok
    }
}
