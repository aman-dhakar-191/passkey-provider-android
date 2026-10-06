package io.github.amandhakar.passkeydemo

import org.json.JSONArray

/** The site-side setup the provider checks before it lets an app use a site's passkeys. */
object AssetLinks {
    const val RELATION = "delegate_permission/common.get_login_creds"

    /** The statement a site must publish at /.well-known/assetlinks.json for this app (as written, not re-escaped). */
    fun statement(packageName: String, fingerprint: String): String = """
        {
          "relation": ["$RELATION"],
          "target": {
            "namespace": "android_app",
            "package_name": "$packageName",
            "sha256_cert_fingerprints": ["$fingerprint"]
          }
        }
    """.trimIndent()

    fun file(packageName: String, fingerprint: String): String = "[\n" + statement(packageName, fingerprint).prependIndent("  ") + "\n]\n"

    /** [status] is the HTTP status, or null if the request failed ([body] is then the error text). */
    fun analyze(status: Int?, body: String?, packageName: String, fingerprint: String): List<Check> {
        val checks = mutableListOf<Check>()
        checks += Check("assetlinks.json can be fetched over HTTPS (no redirect)", status == 200, if (status == 200) "HTTP 200" else "HTTP $status ${body.orEmpty()}".trim())
        if (status != 200 || body == null) return checks
        val array = runCatching { JSONArray(body) }.getOrNull()
        checks += Check("It is a JSON list", array != null)
        if (array == null) return checks
        var packageSeen = false
        var relationSeen = false
        var fingerprintSeen = false
        for (i in 0 until array.length()) {
            val statement = array.optJSONObject(i) ?: continue
            val target = statement.optJSONObject("target") ?: continue
            if (target.optString("namespace") != "android_app" || target.optString("package_name") != packageName) continue
            packageSeen = true
            val relations = statement.optJSONArray("relation") ?: continue
            if ((0 until relations.length()).none { relations.optString(it) == RELATION }) continue
            relationSeen = true
            val prints = target.optJSONArray("sha256_cert_fingerprints") ?: continue
            if ((0 until prints.length()).any { prints.optString(it).equals(fingerprint, ignoreCase = true) }) fingerprintSeen = true
        }
        checks += Check("A statement names this app's package ($packageName)", packageSeen)
        checks += Check("...with the get_login_creds relation", relationSeen, if (packageSeen && !relationSeen) "found the package, but not the relation $RELATION" else "")
        checks += Check("...and this app's signing certificate", fingerprintSeen, if (relationSeen && !fingerprintSeen) "found the package, but another certificate; expected $fingerprint" else "")
        return checks
    }
}
