package io.github.amandhakar.passkeydemo

import org.json.JSONArray

data class Release(
    val version: String,
    val apkUrl: String,
    val apkSize: Long,
    val sha256: String?,
    val notes: String,
    val pageUrl: String,
)

/** "1.2.3" or "v1.2.3-debug" compared as numbers, so 1.10.0 is newer than 1.9.0. */
object AppVersion {
    fun parse(version: String): List<Int> =
        version.trim().removePrefix("v").substringBefore('-').split('.')
            .map { it.toIntOrNull() ?: 0 }
            .let { it + List(3) { 0 } }
            .take(3)

    fun isNewer(remote: String, local: String): Boolean {
        val r = parse(remote)
        val l = parse(local)
        for (i in 0 until 3) if (r[i] != l[i]) return r[i] > l[i]
        return false
    }
}

/**
 * Picks the demo app's newest release out of the repository's release list. The repository also holds the
 * Passkey Vault's own releases (tags v1.2.3), so only tags starting with [TAG_PREFIX] count, and the APK must
 * be one this repository's release page serves under that tag.
 */
object Releases {
    const val TAG_PREFIX = "demo-v"
    private val VERSION = Regex("^\\d{1,2}\\.\\d{1,2}\\.\\d{1,2}$")
    private val APK_NAME = Regex("^passkey-demo-\\d+\\.\\d+\\.\\d+\\.apk$")

    fun latest(json: String, repo: String): Release? {
        val releases = JSONArray(json)
        var best: Release? = null
        for (i in 0 until releases.length()) {
            val release = releases.optJSONObject(i) ?: continue
            if (release.optBoolean("draft")) continue
            val tag = release.optString("tag_name")
            if (!tag.startsWith(TAG_PREFIX)) continue
            val version = tag.removePrefix(TAG_PREFIX)
            if (!VERSION.matches(version)) continue
            val assets = release.optJSONArray("assets") ?: continue
            val downloadBase = "https://github.com/$repo/releases/download/$tag/"
            val apk = (0 until assets.length()).mapNotNull { assets.optJSONObject(it) }.firstOrNull {
                APK_NAME.matches(it.optString("name")) && it.optString("browser_download_url") == downloadBase + it.optString("name")
            } ?: continue
            if (best == null || AppVersion.isNewer(version, best.version)) {
                best = Release(
                    version = version,
                    apkUrl = apk.getString("browser_download_url"),
                    apkSize = apk.optLong("size"),
                    sha256 = apk.optString("digest").takeIf { it.startsWith("sha256:") }?.removePrefix("sha256:"),
                    notes = release.optString("body").takeIf { it != "null" }.orEmpty(),
                    pageUrl = release.optString("html_url"),
                )
            }
        }
        return best
    }
}
