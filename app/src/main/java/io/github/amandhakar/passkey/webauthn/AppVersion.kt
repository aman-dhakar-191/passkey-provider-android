package io.github.amandhakar.passkey.webauthn

/** Semantic version comparison used by the self-updater ("v1.2.3", "1.2.3-debug"). */
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
