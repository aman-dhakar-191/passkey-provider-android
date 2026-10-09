package io.github.amandhakar.passkey.devicesetup

import io.github.amandhakar.passkey.webauthn.Base64Url
import org.json.JSONArray
import org.json.JSONObject

/**
 * BETA. The FIDO Credential Exchange Format (CXF 1.0) as far as device setup needs it: an empty export
 * document, reading the passkeys in a document Android delivers, and a log-safe outline of any document.
 *
 * ## CXF mapping of a passkey
 *
 * A CXF document is a Header { version {major, minor}, exporterRpId, exporterDisplayName, timestamp,
 * accounts[] }. Each Account { id, username, email, collections[], items[] } holds Items
 * { id, title, credentials[], ... }, and a passkey is one entry in an Item's credentials:
 *
 * ```
 * { "type": "passkey",
 *   "credentialId": base64url(rawId),        ← our Passkey.credentialId (already base64url)
 *   "rpId": "example.com",                   ← Passkey.rpId
 *   "username": "alice",                     ← Passkey.userName
 *   "userDisplayName": "Alice",              ← Passkey.displayName
 *   "userHandle": base64url(user.id),        ← Passkey.userId (already base64url)
 *   "key": base64url(PKCS#8 DER private key) ← NOT AVAILABLE: see below
 *   "fido2Extensions": { ... } }             ← optional; we use none
 * ```
 *
 * `key` is required and must be the credential's private key as a PKCS#8 byte string. Passkey Vault
 * creates every private key inside the Android Keystore (StrongBox or the TEE) as non-exportable, so no
 * code, including ours, can ever read those bytes. That is why this beta always exports zero passkeys: a
 * passkey without its key would be a record the new phone could never sign in with, so sending it would
 * fake a migration.
 *
 * CXF also requires signature counters of 0 (exporters must exclude passkeys with a non-zero counter);
 * Passkey Vault always reports 0, so that rule is not what blocks export.
 *
 * Pure Kotlin and org.json only, so it is unit-tested on the JVM.
 */
object Cxf {
    const val TYPE_PASSKEY = "passkey"
    const val VERSION_MAJOR = 1
    const val VERSION_MINOR = 0

    /**
     * The document the old phone returns: a valid CXF header that holds no accounts, because no passkey can
     * be exported (see the class comment). [timestampSeconds] is UNIX time in seconds.
     */
    fun emptyExport(exporterRpId: String, exporterDisplayName: String, timestampSeconds: Long): String =
        JSONObject()
            .put("version", JSONObject().put("major", VERSION_MAJOR).put("minor", VERSION_MINOR))
            .put("exporterRpId", exporterRpId)
            .put("exporterDisplayName", exporterDisplayName)
            .put("timestamp", timestampSeconds)
            .put("accounts", JSONArray())
            .toString()

    /**
     * How one of our passkeys would map to a CXF passkey credential, for the log only. Identifying values are
     * replaced by their sizes and `key` says why it is missing; this is never sent anywhere.
     */
    fun passkeyOutline(rpSite: String, credentialIdLength: Int, userHandleLength: Int, keyStorage: String): String =
        "{type: passkey, rpId: $rpSite, credentialId: <$credentialIdLength chars>, username: <redacted>, " +
            "userDisplayName: <redacted>, userHandle: <$userHandleLength chars>, " +
            "key: <not available: $keyStorage, non-exportable>}"

    /** A passkey found in a delivered CXF document. Holds only sizes and flags, never the values. */
    data class IncomingPasskey(
        val rpId: String?,
        val hasCredentialId: Boolean,
        val hasUserHandle: Boolean,
        /** Decoded size of `key`, or null if it is missing or not base64url. */
        val keyBytes: Int?,
        /** True if `key` starts like a PKCS#8 DER structure (an ASN.1 SEQUENCE). */
        val keyLooksLikePkcs8: Boolean,
    ) {
        val complete: Boolean get() = rpId != null && hasCredentialId && hasUserHandle && keyLooksLikePkcs8
    }

    data class Delivered(val version: String, val accounts: Int, val items: Int, val passkeys: List<IncomingPasskey>, val otherCredentials: Map<String, Int>)

    /** Reads what Android delivered to the new phone. Throws [org.json.JSONException] if it is not a CXF header. */
    fun read(json: String): Delivered {
        val header = JSONObject(json)
        val version = header.optJSONObject("version")?.let { "${it.opt("major")}.${it.opt("minor")}" } ?: "missing"
        val accounts = header.getJSONArray("accounts")
        var items = 0
        val passkeys = mutableListOf<IncomingPasskey>()
        val others = sortedMapOf<String, Int>()
        for (a in 0 until accounts.length()) {
            val itemArray = accounts.getJSONObject(a).optJSONArray("items") ?: continue
            items += itemArray.length()
            for (i in 0 until itemArray.length()) {
                val credentials = itemArray.getJSONObject(i).optJSONArray("credentials") ?: continue
                for (c in 0 until credentials.length()) {
                    val credential = credentials.getJSONObject(c)
                    val type = credential.optString("type", "missing")
                    if (type == TYPE_PASSKEY) passkeys += readPasskey(credential) else others.merge(type, 1, Int::plus)
                }
            }
        }
        return Delivered(version, accounts.length(), items, passkeys, others)
    }

    private fun readPasskey(o: JSONObject): IncomingPasskey {
        val key = o.optString("key").takeIf { it.isNotEmpty() }?.let { runCatching { Base64Url.decode(it) }.getOrNull() }
        val result = IncomingPasskey(
            rpId = o.optString("rpId").takeIf { it.isNotEmpty() },
            hasCredentialId = o.optString("credentialId").isNotEmpty(),
            hasUserHandle = o.optString("userHandle").isNotEmpty(),
            keyBytes = key?.size,
            keyLooksLikePkcs8 = key != null && key.size > 2 && key[0] == 0x30.toByte(),
        )
        key?.fill(0)
        return result
    }

    // Values of these members are structural and safe to log as they are. Everything else is replaced by its size.
    private val SAFE_VALUES = setOf("type", "major", "minor", "timestamp", "creationAt", "modifiedAt", "hashAlg")

    /**
     * A log-safe outline of any CXF document: every member's path and type, with values only for [SAFE_VALUES].
     * Names, user handles, credential IDs, keys and passwords appear only as their length. `rpId` is shown
     * through [site], so it can be checked the same way the activity log checks site names.
     */
    fun outline(json: String, site: (String) -> String, maxLines: Int = 80): List<String> {
        val lines = mutableListOf<String>()
        fun walk(value: Any?, path: String) {
            if (lines.size >= maxLines) return
            when (value) {
                is JSONObject -> {
                    lines += "$path {${value.length()} members}"
                    value.keys().asSequence().sorted().forEach { walk(value.opt(it), "$path.$it") }
                }
                is JSONArray -> {
                    lines += "$path [${value.length()} entries]"
                    // Arrays of items can be long; the first few show the shape.
                    for (i in 0 until minOf(value.length(), 3)) walk(value.opt(i), "$path[$i]")
                    if (value.length() > 3) lines += "$path[3..] (${value.length() - 3} more, not shown)"
                }
                else -> {
                    val name = path.substringAfterLast('.')
                    lines += when {
                        name in SAFE_VALUES -> "$path = $value"
                        name == "rpId" -> "$path = ${site(value.toString())}"
                        name == "key" -> "$path = <private key, ${value.toString().length} chars, not logged>"
                        value is String -> "$path = <string, ${value.length} chars>"
                        else -> "$path = <${value?.javaClass?.simpleName ?: "null"}>"
                    }
                }
            }
        }
        walk(JSONObject(json), "$")
        if (lines.size >= maxLines) lines += "(outline cut at $maxLines lines)"
        return lines
    }
}
