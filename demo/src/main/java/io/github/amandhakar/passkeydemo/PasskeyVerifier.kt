package io.github.amandhakar.passkeydemo

import org.json.JSONObject
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * One line of a test report: what was checked, whether it held, and why not (or what was seen).
 * [skipped]: the demo had no way to check it (not a failure, not a pass either).
 */
data class Check(val name: String, val ok: Boolean, val detail: String = "", val skipped: Boolean = false)

data class Report(val title: String, val checks: List<Check>, val note: String? = null) {
    val ok get() = checks.all { it.ok }

    /** "All 12 checks passed", "11 checks passed, 1 not checked" or "2 of 12 checks failed". */
    fun summary(): String {
        val failed = checks.count { !it.ok }
        val skipped = checks.count { it.skipped }
        return when {
            failed > 0 -> "$failed of ${checks.size} checks failed"
            skipped > 0 -> "${checks.size - skipped} checks passed, $skipped not checked"
            else -> "All ${checks.size} checks passed"
        }
    }

    fun toText(): String = buildString {
        append(title).append(": ")
        // Copied reports keep shouting failures, as before.
        append(if (ok) summary() else "${checks.count { !it.ok }} of ${checks.size} checks FAILED")
        for (c in checks) {
            append("\n  ").append(if (c.skipped) "[not checked] " else if (c.ok) "[ok] " else "[FAIL] ").append(c.name)
            if (c.detail.isNotBlank()) append("\n       ").append(c.detail)
        }
        note?.let { append("\n  ").append(it) }
    }
}

class Registration(val credentialId: String?, val publicKey: ByteArray?, val checks: List<Check>) {
    val ok get() = checks.all { it.ok }
}

/**
 * Plays the part of a website's server: checks what a passkey provider returned the way WebAuthn L3 §7
 * says a relying party must. A real server would remember the challenge it issued and the public key
 * from registration; this demo keeps both on the phone.
 */
object PasskeyVerifier {
    private const val FLAG_UP = 0x01
    private const val FLAG_UV = 0x04
    private const val FLAG_BE = 0x08
    private const val FLAG_BS = 0x10
    private const val FLAG_AT = 0x40

    fun b64u(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun unb64u(value: String): ByteArray =
        Base64.getUrlDecoder().decode(value.trim().trimEnd('=').replace('+', '-').replace('/', '_'))

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /**
     * [expectedOrigin] is what clientDataJSON must say (for a native app: its android:apk-key-hash: origin).
     * Null means "any, just report it" (a WebView decides the origin itself).
     */
    fun verifyRegistration(rpId: String, challenge: ByteArray, responseJson: String, expectedOrigin: String?): Registration {
        val checks = mutableListOf<Check>()
        try {
            val json = JSONObject(responseJson)
            val response = json.getJSONObject("response")
            val id = json.optString("id")
            checks += Check("Credential has an id and type public-key", id.isNotEmpty() && json.optString("type") == "public-key", "id: $id")
            checks += Check("id equals rawId", id == json.optString("rawId"))
            val clientData = unb64u(response.getString("clientDataJSON"))
            val authData = unb64u(response.getString("authenticatorData"))
            commonChecks(checks, "webauthn.create", rpId, challenge, expectedOrigin, clientData, authData)

            val hasAttested = authData.size > 37 && authData[32].toInt() and FLAG_AT != 0
            checks += Check("Authenticator data carries the new credential (AT flag)", hasAttested)
            if (hasAttested && authData.size >= 55) {
                val length = ((authData[53].toInt() and 0xff) shl 8) or (authData[54].toInt() and 0xff)
                val inData = if (authData.size >= 55 + length) authData.copyOfRange(55, 55 + length) else byteArrayOf()
                checks += Check("Credential id inside authenticator data equals the returned id", b64u(inData) == id)
            }
            val spki = response.optString("publicKey")
            var publicKey: ByteArray? = null
            if (spki.isEmpty()) {
                checks += Check("Response includes the public key", false, "no 'publicKey' field; a server would read the COSE key from the attestation object")
            } else {
                val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(unb64u(spki))) as ECPublicKey
                checks += Check("Public key is a P-256 (ES256) key", key.params.order.bitLength() == 256)
                publicKey = key.encoded
            }
            return Registration(id.takeIf { it.isNotEmpty() }, publicKey, checks)
        } catch (e: Exception) {
            checks += Check("Response could be read", false, "${e.javaClass.simpleName}: ${e.message}")
            return Registration(null, null, checks)
        }
    }

    /** [publicKeyFor] returns the stored SPKI public key for a credential id, or null if unknown. */
    fun verifySignIn(
        rpId: String,
        challenge: ByteArray,
        responseJson: String,
        expectedOrigin: String?,
        publicKeyFor: (String) -> ByteArray?,
    ): List<Check> {
        val checks = mutableListOf<Check>()
        try {
            val json = JSONObject(responseJson)
            val response = json.getJSONObject("response")
            val id = json.optString("id")
            checks += Check("Credential has an id and type public-key", id.isNotEmpty() && json.optString("type") == "public-key", "id: $id")
            checks += Check("id equals rawId", id == json.optString("rawId"))
            val clientData = unb64u(response.getString("clientDataJSON"))
            val authData = unb64u(response.getString("authenticatorData"))
            val signature = unb64u(response.getString("signature"))
            commonChecks(checks, "webauthn.get", rpId, challenge, expectedOrigin, clientData, authData)
            checks += Check(
                "User handle returned (discoverable credential)",
                response.optString("userHandle").isNotEmpty() && response.optString("userHandle") != "null",
            )

            val stored = publicKeyFor(id)
            if (stored == null) {
                // Like a website, the demo needs the public key from registration; it keeps them on the phone that
                // made the passkey. A passkey moved from another phone (or made before 'Forget') isn't there.
                checks += Check(
                    "Signature not checked: this demo didn't see this passkey being made",
                    ok = true,
                    detail = "made on another phone (e.g. moved there) or before 'Forget'. A real site keeps the public " +
                        "key on its server and checks it; to test that, use a site such as webauthn.io",
                    skipped = true,
                )
            } else {
                val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(stored))
                val valid = Signature.getInstance("SHA256withECDSA").run {
                    initVerify(key)
                    update(authData + sha256(clientData))
                    verify(signature)
                }
                checks += Check("Signature verifies with the public key saved at registration", valid)
            }
        } catch (e: Exception) {
            checks += Check("Response could be read", false, "${e.javaClass.simpleName}: ${e.message}")
        }
        return checks
    }

    private fun commonChecks(
        checks: MutableList<Check>,
        type: String,
        rpId: String,
        challenge: ByteArray,
        expectedOrigin: String?,
        clientDataBytes: ByteArray,
        authData: ByteArray,
    ) {
        val clientData = JSONObject(String(clientDataBytes, Charsets.UTF_8))
        checks += Check("clientDataJSON type is $type", clientData.optString("type") == type, "type: ${clientData.optString("type")}")
        checks += Check("Challenge is the one this demo issued", clientData.optString("challenge") == b64u(challenge))
        val origin = clientData.optString("origin")
        checks += if (expectedOrigin != null) {
            Check("Origin is this app", origin == expectedOrigin, "origin: $origin")
        } else {
            Check("Origin reported by the web view", origin.isNotEmpty(), "origin: $origin")
        }
        checks += Check("Authenticator data is long enough", authData.size >= 37, "${authData.size} bytes")
        if (authData.size < 37) return
        checks += Check("RP ID hash is for $rpId", authData.copyOfRange(0, 32).contentEquals(sha256(rpId.toByteArray())))
        val flags = authData[32].toInt() and 0xff
        checks += Check("User present (UP)", flags and FLAG_UP != 0)
        checks += Check("User verified (UV)", flags and FLAG_UV != 0)
        // WebAuthn L3 §6.1.3: "backed up" (BS) may only be set on a "backup eligible" (BE) credential.
        val kind = when {
            flags and FLAG_BE == 0 && flags and FLAG_BS == 0 -> "device-bound (stays on one phone)"
            flags and FLAG_BE != 0 && flags and FLAG_BS == 0 -> "movable, not copied to another device yet"
            flags and FLAG_BE != 0 -> "movable, and a copy exists on another device (backed up)"
            else -> "INVALID: marked backed up but not backup eligible"
        }
        checks += Check(
            "Backup flags are valid (BS only with BE)",
            !(flags and FLAG_BS != 0 && flags and FLAG_BE == 0),
            "$kind; flags: 0x%02x".format(flags),
        )
    }
}
