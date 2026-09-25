package io.github.amandhakar.passkey.webauthn

import org.json.JSONArray
import org.json.JSONObject

private fun JSONObject.stringOrNull(key: String): String? =
    if (has(key) && !isNull(key)) getString(key) else null

private fun JSONArray?.credentialIds(): List<ByteArray> {
    if (this == null) return emptyList()
    return (0 until length()).mapNotNull { i ->
        optJSONObject(i)?.stringOrNull("id")?.let { runCatching { Base64Url.decode(it) }.getOrNull() }
    }
}

/** The fields of PublicKeyCredentialCreationOptionsJSON this authenticator uses. */
class CreationOptions(
    val rpId: String?,
    val rpName: String,
    val userId: ByteArray,
    val userName: String,
    val userDisplayName: String,
    val challenge: ByteArray,
    val algorithms: List<Int>,
    val excludeCredentialIds: List<ByteArray>,
) {
    companion object {
        fun parse(json: String): CreationOptions {
            val o = JSONObject(json)
            val rp = o.getJSONObject("rp")
            val user = o.getJSONObject("user")
            val params = o.optJSONArray("pubKeyCredParams")
            val algs = if (params == null) emptyList() else
                (0 until params.length()).mapNotNull { params.optJSONObject(it)?.optInt("alg") }
            // Domain names are case-insensitive; store and compare them in lowercase.
            val rpId = rp.stringOrNull("id")?.lowercase()
            return CreationOptions(
                rpId = rpId,
                rpName = rp.stringOrNull("name") ?: rpId ?: "",
                userId = Base64Url.decode(user.getString("id")),
                userName = user.stringOrNull("name") ?: "",
                userDisplayName = user.stringOrNull("displayName") ?: "",
                challenge = Base64Url.decode(o.getString("challenge")),
                algorithms = algs,
                excludeCredentialIds = o.optJSONArray("excludeCredentials").credentialIds(),
            )
        }
    }
}

/** The fields of PublicKeyCredentialRequestOptionsJSON this authenticator uses. */
class AssertionOptions(
    val rpId: String?,
    val challenge: ByteArray,
    val allowCredentialIds: List<ByteArray>,
) {
    companion object {
        fun parse(json: String): AssertionOptions {
            val o = JSONObject(json)
            return AssertionOptions(
                rpId = o.stringOrNull("rpId")?.lowercase(),
                challenge = Base64Url.decode(o.getString("challenge")),
                allowCredentialIds = o.optJSONArray("allowCredentials").credentialIds(),
            )
        }
    }
}

object WebAuthnJson {
    /** RegistrationResponseJSON (WebAuthn L3 §5.1). */
    fun registrationResponse(
        credentialId: ByteArray,
        clientDataJson: ByteArray,
        attestationObject: ByteArray,
        authenticatorData: ByteArray,
        subjectPublicKeyInfo: ByteArray,
    ): String {
        val id = Base64Url.encode(credentialId)
        val response = JSONObject()
            .put("clientDataJSON", Base64Url.encode(clientDataJson))
            .put("attestationObject", Base64Url.encode(attestationObject))
            .put("authenticatorData", Base64Url.encode(authenticatorData))
            .put("publicKey", Base64Url.encode(subjectPublicKeyInfo))
            .put("publicKeyAlgorithm", WebAuthnEncoding.COSE_ALG_ES256)
            .put("transports", JSONArray().put("internal").put("hybrid"))
        return JSONObject()
            .put("id", id)
            .put("rawId", id)
            .put("type", "public-key")
            .put("authenticatorAttachment", "platform")
            .put("response", response)
            .put("clientExtensionResults", JSONObject().put("credProps", JSONObject().put("rk", true)))
            .toString()
    }

    /** AuthenticationResponseJSON (WebAuthn L3 §5.1). */
    fun authenticationResponse(
        credentialId: ByteArray,
        clientDataJson: ByteArray,
        authenticatorData: ByteArray,
        signature: ByteArray,
        userHandle: ByteArray,
    ): String {
        val id = Base64Url.encode(credentialId)
        val response = JSONObject()
            .put("clientDataJSON", Base64Url.encode(clientDataJson))
            .put("authenticatorData", Base64Url.encode(authenticatorData))
            .put("signature", Base64Url.encode(signature))
            .put("userHandle", Base64Url.encode(userHandle))
        return JSONObject()
            .put("id", id)
            .put("rawId", id)
            .put("type", "public-key")
            .put("authenticatorAttachment", "platform")
            .put("response", response)
            .put("clientExtensionResults", JSONObject())
            .toString()
    }
}
