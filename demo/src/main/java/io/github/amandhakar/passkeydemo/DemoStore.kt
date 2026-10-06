package io.github.amandhakar.passkeydemo

import android.content.Context
import org.json.JSONObject

/**
 * The passkeys this demo made, with the public key each was registered with (what a website's server would
 * keep). Only the demo's own record: the private keys are in the passkey provider.
 */
object DemoStore {
    private fun prefs(context: Context) = context.getSharedPreferences("demo", Context.MODE_PRIVATE)

    private fun load(context: Context): JSONObject =
        runCatching { JSONObject(prefs(context).getString("passkeys", "{}").orEmpty()) }.getOrDefault(JSONObject())

    fun save(context: Context, credentialId: String, publicKey: ByteArray, userName: String, via: String) {
        val all = load(context)
        all.put(
            credentialId,
            JSONObject().put("publicKey", PasskeyVerifier.b64u(publicKey)).put("userName", userName).put("via", via),
        )
        prefs(context).edit().putString("passkeys", all.toString()).apply()
    }

    fun publicKey(context: Context, credentialId: String): ByteArray? =
        load(context).optJSONObject(credentialId)?.optString("publicKey")?.takeIf { it.isNotEmpty() }?.let(PasskeyVerifier::unb64u)

    fun ids(context: Context): List<String> = load(context).keys().asSequence().toList()

    fun clear(context: Context) = prefs(context).edit().remove("passkeys").apply()
}
