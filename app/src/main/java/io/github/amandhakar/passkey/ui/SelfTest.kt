package io.github.amandhakar.passkey.ui

import android.app.Activity
import android.os.Build
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import io.github.amandhakar.passkey.BuildConfig
import io.github.amandhakar.passkey.provider.CallerVerifier
import io.github.amandhakar.passkey.provider.ProviderErrors
import io.github.amandhakar.passkey.webauthn.Base64Url
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Asks Android's Credential Manager to create a passkey, exactly as a website or app would, but without
 * a browser in between. Shows whether Android offers this provider and whether creation works.
 */
object SelfTest {
    suspend fun run(activity: Activity): String {
        val random = SecureRandom()
        val request = JSONObject()
            .put("rp", JSONObject().put("id", CallerVerifier.SELF_TEST_RP_ID).put("name", "Self-test"))
            .put(
                "user",
                JSONObject()
                    .put("id", Base64Url.encode(ByteArray(16).also(random::nextBytes)))
                    .put("name", "self-test")
                    .put("displayName", "Self-test (safe to delete)"),
            )
            .put("challenge", Base64Url.encode(ByteArray(32).also(random::nextBytes)))
            .put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
            .put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "required"))
            .put("attestation", "none")
            .put("timeout", 120_000)
        ProviderErrors.note(
            activity,
            "Self-test: asking Android to create a passkey (app ${BuildConfig.VERSION_NAME}, " +
                "Android ${Build.VERSION.RELEASE} / API ${Build.VERSION.SDK_INT}, ${Build.MANUFACTURER} ${Build.MODEL}, " +
                "${Build.DISPLAY})",
        )
        val message = try {
            CredentialManager.create(activity)
                .createCredential(activity, CreatePublicKeyCredentialRequest(request.toString()))
            "Self-test passed: Android offered a provider and a passkey was created."
        } catch (e: CreateCredentialNoCreateOptionException) {
            "Self-test: Android found no service to save passkeys (${e.message}). " +
                "Check that Passkey Provider is on in Passwords, passkeys & accounts."
        } catch (e: CreateCredentialCancellationException) {
            "Self-test cancelled (${e.message})."
        } catch (e: CreateCredentialException) {
            "Self-test failed: ${e.type}: ${e.message}"
        }
        ProviderErrors.note(activity, message)
        return message
    }
}
