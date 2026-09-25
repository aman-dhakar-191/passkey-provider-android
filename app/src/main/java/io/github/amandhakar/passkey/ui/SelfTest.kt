package io.github.amandhakar.passkey.ui

import android.app.Activity
import android.os.Build
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import androidx.credentials.exceptions.GetCredentialException
import io.github.amandhakar.passkey.BuildConfig
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.provider.CallerVerifier
import io.github.amandhakar.passkey.provider.ProviderErrors
import io.github.amandhakar.passkey.webauthn.Base64Url
import io.github.amandhakar.passkey.webauthn.WebAuthnEncoding
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.security.Signature

/**
 * Debug builds only (run by the emulator workflow). Goes through Android's Credential Manager exactly as
 * a website or app would, without a browser in between: creates a passkey, signs in with it, checks the
 * signature against the stored public key, then deletes the test passkey again.
 */
object SelfTest {
    private val random = SecureRandom()

    private fun randomB64(size: Int) = Base64Url.encode(ByteArray(size).also(random::nextBytes))

    suspend fun run(activity: Activity): String {
        ProviderErrors.note(
            activity,
            "Self-test: asking Android to create a passkey (app ${BuildConfig.VERSION_NAME}, " +
                "Android ${Build.VERSION.RELEASE} / API ${Build.VERSION.SDK_INT}, ${Build.MANUFACTURER} ${Build.MODEL}, " +
                "${Build.DISPLAY})",
        )
        val message = try {
            val credentialId = create(activity)
            ProviderErrors.note(activity, "Self-test: passkey created, now signing in with it")
            try {
                signIn(activity, credentialId)
            } finally {
                PasskeyStore.get(activity).remove(Base64Url.encode(credentialId))
                PasskeyKeys.delete(credentialId)
            }
            "Self-test passed: created a passkey, signed in with it and verified the signature."
        } catch (e: CreateCredentialNoCreateOptionException) {
            "Self-test failed: Android found no service to save passkeys (${e.message}). " +
                "Check that Passkey Vault is on in Passwords, passkeys & accounts."
        } catch (e: CreateCredentialException) {
            "Self-test failed while creating: ${e.type}: ${e.message}"
        } catch (e: GetCredentialException) {
            "Self-test failed while signing in: ${e.type}: ${e.message}"
        } catch (e: Exception) {
            "Self-test failed: ${e.message ?: e.javaClass.simpleName}"
        }
        ProviderErrors.note(activity, message)
        return message
    }

    private suspend fun create(activity: Activity): ByteArray {
        val request = JSONObject()
            .put("rp", JSONObject().put("id", CallerVerifier.SELF_TEST_RP_ID).put("name", "Self-test"))
            .put(
                "user",
                JSONObject().put("id", randomB64(16)).put("name", "self-test").put("displayName", "Self-test"),
            )
            .put("challenge", randomB64(32))
            .put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
            .put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "required"))
            .put("attestation", "none")
            .put("timeout", 120_000)
        val response = CredentialManager.create(activity)
            .createCredential(activity, CreatePublicKeyCredentialRequest(request.toString()))
        val json = JSONObject((response as CreatePublicKeyCredentialResponse).registrationResponseJson)
        return Base64Url.decode(json.getString("rawId"))
    }

    private suspend fun signIn(activity: Activity, credentialId: ByteArray) {
        val challenge = randomB64(32)
        val request = JSONObject()
            .put("rpId", CallerVerifier.SELF_TEST_RP_ID)
            .put("challenge", challenge)
            .put(
                "allowCredentials",
                JSONArray().put(JSONObject().put("type", "public-key").put("id", Base64Url.encode(credentialId))),
            )
            .put("userVerification", "required")
            .put("timeout", 120_000)
        val result = CredentialManager.create(activity).getCredential(
            activity,
            GetCredentialRequest(listOf(GetPublicKeyCredentialOption(request.toString()))),
        )
        val credential = result.credential as? PublicKeyCredential
            ?: throw IllegalStateException("Sign-in returned ${result.credential.type}, not a passkey")
        val json = JSONObject(credential.authenticationResponseJson)
        check(json.getString("rawId") == Base64Url.encode(credentialId)) { "Sign-in used a different passkey" }
        val response = json.getJSONObject("response")
        val clientData = Base64Url.decode(response.getString("clientDataJSON"))
        val authData = Base64Url.decode(response.getString("authenticatorData"))
        val signature = Base64Url.decode(response.getString("signature"))
        check(JSONObject(String(clientData)).getString("challenge") == challenge) { "Challenge was not signed" }
        val publicKey = PasskeyKeys.publicKey(credentialId) ?: throw IllegalStateException("Public key missing")
        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(authData + WebAuthnEncoding.sha256(clientData))
            verify(signature)
        }
        check(valid) { "Signature does not verify" }
    }
}
