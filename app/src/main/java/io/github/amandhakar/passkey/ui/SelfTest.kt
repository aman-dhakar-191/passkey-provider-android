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
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import io.github.amandhakar.passkey.BuildConfig
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.provider.CallerVerifier
import io.github.amandhakar.passkey.provider.ProviderErrors
import io.github.amandhakar.passkey.webauthn.Base64Url
import io.github.amandhakar.passkey.webauthn.WebAuthnEncoding
import org.json.JSONArray
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.security.SecureRandom
import java.security.Signature

/**
 * Debug and CI-only "minified" builds (BuildConfig.SELF_TEST), run by the emulator workflow. Goes through
 * Android's Credential Manager exactly as a website or app would, without a browser in between: creates a passkey, signs in with it, checks the
 * signature against the stored public key, then deletes the test passkey again.
 *
 * Then the refusals: a second passkey for the same account is refused (InvalidStateError), and this app,
 * which example.com does not vouch for, is neither shown example.com's passkeys nor allowed to create one.
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
                ProviderErrors.note(activity, "Self-test: signed in; now asking for a second passkey for the same account")
                duplicateRefused(activity, credentialId)
            } finally {
                PasskeyStore.get(activity).remove(Base64Url.encode(credentialId))
                PasskeyKeys.delete(credentialId)
            }
            ProviderErrors.note(activity, "Self-test: checking that example.com's passkeys are not shown to this app")
            unverifiedSiteHidden(activity)
            ProviderErrors.note(activity, "Self-test: checking that this app cannot create a passkey for example.com")
            unverifiedSiteCannotCreate(activity)
            "Self-test passed: created a passkey, signed in with it and verified the signature; " +
                "refused a duplicate, and refused an app that example.com does not vouch for."
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

    private suspend fun create(
        activity: Activity,
        rpId: String = CallerVerifier.SELF_TEST_RP_ID,
        exclude: ByteArray? = null,
    ): ByteArray {
        val request = JSONObject()
            .put("rp", JSONObject().put("id", rpId).put("name", "Self-test"))
            .put(
                "user",
                JSONObject().put("id", randomB64(16)).put("name", "self-test").put("displayName", "Self-test"),
            )
            .put("challenge", randomB64(32))
            .put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
            .put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "required"))
            .put("attestation", "none")
            .put("timeout", 120_000)
        if (exclude != null) {
            request.put(
                "excludeCredentials",
                JSONArray().put(JSONObject().put("type", "public-key").put("id", Base64Url.encode(exclude))),
            )
        }
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

    /** WebAuthn: a site that lists an existing passkey in excludeCredentials gets InvalidStateError. */
    private suspend fun duplicateRefused(activity: Activity, existing: ByteArray) {
        val error = try {
            val created = create(activity, exclude = existing)
            PasskeyStore.get(activity).remove(Base64Url.encode(created))
            PasskeyKeys.delete(created)
            throw IllegalStateException("A second passkey was created for an account that already has one")
        } catch (e: CreateCredentialException) {
            e
        }
        check(error is CreatePublicKeyCredentialDomException && error.domError is InvalidStateError) {
            "A duplicate passkey was refused with ${error.type} instead of InvalidStateError"
        }
    }

    /**
     * A decoy passkey for example.com is saved, then this app asks for example.com's passkeys. example.com
     * publishes no assetlinks.json vouching for this app, so the provider must list nothing; the decoy
     * proves the empty answer comes from that refusal and not from having no passkey for the site.
     */
    private suspend fun unverifiedSiteHidden(activity: Activity) {
        val store = PasskeyStore.get(activity)
        val now = System.currentTimeMillis()
        val decoy = Passkey(
            credentialId = randomB64(32),
            rpId = UNVERIFIED_RP_ID,
            rpName = "Example",
            userId = randomB64(16),
            userName = "decoy-account",
            displayName = "Decoy",
            createdAt = now,
            lastUsedAt = now,
        )
        store.add(decoy)
        try {
            val request = JSONObject()
                .put("rpId", UNVERIFIED_RP_ID)
                .put("challenge", randomB64(32))
                .put("userVerification", "required")
            val result = withTimeoutOrNull(30_000) {
                runCatching {
                    CredentialManager.create(activity).getCredential(
                        activity,
                        GetCredentialRequest(
                            listOf(GetPublicKeyCredentialOption(request.toString())),
                            // No "use another device" sheet: answer at once if nothing is offered.
                            preferImmediatelyAvailableCredentials = true,
                        ),
                    )
                }
            }
            val error = result?.exceptionOrNull()
            check(error is NoCredentialException) {
                when {
                    result == null -> "$UNVERIFIED_RP_ID's passkeys were shown to an app the site does not vouch for"
                    result.isSuccess -> "This app signed in to $UNVERIFIED_RP_ID, which does not vouch for it"
                    else -> "Unexpected answer for $UNVERIFIED_RP_ID: ${error?.javaClass?.simpleName}: ${error?.message}"
                }
            }
        } finally {
            store.remove(decoy.credentialId)
        }
    }

    /** The create sheet is offered to anyone, but CreatePasskeyActivity must refuse before making a key. */
    private suspend fun unverifiedSiteCannotCreate(activity: Activity) {
        try {
            val created = create(activity, rpId = UNVERIFIED_RP_ID)
            PasskeyStore.get(activity).remove(Base64Url.encode(created))
            PasskeyKeys.delete(created)
            throw IllegalStateException("This app created a passkey for $UNVERIFIED_RP_ID, which does not vouch for it")
        } catch (_: CreateCredentialException) {
            // Refused, as it must be.
        }
        check(PasskeyStore.get(activity).forRp(UNVERIFIED_RP_ID).isEmpty()) {
            "A passkey for $UNVERIFIED_RP_ID was saved although creating it failed"
        }
    }

    /** A real site whose assetlinks.json does not list this app. */
    private const val UNVERIFIED_RP_ID = "example.com"
}
