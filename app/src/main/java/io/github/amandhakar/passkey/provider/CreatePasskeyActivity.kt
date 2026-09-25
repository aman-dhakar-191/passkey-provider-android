package io.github.amandhakar.passkey.provider

import android.content.Intent
import android.os.Bundle
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.webauthn.Base64Url
import io.github.amandhakar.passkey.webauthn.CreationOptions
import io.github.amandhakar.passkey.webauthn.WebAuthnEncoding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** Invisible activity that verifies the caller and the user, then creates the passkey. */
class CreatePasskeyActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return // already running; the coroutine survives in lifecycleScope
        lifecycleScope.launch {
            val result = Intent()
            try {
                PendingIntentHandler.setCreateCredentialResponse(
                    result,
                    CreatePublicKeyCredentialResponse(createPasskey()),
                )
            } catch (e: CreateCredentialException) {
                if (e !is CreateCredentialCancellationException) ProviderErrors.record(this@CreatePasskeyActivity, "Creating passkey", e)
                PendingIntentHandler.setCreateCredentialException(result, e)
            } catch (e: Exception) {
                ProviderErrors.record(this@CreatePasskeyActivity, "Creating passkey", e)
                PendingIntentHandler.setCreateCredentialException(
                    result,
                    CreateCredentialUnknownException(e.message ?: e.javaClass.simpleName),
                )
            }
            setResult(RESULT_OK, result)
            finish()
        }
    }

    private suspend fun createPasskey(): String {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            ?: throw CreateCredentialUnknownException("No request")
        val pkRequest = request.callingRequest as? CreatePublicKeyCredentialRequest
            ?: throw CreateCredentialUnknownException("Only passkeys are supported")
        ProviderErrors.note(
            this,
            "Create started by ${request.callingAppInfo.packageName} " +
                "(origin given: ${request.callingAppInfo.isOriginPopulated()}, " +
                "client data hash: ${pkRequest.clientDataHash != null})\n" + requestSummary(pkRequest.requestJson),
        )
        val options = CreationOptions.parse(pkRequest.requestJson)
        val verifier = CallerVerifier(this)

        val (origin, rpId) = withContext(Dispatchers.IO) {
            val origin = verifier.resolveOrigin(request.callingAppInfo)
            val rpId = options.rpId ?: CallerVerifier.hostOf(origin)
                ?: throw CreateCredentialUnknownException("Missing RP ID")
            verifier.verifyRpId(request.callingAppInfo, origin, rpId)
            origin to rpId
        }

        if (options.algorithms.isNotEmpty() && WebAuthnEncoding.COSE_ALG_ES256 !in options.algorithms) {
            throw CreatePublicKeyCredentialDomException(NotSupportedError(), "The site does not accept ES256 keys")
        }
        val existing = PasskeyStore.get(this).forRp(rpId).map { it.credentialId }.toSet()
        if (options.excludeCredentialIds.any { Base64Url.encode(it) in existing }) {
            // WebAuthn: InvalidStateError tells the site this account is already registered on this device.
            throw CreatePublicKeyCredentialDomException(
                InvalidStateError(),
                "You already have a passkey for this account on this device",
            )
        }

        // Android 15+ may already have verified the user in its passkey sheet; otherwise ask here.
        if (request.biometricPromptResult?.isSuccessful == true) {
            ProviderErrors.note(this, "User verified in Android's passkey sheet")
        } else if (!verifyUser("Create a passkey", "for ${options.userName.ifBlank { rpId }} on $rpId")) {
            throw CreateCredentialCancellationException("User cancelled")
        }
        val response = withContext(Dispatchers.Default) {
            Authenticator(this@CreatePasskeyActivity).register(options, rpId, origin)
        }
        ProviderErrors.succeeded(this, "Passkey created for $rpId (origin $origin), returned ${response.length} bytes")
        return response
    }

    /** Only the request fields that affect whether a passkey can be made; no challenge or user id. */
    private fun requestSummary(json: String): String = runCatching {
        val o = JSONObject(json)
        JSONObject()
            .put("rp", o.optJSONObject("rp"))
            .put("pubKeyCredParams", o.optJSONArray("pubKeyCredParams"))
            .put("authenticatorSelection", o.optJSONObject("authenticatorSelection"))
            .put("attestation", o.opt("attestation"))
            .put("excludeCredentials", o.optJSONArray("excludeCredentials")?.length() ?: 0)
            .put("extensions", o.optJSONObject("extensions"))
            .toString()
    }.getOrElse { "unparsable request: ${it.message}" }
}
