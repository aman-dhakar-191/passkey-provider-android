package io.github.amandhakar.passkey.provider

import android.content.Intent
import android.os.Bundle
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
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
            throw CreateCredentialUnknownException("The site does not accept ES256 keys")
        }
        val existing = PasskeyStore.get(this).forRp(rpId).map { it.credentialId }.toSet()
        if (options.excludeCredentialIds.any { Base64Url.encode(it) in existing }) {
            throw CreateCredentialUnknownException("You already have a passkey for this account on this device")
        }

        if (!verifyUser("Create a passkey", "for ${options.userName.ifBlank { rpId }} on $rpId")) {
            throw CreateCredentialCancellationException("User cancelled")
        }
        return withContext(Dispatchers.Default) {
            Authenticator(this@CreatePasskeyActivity).register(options, rpId, origin)
        }
    }
}
