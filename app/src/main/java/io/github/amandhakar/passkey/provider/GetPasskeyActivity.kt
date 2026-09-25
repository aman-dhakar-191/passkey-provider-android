package io.github.amandhakar.passkey.provider

import android.content.Intent
import android.os.Bundle
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.webauthn.AssertionOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Invisible activity that verifies the caller and the user, then signs the WebAuthn challenge. */
class GetPasskeyActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return
        lifecycleScope.launch {
            val result = Intent()
            try {
                PendingIntentHandler.setGetCredentialResponse(
                    result,
                    GetCredentialResponse(PublicKeyCredential(signIn())),
                )
            } catch (e: GetCredentialException) {
                if (e !is GetCredentialCancellationException) ProviderErrors.record(this@GetPasskeyActivity, "Passkey sign-in", e)
                PendingIntentHandler.setGetCredentialException(result, e)
            } catch (e: Exception) {
                ProviderErrors.record(this@GetPasskeyActivity, "Passkey sign-in", e)
                PendingIntentHandler.setGetCredentialException(
                    result,
                    GetCredentialUnknownException(e.message ?: e.javaClass.simpleName),
                )
            }
            setResult(RESULT_OK, result)
            finish()
        }
    }

    private suspend fun signIn(): String {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            ?: throw GetCredentialUnknownException("No request")
        val option = request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull()
            ?: throw GetCredentialUnknownException("No passkey request")
        val credentialId = intent.getStringExtra(PasskeyProviderService.EXTRA_CREDENTIAL_ID)
            ?: throw GetCredentialUnknownException("No passkey selected")
        val passkey = PasskeyStore.get(this).find(credentialId)
            ?: throw GetCredentialUnknownException("Passkey not found")
        val options = AssertionOptions.parse(option.requestJson)
        if (options.rpId != null && options.rpId != passkey.rpId) {
            throw GetCredentialUnknownException("Passkey belongs to a different site")
        }

        val origin = withContext(Dispatchers.IO) {
            val verifier = CallerVerifier(this@GetPasskeyActivity)
            verifier.resolveOrigin(request.callingAppInfo).also {
                verifier.verifyRpId(request.callingAppInfo, it, passkey.rpId)
            }
        }

        if (!verifyUser("Sign in with passkey", "${passkey.userName} on ${passkey.rpId}")) {
            throw GetCredentialCancellationException("User cancelled")
        }
        return withContext(Dispatchers.Default) {
            Authenticator(this@GetPasskeyActivity).authenticate(passkey, options, origin, option.clientDataHash)
        }
    }
}
