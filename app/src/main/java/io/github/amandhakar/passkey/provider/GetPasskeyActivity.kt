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
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.webauthn.AssertionOptions
import io.github.amandhakar.passkey.webauthn.Base64Url
import java.security.Signature
import kotlin.coroutines.cancellation.CancellationException
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
        // Without an rpId the request is for the page's own host exactly (WebAuthn §5.1.4.1), not a parent domain.
        if (options.rpId == null && CallerVerifier.hostOf(origin) != passkey.rpId) {
            throw GetCredentialUnknownException("Passkey belongs to a different site")
        }

        val authenticator = Authenticator(this)
        val keyId = Base64Url.decode(passkey.credentialId)
        val title = "Sign in with passkey"
        val subtitle = "${passkey.userName} on ${passkey.rpId}"
        suspend fun sign(signer: Signature) = withContext(Dispatchers.Default) {
            authenticator.authenticate(passkey, options, origin, option.clientDataHash, signer)
        }
        suspend fun promptAndSign(): String {
            val timeBound = withContext(Dispatchers.Default) { PasskeyKeys.isTimeBound(keyId) }
            val signer = if (timeBound) {
                // Passkey from app 1.3.5 or older: its key works for 30 s after any authentication.
                if (!verifyUser(title, subtitle)) throw GetCredentialCancellationException("User cancelled")
                withContext(Dispatchers.Default) { PasskeyKeys.signer(keyId) }
            } else {
                // The prompt authorises this one signer; the Keystore refuses any other signature.
                val signer = withContext(Dispatchers.Default) { PasskeyKeys.signer(keyId) }
                verifyUserFor(signer, title, subtitle) ?: throw GetCredentialCancellationException("User cancelled")
            }
            return sign(signer)
        }
        // Android 15+ may already have verified the user in its passkey sheet. For a current key that prompt
        // authorised the signer kept in SheetSigners; for an older time-bound key it unlocked the key for 30 s.
        // If neither works (process restarted, Keystore dropped the operation, weaker biometric), the Keystore
        // refuses and we fall back to our own prompt.
        val sheetSigner = SheetSigners.take(passkey.credentialId)
        val response = if (request.biometricPromptResult?.isSuccessful == true) {
            try {
                sign(sheetSigner ?: withContext(Dispatchers.Default) { PasskeyKeys.signer(keyId) })
                    .also { ProviderErrors.note(this, "User verified in Android's passkey sheet") }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ProviderErrors.note(this, "Sheet verification did not unlock the key (${e.javaClass.simpleName}); asking again")
                promptAndSign()
            }
        } else {
            promptAndSign()
        }
        ProviderErrors.succeeded(
            this,
            "Signed in to ${passkey.rpId} for ${request.callingAppInfo.packageName} (origin $origin)",
        )
        return response
    }
}
