package io.github.amandhakar.passkey.provider

import android.app.KeyguardManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.Signature
import kotlin.coroutines.resume

/** Shows the system biometric / screen-lock prompt. Returns true if the user verified. */
suspend fun FragmentActivity.verifyUser(title: String, subtitle: String): Boolean =
    prompt(title, subtitle, crypto = null)

/**
 * Shows the prompt bound to [signer], so that success authorises the Keystore to sign with that one
 * object (a per-operation passkey key). Returns the unlocked signer, or null if the user did not verify.
 */
suspend fun FragmentActivity.verifyUserFor(signer: Signature, title: String, subtitle: String): Signature? =
    if (prompt(title, subtitle, BiometricPrompt.CryptoObject(signer))) signer else null

private suspend fun FragmentActivity.prompt(title: String, subtitle: String, crypto: BiometricPrompt.CryptoObject?): Boolean {
    val keyguard = getSystemService(KeyguardManager::class.java)
    if (!keyguard.isDeviceSecure) {
        throw IllegalStateException("Set up a screen lock (PIN, pattern, password or biometrics) to use passkeys")
    }
    return suspendCancellableCoroutine { cont ->
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (cont.isActive) cont.resume(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (cont.isActive) cont.resume(false)
                }
            },
        )
        // Strong biometrics or the device PIN/pattern/password: those are what unlock the passkey keys.
        // A CryptoObject together with the device credential needs API 30+; this app needs 34.
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()
        if (crypto == null) prompt.authenticate(info) else prompt.authenticate(info, crypto)
        cont.invokeOnCancellation { prompt.cancelAuthentication() }
    }
}
