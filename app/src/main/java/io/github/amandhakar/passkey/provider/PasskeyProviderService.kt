package io.github.amandhakar.passkey.provider

import android.app.KeyguardManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.os.Process
import android.os.SystemClock
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.BiometricPromptData
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import io.github.amandhakar.passkey.BuildConfig
import io.github.amandhakar.passkey.R
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.webauthn.AssertionOptions
import io.github.amandhakar.passkey.webauthn.Base64Url
import org.json.JSONObject
import java.security.SecureRandom
import java.security.Signature
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * Entry point for Android's Credential Manager. The "begin" calls must be fast and must not show UI:
 * they only say which passkeys we could offer. The real work happens in the activities behind the
 * PendingIntents once the user picks an entry.
 *
 * Cross-device sign-in (desktop shows a QR code, phone scans it) is carried by Google Play services'
 * hybrid transport; it ends up calling this same service, so no extra code is needed here.
 */
class PasskeyProviderService : CredentialProviderService() {

    override fun onCreate() {
        super.onCreate()
        ProviderErrors.note(this, "Passkey service started by Android")
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        // What the system sent decides whether it shows our entry, so record it (no challenge or user id).
        val asker = request.callingAppInfo
        val publicKeyRequest = request as? BeginCreatePublicKeyCredentialRequest
        ProviderErrors.note(
            this,
            "Create asked by ${LogText.field(asker?.packageName ?: "unknown caller")} " +
                "(origin given: ${asker?.isOriginPopulated()}, client data hash: ${publicKeyRequest?.clientDataHash != null}, " +
                "Android ${Build.VERSION.SDK_INT}, app process age ${processAgeMs()} ms)" +
                (publicKeyRequest?.let { "\n" + LogText.createRequestSummary(it.requestJson) } ?: ""),
        )
        // An exception here is not a crash: Android drops it silently and just leaves this provider out.
        try {
            if (request !is BeginCreatePublicKeyCredentialRequest) {
                callback.onError(CreateCredentialUnknownException("Only passkeys are supported"))
                return
            }
            val userName = runCatching { JSONObject(request.requestJson).getJSONObject("user").optString("name") }
                .getOrNull().orEmpty()
            val sheetPrompt = if (Build.VERSION.SDK_INT >= 35) createSheetPrompt() else null
            val entry = CreateEntry.Builder(
                userName.ifBlank { getString(R.string.app_name) },
                pendingIntent(CreatePasskeyActivity::class.java, null),
            ).setDescription(getString(R.string.create_entry_description))
                .apply {
                    if (Build.VERSION.SDK_INT >= 35) sheetPrompt?.let { setBiometricPromptData(it) }
                }
                .build()
            callback.onResult(BeginCreateCredentialResponse(createEntries = listOf(entry)))
            ProviderErrors.note(this, "Create offered to the system (fingerprint prompt in the sheet: ${sheetPrompt != null})")
        } catch (e: Throwable) {
            ProviderErrors.problem(this, "Create offer FAILED\n" + e.stackTraceToString().lineSequence().take(30).joinToString("\n"))
            callback.onError(CreateCredentialUnknownException(e.message ?: e.javaClass.simpleName))
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        // Checking the caller can mean fetching a site's assetlinks.json, so it must not run on the main thread.
        background.execute {
            try {
                beginGet(request, callback)
            } catch (e: Throwable) {
                ProviderErrors.problem(this, "Sign-in offer FAILED\n" + e.stackTraceToString().lineSequence().take(30).joinToString("\n"))
                callback.onError(GetCredentialUnknownException(e.javaClass.simpleName))
            }
        }
    }

    private fun beginGet(
        request: BeginGetCredentialRequest,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val store = PasskeyStore.get(this)
        val entries = mutableListOf<CredentialEntry>()
        val info = request.callingAppInfo
        val caller = info?.packageName ?: "unknown caller"
        val verifier = CallerVerifier(this)
        val sheetSigners = mutableMapOf<String, Signature>()
        for (option in request.beginGetCredentialOptions) {
            if (option !is BeginGetPublicKeyCredentialOption) continue
            val options = runCatching { AssertionOptions.parse(option.requestJson) }.getOrNull() ?: continue
            // rpId is optional in WebAuthn sign-in requests; it then defaults to the page's own host.
            val rpId = options.rpId ?: info?.let { originHost(it) }
            // Only list passkeys to a caller that may use them: a trusted browser on that site, or an app the site
            // vouches for. Otherwise another app could make the sheet show the user's accounts for any site.
            // GetPasskeyActivity checks again before signing.
            val refused = when {
                info == null || rpId == null -> "caller or site unknown"
                else -> runCatching { verifier.verifyRpId(info, verifier.resolveOrigin(info), rpId) }
                    .exceptionOrNull()?.let { it.message ?: it.javaClass.simpleName }
            }
            if (refused != null) {
                ProviderErrors.problem(this, "Sign-in asked by $caller for ${LogText.site(rpId)}: refused ($refused)")
                continue
            }
            val allowed = options.allowCredentialIds.map { Base64Url.encode(it) }.toSet()
            val matching = if (rpId == null) emptyList() else store.forRp(rpId)
                .filter { allowed.isEmpty() || it.credentialId in allowed }
            // Store builds record only how many passkeys are saved, never the list of the user's sites.
            val saved = if (BuildConfig.LOG_ALL_REQUESTS) {
                "passkeys saved for: ${store.all().map { it.rpId }.distinct().ifEmpty { listOf("none") }}"
            } else {
                "${store.all().size} passkey(s) saved in total"
            }
            val message = "Sign-in asked by $caller for " +
                "${LogText.site(rpId)}${if (options.rpId == null) " (site taken from the page)" else ""}: " +
                "${matching.size} passkey(s) offered, ${allowed.size} allowed by the site, $saved"
            // Nothing to offer looks like a failure to the user, so it is kept even in store builds.
            if (matching.isEmpty()) ProviderErrors.problem(this, message) else ProviderErrors.note(this, message)
            matching
                .sortedByDescending { it.lastUsedAt }
                .forEach { passkey ->
                    entries += PublicKeyCredentialEntry.Builder(
                        this,
                        passkey.userName.ifBlank { passkey.displayName },
                        pendingIntent(GetPasskeyActivity::class.java, passkey.credentialId),
                        option,
                    )
                        .setDisplayName(passkey.label.ifBlank { passkey.displayName }.ifBlank { null })
                        .apply {
                            if (Build.VERSION.SDK_INT >= 35) {
                                signInSheetPrompt(passkey, sheetSigners)?.let { setBiometricPromptData(it) }
                            }
                        }
                        .setLastUsedTime(Instant.ofEpochMilli(passkey.lastUsedAt))
                        .build()
                }
        }
        SheetSigners.replaceAll(sheetSigners)
        callback.onResult(BeginGetCredentialResponse(credentialEntries = entries))
    }

    /**
     * Android 15+ can show the fingerprint / screen-lock prompt inside its own passkey sheet, so picking a
     * passkey and verifying is one step. Only with an enrolled strong biometric: without one the sheet has
     * nothing to show and can get stuck (seen on an Android 16 emulator with only a PIN). Then the activity
     * shows its own prompt.
     */
    @RequiresApi(35)
    private fun sheetPromptAvailable(): Boolean =
        getSystemService(KeyguardManager::class.java).isDeviceSecure &&
            BiometricManager.from(this).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    /** Creating a passkey uses no key, so the sheet's prompt only confirms the user (biometric or screen lock). */
    @RequiresApi(35)
    private fun createSheetPrompt(): BiometricPromptData? {
        if (!sheetPromptAvailable()) return null
        return BiometricPromptData.Builder()
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()
    }

    /**
     * For signing in, the sheet's prompt must unlock the Keystore operation that will sign, so it carries a
     * signer as its CryptoObject (kept in [signers] for GetPasskeyActivity). Android then allows only a strong
     * biometric in the sheet; someone who prefers the PIN, or whose fingerprint fails, gets the activity's
     * prompt instead. Older time-bound keys (app 1.3.5 and before) keep the plain prompt, which unlocks them
     * for 30 s. Returns null when the activity should prompt instead.
     */
    @RequiresApi(35)
    private fun signInSheetPrompt(passkey: Passkey, signers: MutableMap<String, Signature>): BiometricPromptData? {
        if (!sheetPromptAvailable()) return null
        return try {
            val keyId = Base64Url.decode(passkey.credentialId)
            if (PasskeyKeys.isTimeBound(keyId)) {
                BiometricPromptData.Builder().setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL).build()
            } else if (signers.size < MAX_SHEET_SIGNERS) {
                // Each signer holds an open Keystore operation, of which an app gets only a few.
                val signer = PasskeyKeys.signer(keyId)
                signers[passkey.credentialId] = signer
                BiometricPromptData.Builder()
                    .setCryptoObject(BiometricPrompt.CryptoObject(signer))
                    .setAllowedAuthenticators(BIOMETRIC_STRONG)
                    .build()
            } else {
                null
            }
        } catch (e: Exception) {
            ProviderErrors.problem(this, "Could not prepare the sheet prompt (${e.javaClass.simpleName}); the app will ask instead")
            null
        }
    }

    /** Host of a browser caller's page, or null for apps (their requests must name the rpId). */
    private fun originHost(info: CallingAppInfo): String? = runCatching {
        if (!info.isOriginPopulated()) return null
        CallerVerifier.hostOf(CallerVerifier(this).resolveOrigin(info))
    }.getOrNull()

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }

    private fun pendingIntent(activity: Class<*>, credentialId: String?): PendingIntent {
        val intent = Intent(this, activity).setPackage(packageName)
        if (credentialId != null) intent.putExtra(EXTRA_CREDENTIAL_ID, credentialId)
        return PendingIntent.getActivity(
            this,
            requestCodes.incrementAndGet(),
            intent,
            // Mutable: the system adds the full request to the intent before launching it.
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    /**
     * How long this app's process has been running. Android waits only a few seconds for a provider to
     * answer and leaves it out of the sheet if it is slower; a process that is only milliseconds old when a
     * request arrives was started by that request, which explains a missing entry.
     */
    private fun processAgeMs() = SystemClock.elapsedRealtime() - Process.getStartElapsedRealtime()

    companion object {
        const val EXTRA_CREDENTIAL_ID = "io.github.amandhakar.passkey.CREDENTIAL_ID"
        // Random start: codes from before a process restart can't line up with new ones.
        private val requestCodes = AtomicInteger(SecureRandom().nextInt())
        private val background = Executors.newSingleThreadExecutor()
        private const val MAX_SHEET_SIGNERS = 4
    }
}
