package io.github.amandhakar.passkey.provider

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import io.github.amandhakar.passkey.R
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.webauthn.AssertionOptions
import io.github.amandhakar.passkey.webauthn.Base64Url
import org.json.JSONObject
import java.time.Instant
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

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            callback.onError(CreateCredentialUnknownException("Only passkeys are supported"))
            return
        }
        val userName = runCatching { JSONObject(request.requestJson).getJSONObject("user").optString("name") }
            .getOrNull().orEmpty()
        val entry = CreateEntry.Builder(
            userName.ifBlank { getString(R.string.app_name) },
            pendingIntent(CreatePasskeyActivity::class.java, null),
        ).setDescription(getString(R.string.create_entry_description)).build()
        ProviderErrors.note(this, "Create offered to ${request.callingAppInfo?.packageName ?: "unknown caller"}")
        callback.onResult(BeginCreateCredentialResponse(createEntries = listOf(entry)))
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val store = PasskeyStore.get(this)
        val entries = mutableListOf<CredentialEntry>()
        for (option in request.beginGetCredentialOptions) {
            if (option !is BeginGetPublicKeyCredentialOption) continue
            val options = runCatching { AssertionOptions.parse(option.requestJson) }.getOrNull() ?: continue
            val rpId = options.rpId ?: continue
            val allowed = options.allowCredentialIds.map { Base64Url.encode(it) }.toSet()
            store.forRp(rpId)
                .filter { allowed.isEmpty() || it.credentialId in allowed }
                .sortedByDescending { it.lastUsedAt }
                .forEach { passkey ->
                    entries += PublicKeyCredentialEntry.Builder(
                        this,
                        passkey.userName.ifBlank { passkey.displayName },
                        pendingIntent(GetPasskeyActivity::class.java, passkey.credentialId),
                        option,
                    )
                        .setDisplayName(passkey.displayName.ifBlank { null })
                        .setLastUsedTime(Instant.ofEpochMilli(passkey.lastUsedAt))
                        .build()
                }
        }
        if (request.beginGetCredentialOptions.any { it is BeginGetPublicKeyCredentialOption }) {
            ProviderErrors.note(
                this,
                "Sign-in asked by ${request.callingAppInfo?.packageName ?: "unknown caller"}: " +
                    "${entries.size} passkey(s) offered",
            )
        }
        callback.onResult(BeginGetCredentialResponse(credentialEntries = entries))
    }

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

    companion object {
        const val EXTRA_CREDENTIAL_ID = "io.github.amandhakar.passkey.CREDENTIAL_ID"
        private val requestCodes = AtomicInteger()
    }
}
