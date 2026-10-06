package io.github.amandhakar.passkey.provider

import java.security.Signature
import java.util.concurrent.ConcurrentHashMap

/**
 * Signers whose Keystore operation was handed to Android 15+'s passkey sheet. The sheet's fingerprint
 * prompt authorises that exact operation (by its handle), so GetPasskeyActivity must sign with the very
 * same object. It is kept here, in this process, from listing the passkey until the user picks it.
 * If the process restarts in between, the activity finds nothing and shows its own prompt.
 */
internal object SheetSigners {
    private val signers = ConcurrentHashMap<String, Signature>()

    /** Replaces the signers of the previous request; dropping them lets the Keystore end those operations. */
    fun replaceAll(new: Map<String, Signature>) {
        signers.clear()
        signers.putAll(new)
    }

    fun take(credentialId: String): Signature? = signers.remove(credentialId)
}
