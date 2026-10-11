package io.github.amandhakar.passkey.transfer

import android.content.Context
import java.security.interfaces.ECPublicKey

/**
 * Store channel (Google Play, Indus Appstore): passkeys always stay on this phone, as before. Moving passkeys
 * to a new phone is a GitHub-build feature still being tried out; this build has only this stub.
 */
object MovablePasskeys {
    const val ENABLED = false

    fun newPasskeysMovable(context: Context) = false

    fun createKey(context: Context, credentialId: ByteArray): Pair<ECPublicKey, String> =
        throw UnsupportedOperationException("Movable passkeys are not in this build")

    fun open(context: Context) = Unit

    fun upgradeQuietly(context: Context) = 0
}
