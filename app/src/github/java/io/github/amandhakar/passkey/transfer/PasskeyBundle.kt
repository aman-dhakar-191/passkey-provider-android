package io.github.amandhakar.passkey.transfer

import android.content.Context
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.webauthn.Base64Url
import org.json.JSONObject

/**
 * Packing movable passkeys with their private keys, and adding received ones: shared by moving passkeys to
 * another phone (TransferActivity) and by the encrypted backup (recovery/BackupActivity).
 */
internal object PasskeyBundle {
    /** This phone's movable passkeys that have an encrypted copy, i.e. can be moved or backed up. */
    fun movable(context: Context): List<Passkey> =
        PasskeyStore.get(context).all().filter { it.movable && it.wrappedKey.isNotEmpty() }

    /**
     * [movable] with their private keys, as a [TransferPayload] (plus [recovery] for a backup file). Call within
     * 30 s of a fingerprint check; the caller wipes the result.
     */
    fun encode(context: Context, movable: List<Passkey>, recovery: JSONObject? = null): ByteArray =
        TransferPayload.encode(
            movable.map { passkey ->
                val id = Base64Url.decode(passkey.credentialId)
                val publicKey = PasskeyKeys.publicKey(id) ?: throw IllegalStateException("A passkey's key is missing")
                MovingPasskey(passkey, publicKey.encoded, MovablePasskeys.privateKey(context, passkey))
            },
            recovery,
        )

    /** Splits received passkeys into (new, already on this phone). */
    fun partition(context: Context, incoming: List<MovingPasskey>): Pair<List<MovingPasskey>, List<MovingPasskey>> {
        val store = PasskeyStore.get(context)
        return incoming.partition { moving ->
            store.all().none {
                it.credentialId == moving.passkey.credentialId ||
                    (it.rpId == moving.passkey.rpId && it.userId == moving.passkey.userId)
            }
        }
    }

    /** One line per account, for the "Add these passkeys?" question. */
    fun describe(incoming: List<MovingPasskey>): List<String> =
        incoming.map { "${it.passkey.userName.ifBlank { it.passkey.displayName }} on ${it.passkey.rpId}" }

    /** Adds received passkeys, skipping any this phone already has. Returns (added, skipped). */
    fun addAll(context: Context, incoming: List<MovingPasskey>): Pair<Int, Int> {
        val store = PasskeyStore.get(context)
        var added = 0
        var skipped = 0
        incoming.forEach { moving ->
            val passkey = moving.passkey
            val exists = store.all().any {
                it.credentialId == passkey.credentialId || (it.rpId == passkey.rpId && it.userId == passkey.userId)
            }
            if (exists) {
                skipped++
                return@forEach
            }
            val (publicKey, privateKey) = TransferPayload.keyPair(moving)
            val id = Base64Url.decode(passkey.credentialId)
            val wrapped = MovablePasskeys.importKey(id, publicKey, privateKey)
            moving.privateKey.fill(0)
            if (store.addIfAbsent(passkey.copy(movable = true, backedUp = true, wrappedKey = wrapped))) {
                added++
            } else {
                PasskeyKeys.delete(id)
                skipped++
            }
        }
        return added to skipped
    }
}
