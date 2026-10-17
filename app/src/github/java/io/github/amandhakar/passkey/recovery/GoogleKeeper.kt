package io.github.amandhakar.passkey.recovery

import android.content.Context
import com.google.android.gms.auth.blockstore.Blockstore
import com.google.android.gms.auth.blockstore.BlockstoreClient
import com.google.android.gms.auth.blockstore.DeleteBytesRequest
import com.google.android.gms.auth.blockstore.RetrieveBytesRequest
import com.google.android.gms.auth.blockstore.StoreBytesData
import com.google.android.gms.tasks.Task
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Google as a keeper, through Google Play services' Block Store: a small value kept on this phone and, when
 * the phone has a screen lock, backed up to the person's Google account end-to-end encrypted with that screen
 * lock. It comes back on a new phone that is set up from that Google backup (Android's restore during setup),
 * after the old phone's screen lock is entered.
 *
 * This app can check its own phone's copy, but not the one in Google's cloud. It only ever stores one piece.
 */
internal object GoogleKeeper {
    private val KEY = BlockstoreClient.DEFAULT_BYTES_DATA_KEY

    /** True if Google's backup of this piece would be end-to-end encrypted (needs a screen lock). */
    suspend fun endToEndEncrypted(context: Context): Boolean =
        Blockstore.getClient(context).isEndToEndEncryptionAvailable().await()

    /** Stores [share]; backed up to Google's cloud only if that is end-to-end encrypted. Returns whether it is. */
    suspend fun store(context: Context, share: RecoveryShare): Boolean {
        val cloud = endToEndEncrypted(context)
        Blockstore.getClient(context).storeBytes(
            StoreBytesData.Builder().setBytes(share.bytes()).setShouldBackupToCloud(cloud).build(),
        ).await()
        return cloud
    }

    /** The piece Google keeps for this app, if any (on a new phone: restored during setup). */
    suspend fun read(context: Context): RecoveryShare? {
        val response = Blockstore.getClient(context).retrieveBytes(
            RetrieveBytesRequest.Builder().setKeys(listOf(KEY)).build(),
        ).await()
        val bytes = response.blockstoreDataMap[KEY]?.bytes ?: return null
        return runCatching { RecoveryShare.parse(RecoveryShare.QR_PREFIX + Base32.encode(bytes)) }.getOrNull()
    }

    suspend fun delete(context: Context) {
        Blockstore.getClient(context).deleteBytes(DeleteBytesRequest.Builder().setKeys(listOf(KEY)).build()).await()
    }

    private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { cont ->
        addOnSuccessListener { if (cont.isActive) cont.resume(it) }
        addOnFailureListener { if (cont.isActive) cont.resumeWithException(it) }
        addOnCanceledListener { cont.cancel() }
    }
}
