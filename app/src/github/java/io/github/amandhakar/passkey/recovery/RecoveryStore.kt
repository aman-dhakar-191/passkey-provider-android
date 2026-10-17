package io.github.amandhakar.passkey.recovery

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.amandhakar.passkey.webauthn.Base64Url
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** JSON form of [BackupSet]; no secrets in it except the owner's points, which are vault-encrypted. */
internal object BackupSetJson {
    fun write(set: BackupSet): JSONObject = JSONObject()
        .put("setId", Base64Url.encode(set.setId))
        .put("createdAt", set.createdAt)
        .put("ownerPoints", set.ownerPoints)
        .put("lastReminderAt", set.lastReminderAt)
        .put(
            "keepers",
            JSONArray().apply {
                set.keepers.forEach { k ->
                    put(
                        JSONObject()
                            .put("x", k.x).put("kind", k.kind.name).put("label", k.label)
                            .put("checkKey", Base64Url.encode(k.checkKey)).put("addedAt", k.addedAt)
                            .put("lastOkAt", k.lastOkAt).put("lastProblem", k.lastProblem)
                            .put("lastProblemAt", k.lastProblemAt).put("pendingChallenge", k.pendingChallenge),
                    )
                }
            },
        )
        .apply {
            set.file?.let { f ->
                put(
                    "file",
                    JSONObject().put("uri", f.uri).put("sha256", f.sha256).put("writtenAt", f.writtenAt)
                        .put("passkeyIds", JSONArray(f.passkeyIds.sorted())).put("lastOkAt", f.lastOkAt)
                        .put("lastProblem", f.lastProblem).put("lastProblemAt", f.lastProblemAt),
                )
            }
        }

    fun read(o: JSONObject): BackupSet {
        val keepers = o.optJSONArray("keepers") ?: JSONArray()
        return BackupSet(
            setId = Base64Url.decode(o.getString("setId")),
            createdAt = o.getLong("createdAt"),
            ownerPoints = o.getString("ownerPoints"),
            lastReminderAt = o.optLong("lastReminderAt"),
            keepers = (0 until keepers.length()).map { i ->
                val k = keepers.getJSONObject(i)
                Keeper(
                    x = k.getInt("x"),
                    kind = KeeperKind.valueOf(k.getString("kind")),
                    label = k.getString("label"),
                    checkKey = Base64Url.decode(k.getString("checkKey")),
                    addedAt = k.getLong("addedAt"),
                    lastOkAt = k.optLong("lastOkAt"),
                    lastProblem = k.optString("lastProblem"),
                    lastProblemAt = k.optLong("lastProblemAt"),
                    pendingChallenge = k.optString("pendingChallenge"),
                )
            },
            file = o.optJSONObject("file")?.let { f ->
                val ids = f.getJSONArray("passkeyIds")
                SavedFile(
                    uri = f.getString("uri"),
                    sha256 = f.getString("sha256"),
                    writtenAt = f.getLong("writtenAt"),
                    passkeyIds = (0 until ids.length()).map { ids.getString(it) }.toSet(),
                    lastOkAt = f.optLong("lastOkAt"),
                    lastProblem = f.optString("lastProblem"),
                    lastProblemAt = f.optLong("lastProblemAt"),
                )
            },
        )
    }

    /** What goes into the backup file so a restored phone knows its keepers (labels and piece numbers only). */
    fun keeperList(set: BackupSet): JSONObject = JSONObject()
        .put("setId", Base64Url.encode(set.setId))
        .put("createdAt", set.createdAt)
        .put(
            "keepers",
            JSONArray().apply {
                set.keepers.forEach { put(JSONObject().put("x", it.x).put("kind", it.kind.name).put("label", it.label).put("addedAt", it.addedAt)) }
            },
        )

    /** Reads [keeperList]; unknown or malformed entries are dropped. */
    fun readKeeperList(o: JSONObject?): List<Triple<Int, KeeperKind, String>> {
        val list = o?.optJSONArray("keepers") ?: return emptyList()
        return (0 until list.length()).mapNotNull { i ->
            runCatching {
                val k = list.getJSONObject(i)
                val x = k.getInt("x")
                require(x in 1..RecoveryShare.MAX_X)
                Triple(x, KeeperKind.valueOf(k.getString("kind")), k.getString("label").take(LABEL_MAX))
            }.getOrNull()
        }.distinctBy { it.first }
    }

    const val LABEL_MAX = 40
}

/** A piece this phone keeps for someone else (keeper mode). [sealed] is the piece encrypted by [HeldShareCipher]. */
internal data class HeldShare(
    val setId: String,
    val x: Int,
    val owner: String,
    val sealed: String,
    val receivedAt: Long,
    val lastAnsweredAt: Long = 0,
    val lastReturnedAt: Long = 0,
)

/**
 * The owner's backup set (at most one) and the pieces kept for others, in app-private files that are excluded
 * from Android's backups (data_extraction_rules.xml).
 */
internal class RecoveryStore private constructor(private val dir: File) {
    private val setFile = File(dir, "backup_set.json")
    private val heldFile = File(dir, "held_shares.json")
    private val setState = MutableStateFlow(loadSet())
    private val heldState = MutableStateFlow(loadHeld())
    val set: StateFlow<BackupSet?> = setState.asStateFlow()
    val held: StateFlow<List<HeldShare>> = heldState.asStateFlow()

    private fun loadSet(): BackupSet? = readJson(setFile)?.let { runCatching { BackupSetJson.read(JSONObject(it)) }.getOrNull() }

    private fun loadHeld(): List<HeldShare> = readJson(heldFile)?.let { text ->
        runCatching {
            val a = JSONArray(text)
            (0 until a.length()).map { i ->
                val o = a.getJSONObject(i)
                HeldShare(
                    setId = o.getString("setId"), x = o.getInt("x"), owner = o.getString("owner"),
                    sealed = o.getString("sealed"), receivedAt = o.getLong("receivedAt"),
                    lastAnsweredAt = o.optLong("lastAnsweredAt"), lastReturnedAt = o.optLong("lastReturnedAt"),
                )
            }
        }.getOrNull()
    } ?: emptyList()

    private fun readJson(file: File): String? {
        if (!file.exists()) return null
        return runCatching { file.readText() }.getOrNull().also {
            // Keep an unreadable file aside rather than overwrite it.
            if (it == null) file.renameTo(File(dir, "${file.name}.unreadable-${System.currentTimeMillis()}"))
        }
    }

    private fun write(file: File, text: String) {
        val tmp = File(dir, file.name + ".tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(file)) throw IllegalStateException("Could not save ${file.name}")
    }

    @Synchronized
    fun update(change: (BackupSet?) -> BackupSet?) {
        val next = change(setState.value)
        if (next == null) setFile.delete() else write(setFile, BackupSetJson.write(next).toString())
        setState.value = next
    }

    @Synchronized
    fun updateKeeper(x: Int, change: (Keeper) -> Keeper) =
        update { set -> set?.copy(keepers = set.keepers.map { if (it.x == x) change(it) else it }) }

    @Synchronized
    fun updateHeld(change: (List<HeldShare>) -> List<HeldShare>) {
        val next = change(heldState.value)
        val a = JSONArray()
        next.forEach {
            a.put(
                JSONObject().put("setId", it.setId).put("x", it.x).put("owner", it.owner).put("sealed", it.sealed)
                    .put("receivedAt", it.receivedAt).put("lastAnsweredAt", it.lastAnsweredAt)
                    .put("lastReturnedAt", it.lastReturnedAt),
            )
        }
        write(heldFile, a.toString())
        heldState.value = next
    }

    companion object {
        @Volatile private var instance: RecoveryStore? = null

        fun get(context: Context): RecoveryStore =
            instance ?: synchronized(this) {
                instance ?: RecoveryStore(context.applicationContext.filesDir).also { instance = it }
            }
    }
}

/**
 * Encrypts pieces kept for others with an AES key in the Keystore that needs no prompt (so checks can be
 * answered quickly) but works only while the phone is unlocked. Giving a piece back asks for the screen lock.
 */
internal object HeldShareCipher {
    private const val ALIAS = "held_recovery_shares_v1"

    fun seal(share: RecoveryShare): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val sealed = cipher.doFinal(share.bytes())
        return Base64Url.encode(cipher.iv + sealed)
    }

    fun open(held: HeldShare): RecoveryShare {
        val blob = Base64Url.decode(held.sealed)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, 12))
        }
        val bytes = cipher.doFinal(blob, 12, blob.size - 12)
        return RecoveryShare.parse(RecoveryShare.QR_PREFIX + Base32.encode(bytes))
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUnlockedDeviceRequired(true)
                    .build(),
            )
            generateKey()
        }
    }
}
