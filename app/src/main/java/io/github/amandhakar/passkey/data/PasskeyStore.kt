package io.github.amandhakar.passkey.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Passkey metadata. The private key itself is in the Android Keystore, keyed by [credentialId]. */
data class Passkey(
    val credentialId: String, // base64url
    val rpId: String,
    val rpName: String,
    val userId: String, // base64url
    val userName: String,
    val displayName: String,
    val createdAt: Long,
    val lastUsedAt: Long,
    /** Optional name the user gave this passkey in the app; empty = none. */
    val label: String = "",
) {
    fun toJson(): JSONObject = JSONObject()
        .put("credentialId", credentialId)
        .put("rpId", rpId)
        .put("rpName", rpName)
        .put("userId", userId)
        .put("userName", userName)
        .put("displayName", displayName)
        .put("createdAt", createdAt)
        .put("lastUsedAt", lastUsedAt)
        .put("label", label)

    companion object {
        fun fromJson(o: JSONObject) = Passkey(
            credentialId = o.getString("credentialId"),
            rpId = o.getString("rpId"),
            rpName = o.optString("rpName"),
            userId = o.getString("userId"),
            userName = o.optString("userName"),
            displayName = o.optString("displayName"),
            createdAt = o.optLong("createdAt"),
            lastUsedAt = o.optLong("lastUsedAt"),
            label = o.optString("label"),
        )
    }
}

/** Small JSON-file store in app-private storage (excluded from backups, see data_extraction_rules). */
class PasskeyStore internal constructor(private val file: File) {
    private val state = MutableStateFlow(load())
    val passkeys: StateFlow<List<Passkey>> = state.asStateFlow()

    private fun load(): List<Passkey> {
        if (!file.exists()) return emptyList()
        return try {
            val array = JSONArray(file.readText())
            (0 until array.length()).map { Passkey.fromJson(array.getJSONObject(it)) }
        } catch (e: Exception) {
            // Never overwrite an unreadable list with an empty one: the keys still exist in the Keystore
            // and the file may be recoverable. Keep it aside and start empty.
            file.renameTo(File(file.parentFile, "${file.name}.unreadable-${System.currentTimeMillis()}"))
            emptyList()
        }
    }

    private fun save(list: List<Passkey>) {
        val array = JSONArray()
        list.forEach { array.put(it.toJson()) }
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(array.toString())
        if (!tmp.renameTo(file)) throw IllegalStateException("Could not save passkeys")
        state.value = list
    }

    fun all(): List<Passkey> = state.value

    fun forRp(rpId: String): List<Passkey> = state.value.filter { it.rpId == rpId }

    fun find(credentialId: String): Passkey? = state.value.firstOrNull { it.credentialId == credentialId }

    /** Adds [passkey], returning any passkey it replaced (same RP and user handle, per WebAuthn). */
    @Synchronized
    fun add(passkey: Passkey): List<Passkey> {
        val replaced = state.value.filter { it.rpId == passkey.rpId && it.userId == passkey.userId }
        save(state.value - replaced.toSet() + passkey)
        return replaced
    }

    @Synchronized
    fun markUsed(credentialId: String, time: Long) {
        save(state.value.map { if (it.credentialId == credentialId) it.copy(lastUsedAt = time) else it })
    }

    @Synchronized
    fun rename(credentialId: String, label: String) {
        save(state.value.map { if (it.credentialId == credentialId) it.copy(label = label.trim().take(60)) else it })
    }

    @Synchronized
    fun remove(credentialId: String) {
        save(state.value.filterNot { it.credentialId == credentialId })
    }

    companion object {
        @Volatile private var instance: PasskeyStore? = null

        fun get(context: Context): PasskeyStore =
            instance ?: synchronized(this) {
                instance ?: PasskeyStore(File(context.applicationContext.filesDir, "passkeys.json"))
                    .also { instance = it }
            }
    }
}
