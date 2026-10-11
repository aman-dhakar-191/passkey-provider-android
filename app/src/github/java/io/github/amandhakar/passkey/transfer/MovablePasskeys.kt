package io.github.amandhakar.passkey.transfer

import android.content.Context
import android.content.Intent
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.Passkey
import io.github.amandhakar.passkey.data.PasskeyStore
import io.github.amandhakar.passkey.webauthn.Base64Url
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * GitHub build: passkeys that can be moved to a new phone (a setting, off by default).
 *
 * A movable passkey's key pair is made in software, then:
 *  - the private key is imported into the Keystore under the passkey's alias, with the same rule as every
 *    other passkey (each signature needs its own fingerprint or screen-lock prompt), so signing in is unchanged;
 *  - an encrypted copy is kept in the passkey's details ([KeyWrap]) under the "vault": an RSA key in the
 *    Keystore that decrypts only for 30 s after a **fingerprint** check (not the PIN), and that the Keystore
 *    destroys if fingerprints are added or removed. So someone who knows the PIN can't copy passkeys away,
 *    not even by enrolling their own finger. Only moving passkeys (TransferActivity) ever opens it.
 *
 * Copies made by the first version (vault v1, which also accepted the screen lock) are re-wrapped under the
 * fingerprint-only vault (v2) at the first chance: quietly when the phone was just unlocked, or when sending.
 *
 * The trade-off, shown in the app: unlike phone-only passkeys, the private key exists outside the Keystore
 * for a moment when it is made, moved or received, and a copy can end up on another phone.
 */
object MovablePasskeys {
    const val ENABLED = true

    private const val PREFS = "movable_passkeys"
    private const val KEY_NEW_MOVABLE = "new_passkeys_movable"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val VAULT_V1_ALIAS = "passkey_move_vault_v1"
    private const val VAULT_V2_ALIAS = "passkey_move_vault_v2"
    private const val VAULT_AUTH_SECONDS = 30

    /** The setting as chosen, whether or not a fingerprint is enrolled now. */
    fun newPasskeysMovableSetting(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_NEW_MOVABLE, false)

    /** True if new passkeys are made movable: the setting is on and a fingerprint is enrolled. */
    fun newPasskeysMovable(context: Context): Boolean = newPasskeysMovableSetting(context) && fingerprintReady(context)

    fun setNewPasskeysMovable(context: Context, movable: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY_NEW_MOVABLE, movable).apply()
    }

    /** Moving passkeys needs a fingerprint (or another strong biometric); the screen lock alone isn't enough. */
    fun fingerprintReady(context: Context): Boolean =
        BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    fun open(context: Context) {
        context.startActivity(Intent(context, TransferActivity::class.java))
    }

    /** Makes a movable passkey's key: imported into the Keystore, plus its wrapped copy (base64url). */
    @Suppress("UNUSED_PARAMETER")
    fun createKey(context: Context, credentialId: ByteArray): Pair<ECPublicKey, String> {
        val pair = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val pkcs8 = pair.private.encoded
        try {
            val wrapped = store(credentialId, pair.public, pair.private, pkcs8)
            return pair.public as ECPublicKey to wrapped
        } finally {
            pkcs8.fill(0)
        }
    }

    /** Saves a received key pair like [createKey] does; returns the new wrapped copy (base64url). */
    internal fun importKey(credentialId: ByteArray, publicKey: PublicKey, privateKey: PrivateKey): String {
        val pkcs8 = privateKey.encoded
        try {
            return store(credentialId, publicKey, privateKey, pkcs8)
        } finally {
            pkcs8.fill(0)
        }
    }

    private fun store(credentialId: ByteArray, publicKey: PublicKey, privateKey: PrivateKey, pkcs8: ByteArray): String {
        // Wrap first: if the vault can't be made, nothing is left half-saved in the Keystore.
        val wrapped = KeyWrap.wrap(vaultPublicKey(), pkcs8, credentialId)
        PasskeyKeys.import(credentialId, privateKey, SelfSignedCertificate.create(publicKey, privateKey))
        return Base64Url.encode(wrapped)
    }

    /**
     * The private key of a movable passkey (PKCS#8), for sending it to another phone. Call within 30 s of a
     * successful fingerprint prompt; the Keystore refuses otherwise. A copy still under vault v1 is re-wrapped
     * under the fingerprint-only vault on the way.
     */
    internal fun privateKey(context: Context, passkey: Passkey): ByteArray {
        require(passkey.movable && passkey.wrappedKey.isNotEmpty()) { "This passkey stays on this phone" }
        val blob = Base64Url.decode(passkey.wrappedKey)
        val vault = KeyWrap.vault(blob)
        val pkcs8 = unwrap(blob, passkey.credentialId, if (vault == KeyWrap.VAULT_V1) VAULT_V1_ALIAS else VAULT_V2_ALIAS)
        if (vault == KeyWrap.VAULT_V1) rewrap(context, passkey, pkcs8)
        return pkcs8
    }

    /**
     * Re-wraps copies still under vault v1 (which also accepted the screen lock) under the fingerprint-only
     * vault. Needs no prompt: it works only if the phone was unlocked in the last 30 s, and otherwise leaves
     * them for the next try (or for sending, which re-wraps them too). Returns how many are left on v1.
     */
    fun upgradeQuietly(context: Context): Int {
        val store = PasskeyStore.get(context)
        val old = store.all().filter { it.movable && it.wrappedKey.isNotEmpty() && isVaultV1(it.wrappedKey) }
        if (old.isEmpty() || !fingerprintReady(context)) return old.size
        var left = old.size
        for (passkey in old) {
            val pkcs8 = runCatching { unwrap(Base64Url.decode(passkey.wrappedKey), passkey.credentialId, VAULT_V1_ALIAS) }
                .getOrNull() ?: return left // not unlocked recently: try again another time
            try {
                rewrap(context, passkey, pkcs8)
                left--
            } finally {
                pkcs8.fill(0)
            }
        }
        if (left == 0) runCatching { keyStore().deleteEntry(VAULT_V1_ALIAS) }
        return left
    }

    private fun isVaultV1(wrappedKey: String) =
        runCatching { KeyWrap.vault(Base64Url.decode(wrappedKey)) == KeyWrap.VAULT_V1 }.getOrDefault(false)

    private fun rewrap(context: Context, passkey: Passkey, pkcs8: ByteArray) {
        val wrapped = KeyWrap.wrap(vaultPublicKey(), pkcs8, Base64Url.decode(passkey.credentialId))
        PasskeyStore.get(context).setWrappedKey(passkey.credentialId, Base64Url.encode(wrapped))
    }

    private fun unwrap(blob: ByteArray, credentialId: String, alias: String): ByteArray {
        val vault = keyStore().getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("The key that protects movable passkeys is missing")
        return KeyWrap.unwrap(blob, Base64Url.decode(credentialId)) { rsa ->
            try {
                Cipher.getInstance(KeyWrap.RSA_TRANSFORMATION).run {
                    init(Cipher.DECRYPT_MODE, vault, KeyWrap.OAEP)
                    doFinal(rsa)
                }
            } catch (_: KeyPermanentlyInvalidatedException) {
                throw IllegalStateException(
                    "Fingerprints were changed after these passkeys were made, so they can no longer be moved. " +
                        "They still sign in on this phone; passkeys made from now on can be moved.",
                )
            }
        }
    }

    /**
     * The fingerprint-only vault's public key, made on first use (and remade if fingerprints changed, which
     * destroys it). Encrypting needs no prompt; it runs in software.
     */
    private fun vaultPublicKey(): PublicKey {
        val keyStore = keyStore()
        if (keyStore.containsAlias(VAULT_V2_ALIAS) && isInvalidated(keyStore)) keyStore.deleteEntry(VAULT_V2_ALIAS)
        val public = keyStore.getCertificate(VAULT_V2_ALIAS)?.publicKey
            ?: KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE).run {
                initialize(
                    KeyGenParameterSpec.Builder(VAULT_V2_ALIAS, KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(3072)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setUserAuthenticationRequired(true)
                        // Fingerprint only: the screen-lock PIN never unlocks the vault.
                        .setUserAuthenticationParameters(VAULT_AUTH_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG)
                        // Adding a fingerprint (which only needs the PIN) destroys the vault, so a PIN alone
                        // can't be turned into a fingerprint that copies passkeys.
                        .setInvalidatedByBiometricEnrollment(true)
                        .build(),
                )
                generateKeyPair().public
            }
        // A plain software copy, so encryption never goes through the Keystore.
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(public.encoded))
    }

    /** A vault the Keystore destroyed (fingerprints changed) can't decrypt anything any more. */
    private fun isInvalidated(keyStore: KeyStore): Boolean {
        val key = keyStore.getKey(VAULT_V2_ALIAS, null) as? PrivateKey ?: return true
        return try {
            Cipher.getInstance(KeyWrap.RSA_TRANSFORMATION).init(Cipher.DECRYPT_MODE, key, KeyWrap.OAEP)
            false
        } catch (_: KeyPermanentlyInvalidatedException) {
            true
        } catch (_: UserNotAuthenticatedException) {
            false // valid, just locked
        } catch (_: Exception) {
            false // unsure: never throw away a vault that might still be good
        }
    }

    private fun keyStore() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
