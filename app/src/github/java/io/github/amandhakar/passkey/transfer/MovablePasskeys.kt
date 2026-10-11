package io.github.amandhakar.passkey.transfer

import android.content.Context
import android.content.Intent
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.amandhakar.passkey.crypto.PasskeyKeys
import io.github.amandhakar.passkey.data.Passkey
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
 *  - an encrypted copy is kept in the passkey's details ([KeyWrap]), under the "vault" key: an RSA key in the
 *    Keystore that decrypts only for 30 s after a fingerprint or screen-lock check. Only moving passkeys
 *    (TransferActivity) ever opens it.
 *
 * The trade-off, shown in the app: unlike phone-only passkeys, the private key exists outside the Keystore
 * for a moment when it is made, moved or received, and a copy can end up on another phone.
 */
object MovablePasskeys {
    const val ENABLED = true

    private const val PREFS = "movable_passkeys"
    private const val KEY_NEW_MOVABLE = "new_passkeys_movable"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val VAULT_ALIAS = "passkey_move_vault_v1"
    private const val VAULT_AUTH_SECONDS = 30

    fun newPasskeysMovable(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_NEW_MOVABLE, false)

    fun setNewPasskeysMovable(context: Context, movable: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY_NEW_MOVABLE, movable).apply()
    }

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
     * successful fingerprint or screen-lock prompt; the Keystore refuses otherwise.
     */
    internal fun privateKey(passkey: Passkey): ByteArray {
        require(passkey.movable && passkey.wrappedKey.isNotEmpty()) { "This passkey stays on this phone" }
        val vault = keyStore().getKey(VAULT_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("The key that protects movable passkeys is missing")
        return KeyWrap.unwrap(Base64Url.decode(passkey.wrappedKey), Base64Url.decode(passkey.credentialId)) { rsa ->
            Cipher.getInstance(KeyWrap.RSA_TRANSFORMATION).run {
                init(Cipher.DECRYPT_MODE, vault, KeyWrap.OAEP)
                doFinal(rsa)
            }
        }
    }

    /** The vault's public key, made on first use. Encrypting needs no prompt; it runs in software. */
    private fun vaultPublicKey(): PublicKey {
        val existing = keyStore().getCertificate(VAULT_ALIAS)?.publicKey
        val public = existing ?: KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE).run {
            initialize(
                KeyGenParameterSpec.Builder(VAULT_ALIAS, KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(3072)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(
                        VAULT_AUTH_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                    // Adding a fingerprint must not make movable passkeys unmovable.
                    .setInvalidatedByBiometricEnrollment(false)
                    .build(),
            )
            generateKeyPair().public
        }
        // A plain software copy, so encryption never goes through the Keystore.
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(public.encoded))
    }

    private fun keyStore() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
