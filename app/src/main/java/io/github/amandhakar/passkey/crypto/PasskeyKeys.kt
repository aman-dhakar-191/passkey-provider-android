package io.github.amandhakar.passkey.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.github.amandhakar.passkey.webauthn.Base64Url
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Passkey private keys live in the Android Keystore (StrongBox when available). They never leave the
 * secure hardware and can only be used for a short window after the user unlocks with biometrics or
 * the device PIN/pattern/password.
 */
object PasskeyKeys {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AUTH_VALIDITY_SECONDS = 30

    private fun alias(credentialId: ByteArray) = "passkey_" + Base64Url.encode(credentialId)

    private fun keyStore() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun generate(credentialId: ByteArray): ECPublicKey =
        try {
            generate(credentialId, strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(credentialId, strongBox = false)
        } catch (_: ProviderException) {
            // Some StrongBox chips claim support but reject this key configuration; use the TEE instead.
            generate(credentialId, strongBox = false)
        }

    private fun generate(credentialId: ByteArray, strongBox: Boolean): ECPublicKey {
        val spec = KeyGenParameterSpec.Builder(alias(credentialId), KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                AUTH_VALIDITY_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            // Adding a new fingerprint must not silently destroy every passkey.
            .setInvalidatedByBiometricEnrollment(false)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(spec)
        return generator.generateKeyPair().public as ECPublicKey
    }

    /** ES256 signature, ASN.1 DER encoded as WebAuthn expects. Requires a recent user authentication. */
    fun sign(credentialId: ByteArray, data: ByteArray): ByteArray {
        val key = keyStore().getKey(alias(credentialId), null) as? PrivateKey
            ?: throw IllegalStateException("The key for this passkey is missing")
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(data)
            sign()
        }
    }

    /** The public key, for checking signatures (the self-test uses it to verify a sign-in). */
    fun publicKey(credentialId: ByteArray): PublicKey? = keyStore().getCertificate(alias(credentialId))?.publicKey

    /** Where a passkey's private key is kept, as the Keystore reports it (see [storage]). */
    data class Storage(val securityLevel: String, val userAuthRequired: Boolean, val exportable: Boolean)

    /**
     * Diagnostics only (the device-setup beta): reads the key's metadata from the Keystore. The key is not
     * used, so no user authentication is needed, and its private bytes are never read: [PrivateKey.getEncoded]
     * is how Java would export a key, and the Android Keystore always answers null. Returns null if the key
     * is missing.
     */
    fun storage(credentialId: ByteArray): Storage? {
        val key = keyStore().getKey(alias(credentialId), null) as? PrivateKey ?: return null
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        val level = when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
            KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "secure hardware (unknown kind)"
            else -> "unknown"
        }
        return Storage(level, info.isUserAuthenticationRequired, exportable = key.encoded != null)
    }

    fun delete(credentialId: ByteArray) {
        keyStore().deleteEntry(alias(credentialId))
    }
}
