package io.github.amandhakar.passkey.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.github.amandhakar.passkey.webauthn.Base64Url
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

    fun delete(credentialId: ByteArray) {
        keyStore().deleteEntry(alias(credentialId))
    }
}
