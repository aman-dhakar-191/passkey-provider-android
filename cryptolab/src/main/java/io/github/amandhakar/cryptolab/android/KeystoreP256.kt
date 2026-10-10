package io.github.amandhakar.cryptolab.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.amandhakar.cryptolab.core.AesGcm
import io.github.amandhakar.cryptolab.core.CipherSuite
import io.github.amandhakar.cryptolab.core.KeyExchange
import io.github.amandhakar.cryptolab.core.P256
import io.github.amandhakar.cryptolab.core.Suites
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.KeyAgreement

/**
 * Key exchange approach 2: the same P-256 ECDH as [P256], but the private key is made and used inside the
 * Android Keystore (TEE, or StrongBox if available) and never enters app memory. On the wire it is
 * identical, so it talks to a phone using the software P-256 suite.
 */
object KeystoreP256 : KeyExchange {
    override val name = "P-256 (Android Keystore)"
    private const val PROVIDER = "AndroidKeyStore"
    private val aliases = ConcurrentHashMap<PublicKey, String>()

    override fun generate(): KeyPair {
        val alias = "cryptolab-" + UUID.randomUUID()
        val pair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).run {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .build(),
            )
            generateKeyPair()
        }
        aliases[pair.public] = alias
        return pair
    }

    override fun decode(encoded: ByteArray): PublicKey = P256.decode(encoded)

    override fun agree(own: KeyPair, peer: PublicKey): ByteArray = KeyAgreement.getInstance("ECDH", PROVIDER).run {
        init(own.private)
        doPhase(peer, true)
        generateSecret()
    }

    override fun dispose(own: KeyPair) {
        val alias = aliases.remove(own.public) ?: return
        runCatching { KeyStore.getInstance(PROVIDER).apply { load(null) }.deleteEntry(alias) }
    }
}

/** Every suite the app offers: the software ones plus the Keystore-backed variant. */
object LabSuites {
    val all: List<CipherSuite> = Suites.software +
        CipherSuite(Suites.P256_AESGCM, "P-256 in Keystore + AES-256-GCM", KeystoreP256, AesGcm)
}
