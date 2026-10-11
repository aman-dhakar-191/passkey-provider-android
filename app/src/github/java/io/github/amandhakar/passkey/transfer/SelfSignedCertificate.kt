package io.github.amandhakar.passkey.transfer

import java.io.ByteArrayOutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * A minimal self-signed X.509 (v1) certificate for an EC P-256 key. The Android Keystore only imports a
 * private key together with a certificate; it uses it to hold the public key. Nobody else ever sees it.
 */
internal object SelfSignedCertificate {
    // ecdsa-with-SHA256 (1.2.840.10045.4.3.2), no parameters.
    private val ECDSA_SHA256 = der(0x30, der(0x06, bytes(0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02)))

    // CN=Passkey Vault
    private val NAME = der(
        0x30,
        der(0x31, der(0x30, der(0x06, bytes(0x55, 0x04, 0x03)) + der(0x0C, "Passkey Vault".toByteArray()))),
    )

    // 2000-01-01 to 9999-12-31: the certificate is never checked for dates, only stored.
    private val VALIDITY = der(0x30, der(0x17, "000101000000Z".toByteArray()) + der(0x18, "99991231235959Z".toByteArray()))

    fun create(publicKey: PublicKey, privateKey: PrivateKey): X509Certificate {
        val tbs = der(
            0x30,
            der(0x02, bytes(0x01)) + // serial number 1
                ECDSA_SHA256 + NAME + VALIDITY + NAME + publicKey.encoded,
        )
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(tbs)
            sign()
        }
        val cert = der(0x30, tbs + ECDSA_SHA256 + der(0x03, byteArrayOf(0) + signature))
        return CertificateFactory.getInstance("X.509").generateCertificate(cert.inputStream()) as X509Certificate
    }

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    /** One DER element: tag, length (short or long form), content. */
    private fun der(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        val n = content.size
        when {
            n < 0x80 -> out.write(n)
            n < 0x100 -> { out.write(0x81); out.write(n) }
            else -> { out.write(0x82); out.write(n ushr 8); out.write(n and 0xFF) }
        }
        out.write(content)
        return out.toByteArray()
    }
}
