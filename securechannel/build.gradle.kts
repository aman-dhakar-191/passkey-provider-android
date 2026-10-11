plugins {
    alias(libs.plugins.android.library)
}

// The secure channel shared by Crypto Lab and Passkey Vault's GitHub build (moving passkeys to a new phone):
// handshake (ECDH with a commitment, authenticated by a QR secret or a compared code), AEAD records, transfers
// and the TCP transport. No Android imports, so its unit tests run on a plain JVM. See cryptolab/README.md.

android {
    namespace = "io.github.amandhakar.securechannel"
    compileSdk = 37

    defaultConfig {
        minSdk = 34
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
    }
}

dependencies {
    testImplementation(libs.junit)
}
