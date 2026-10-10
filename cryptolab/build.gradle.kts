plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Crypto Lab: an experiment app for trying ways to encrypt data and send it to another phone over a secure
// channel (see cryptolab/README.md). Separate from Passkey Vault and Passkey Demo; nothing here ships in them.
// The protocol code (core/, transport/) has no Android imports, so its unit tests run on a plain JVM.

// Released like the demo (see .github/workflows/cryptolab-release.yml): tags cryptolab-vX.Y.Z, always marked as
// pre-releases so Passkey Vault's updater, which follows the repository's "latest" release, never sees them.
val appVersionName = (findProperty("appVersionName") as String?)?.removePrefix("v") ?: "0.1.0"
val appVersionCode = appVersionName.substringBefore('-').split('.')
    .map { it.toIntOrNull() ?: 0 }
    .let { it + List(3) { 0 } }
    .let { (major, minor, patch) -> major * 10_000 + minor * 100 + patch }

// Release signing comes from the environment (GitHub Actions secrets), as for the other apps.
val signingKeystore: String? = System.getenv("SIGNING_KEYSTORE_PATH")

android {
    namespace = "io.github.amandhakar.cryptolab"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.amandhakar.cryptolab"
        minSdk = 34
        targetSdk = 36
        versionCode = appVersionCode
        versionName = appVersionName
    }

    signingConfigs {
        if (signingKeystore != null) {
            create("release") {
                storeFile = file(signingKeystore)
                storePassword = System.getenv("SIGNING_STORE_PASSWORD")
                keyAlias = System.getenv("SIGNING_KEY_ALIAS")
                keyPassword = System.getenv("SIGNING_KEY_PASSWORD")
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false // a test tool: nothing to hide, and no R8 surprises
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = false
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.kotlinx.coroutines.android)
    // QR codes: ZXing draws the receiver's code; Google's code scanner (as in Passkey Vault) reads it.
    implementation(libs.zxing.core)
    implementation(libs.play.services.code.scanner)
    // The code scanner brings an old Fragment library; registerForActivityResult needs 1.3.0 or newer.
    implementation(libs.androidx.fragment.ktx)

    testImplementation(libs.junit)
}
