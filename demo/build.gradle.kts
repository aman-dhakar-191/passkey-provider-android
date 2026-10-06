plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// A small app for trying passkeys the way other apps use them (see README, "Demo app"). Released separately
// from Passkey Vault: tags demo-vX.Y.Z, always marked as pre-releases so Passkey Vault's updater, which
// follows the repository's "latest" release, never sees them.
val appVersionName = (findProperty("appVersionName") as String?)?.removePrefix("v") ?: "0.1.0"
val appVersionCode = appVersionName.substringBefore('-').split('.')
    .map { it.toIntOrNull() ?: 0 }
    .let { it + List(3) { 0 } }
    .let { (major, minor, patch) -> major * 10_000 + minor * 100 + patch }

// The site whose passkeys the demo uses. It must publish /.well-known/assetlinks.json naming this app, or the
// passkey provider refuses (that is part of what the demo shows).
val demoRpId = (findProperty("demoRpId") as String?) ?: "aman-dhakar-191.github.io"
val updateRepo = (findProperty("updateRepo") as String?) ?: "aman-dhakar-191/passkey-provider-android"

// Release signing comes from the environment (GitHub Actions secrets), as for the main app.
val signingKeystore: String? = System.getenv("SIGNING_KEYSTORE_PATH")

android {
    namespace = "io.github.amandhakar.passkeydemo"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.amandhakar.passkeydemo"
        // Same as Passkey Vault: third-party credential providers need Android 14.
        minSdk = 34
        targetSdk = 36
        versionCode = appVersionCode
        versionName = appVersionName
        buildConfigField("String", "RP_ID", "\"$demoRpId\"")
        buildConfigField("String", "UPDATE_REPO", "\"$updateRepo\"")
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
        buildConfig = true
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
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.webkit)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.org.json)
}
