plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Version comes from the git tag in CI (-PappVersionName=1.2.3). versionCode is derived from it so
// every release is strictly increasing, which Android requires for an in-place update.
val appVersionName = (findProperty("appVersionName") as String?)?.removePrefix("v") ?: "0.1.0"
val appVersionCode = appVersionName.substringBefore('-').split('.')
    .map { it.toIntOrNull() ?: 0 }
    .let { it + List(3) { 0 } }
    .let { (major, minor, patch) -> major * 10_000 + minor * 100 + patch }

val updateRepo = (findProperty("updateRepo") as String?) ?: "aman-dhakar-191/passkey-provider-android"

// Release signing keys come from the environment (GitHub Actions secrets). The same key must sign every
// release, otherwise Android refuses to install the update over the existing app.
val signingKeystore: String? = System.getenv("SIGNING_KEYSTORE_PATH")

android {
    namespace = "io.github.amandhakar.passkey"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.amandhakar.passkey"
        // Third-party credential providers need the Credential Manager framework from Android 14.
        minSdk = 34
        // Play requires targeting a recent Android release; 36 = Android 16.
        targetSdk = 36
        versionCode = appVersionCode
        versionName = appVersionName
        buildConfigField("String", "UPDATE_REPO", "\"$updateRepo\"")
    }

    signingConfigs {
        if (signingKeystore != null) {
            create("release") {
                storeFile = file(signingKeystore)
                storePassword = System.getenv("SIGNING_STORE_PASSWORD")
                keyAlias = System.getenv("SIGNING_KEY_ALIAS")
                keyPassword = System.getenv("SIGNING_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // R8 stripped constructors that WorkManager and ML Kit create by reflection at startup, and
            // v1.0.1 crashed on launch. The app is sideloaded, so a few MB saved is not worth that risk.
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    // Two release channels from the same code:
    //  - github: sideloaded from GitHub Releases, updates itself (REQUEST_INSTALL_PACKAGES).
    //  - store:  Google Play / Indus Appstore. Stores deliver updates, so no self-updater, no
    //            install-packages or notification permission (removed in src/store/AndroidManifest.xml).
    flavorDimensions += "distribution"
    productFlavors {
        create("github") {
            dimension = "distribution"
            buildConfigField("boolean", "SELF_UPDATE", "true")
        }
        create("store") {
            dimension = "distribution"
            buildConfigField("boolean", "SELF_UPDATE", "false")
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
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.play.services.code.scanner)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.org.json)
}
