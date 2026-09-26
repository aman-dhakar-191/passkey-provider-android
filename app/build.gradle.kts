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
        // The in-app passkey self-test and its reserved RP ID; never in release builds.
        buildConfigField("boolean", "SELF_TEST", "false")
    }

    signingConfigs {
        if (signingKeystore != null) {
            create("release") {
                storeFile = file(signingKeystore)
                storePassword = System.getenv("SIGNING_STORE_PASSWORD")
                keyAlias = System.getenv("SIGNING_KEY_ALIAS")
                keyPassword = System.getenv("SIGNING_KEY_PASSWORD")
                // v3 carries the signing-key lineage that stores (e.g. Indus) check; v2 for older verifiers.
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            // R8 shrinks unused code and resources. v1.0.1 crashed on launch because R8 removed
            // constructors that WorkManager and ML Kit create by reflection, and nothing had run a minified
            // build. The keep rules in proguard-rules.pro fix that, and the "minified" build type below runs
            // the emulator self-test on a build with these same R8 settings.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            buildConfigField("boolean", "SELF_TEST", "true")
        }
        // Release's R8 settings with the debug package, debug key and the self-test. Not debuggable, since
        // R8 skips its optimizations for debuggable builds and this must behave like release.
        // Only CI uses it (.github/workflows/emulator.yml).
        create("minified") {
            initWith(getByName("debug"))
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            matchingFallbacks += "debug"
        }
    }

    // Two release channels from the same code (src/main is shared):
    //  - github: sideloaded from GitHub Releases. src/github adds the self-updater, its permissions
    //            (REQUEST_INSTALL_PACKAGES, POST_NOTIFICATIONS) and WorkManager.
    //  - store:  Google Play / Indus Appstore, which deliver updates. src/store only has a stub, so the
    //            store app contains no update code at all (checked by scripts/check-store-build.sh).
    flavorDimensions += "distribution"
    productFlavors {
        create("github") {
            dimension = "distribution"
            // Activity log: every step of every request (this is the channel used for debugging).
            buildConfigField("boolean", "LOG_ALL_REQUESTS", "true")
            buildConfigField("String", "UPDATE_REPO", "\"$updateRepo\"")
        }
        create("store") {
            dimension = "distribution"
            // Activity log: only requests that went wrong, with the steps that led to it.
            buildConfigField("boolean", "LOG_ALL_REQUESTS", "false")
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
    "githubImplementation"(libs.androidx.work.runtime.ktx) // only the self-updater uses WorkManager
    implementation(libs.play.services.code.scanner)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.org.json)
}
