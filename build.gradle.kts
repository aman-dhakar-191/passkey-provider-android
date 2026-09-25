// The Android Gradle Plugin brings BouncyCastle onto the build's own classpaths (plugin, lint, R8), not
// into the app. Its version there has known vulnerabilities (flagged by the Security workflow's dependency
// review), so use the current release until AGP ships a fixed one. All BouncyCastle modules must share
// one version.
buildscript {
    configurations.classpath {
        resolutionStrategy.eachDependency {
            if (requested.group == "org.bouncycastle") useVersion("1.86")
        }
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

allprojects {
    configurations.configureEach {
        resolutionStrategy.eachDependency {
            if (requested.group == "org.bouncycastle") useVersion("1.86")
        }
    }
}
