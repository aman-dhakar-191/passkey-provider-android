// The Android Gradle Plugin brings these libraries onto the build's own classpaths (plugin, lint, R8), not
// into the app. The versions it picks have known vulnerabilities (flagged by the Security workflow's
// dependency review), so use fixed releases until AGP ships them. Remove an entry once AGP's own version
// is at least as new.
buildscript {
    configurations.classpath {
        resolutionStrategy.eachDependency {
            when (requested.group) {
                "org.bouncycastle" -> useVersion("1.86") // all BouncyCastle modules must share one version
                "org.bitbucket.b_c" -> if (requested.name == "jose4j") useVersion("0.9.7")
            }
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
            when (requested.group) {
                "org.bouncycastle" -> useVersion("1.86")
                "org.bitbucket.b_c" -> if (requested.name == "jose4j") useVersion("0.9.7")
            }
        }
    }
}
