// The Android Gradle Plugin brings these libraries onto the build's own classpaths (plugin, lint, R8), not
// into the app. The versions it picks have known vulnerabilities (flagged by the Security workflow's
// dependency review), so use fixed releases until AGP ships them. Remove an entry once AGP's own version
// is at least as new. (The list is repeated because the buildscript block can't see the rest of the file.)
buildscript {
    val fixed = mapOf(
        "org.bouncycastle" to "1.86", // all BouncyCastle modules must share one version
        "org.bitbucket.b_c:jose4j" to "0.9.7",
        "org.jdom:jdom2" to "2.0.6.1",
        "org.apache.commons:commons-lang3" to "3.20.0",
        "org.apache.httpcomponents:httpclient" to "4.5.14",
        "org.apache.httpcomponents:httpmime" to "4.5.14",
    )
    configurations.classpath {
        resolutionStrategy.eachDependency {
            (fixed["${requested.group}:${requested.name}"] ?: fixed[requested.group])?.let { useVersion(it) }
        }
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

val fixed = mapOf(
    "org.bouncycastle" to "1.86",
    "org.bitbucket.b_c:jose4j" to "0.9.7",
    "org.jdom:jdom2" to "2.0.6.1",
    "org.apache.commons:commons-lang3" to "3.20.0",
    "org.apache.httpcomponents:httpclient" to "4.5.14",
    "org.apache.httpcomponents:httpmime" to "4.5.14",
)

allprojects {
    configurations.configureEach {
        resolutionStrategy.eachDependency {
            (fixed["${requested.group}:${requested.name}"] ?: fixed[requested.group])?.let { useVersion(it) }
        }
    }
}
