package io.github.amandhakar.passkeydemo

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ReleasesTest {
    private val repo = "owner/repo"

    private fun release(tag: String, draft: Boolean = false, prerelease: Boolean = true, name: String? = null, url: String? = null, digest: String? = null): String {
        val version = tag.substringAfterLast("v")
        val file = name ?: "passkey-demo-$version.apk"
        val href = url ?: "https://github.com/$repo/releases/download/$tag/$file"
        val digestField = if (digest != null) ""","digest":"$digest"""" else ""
        return """{"tag_name":"$tag","draft":$draft,"prerelease":$prerelease,"body":"notes $tag","html_url":"https://github.com/$repo/releases/tag/$tag",
            "assets":[{"name":"$file","size":1234,"browser_download_url":"$href"$digestField},{"name":"$file.sha256","browser_download_url":"$href.sha256"}]}"""
    }

    private fun list(vararg items: String) = "[" + items.joinToString(",") + "]"

    @Test fun picksTheHighestDemoVersionAndIgnoresEverythingElse() {
        val json = list(
            release("v9.9.9", prerelease = false), // the Passkey Vault's own release
            release("demo-v1.2.0", digest = "sha256:abc"),
            release("demo-v1.10.0"), // numeric, not text, comparison
            release("demo-v1.9.0"),
            release("demo-v99.0.0", draft = true),
        )
        val latest = Releases.latest(json, repo)!!
        assertEquals("1.10.0", latest.version)
        assertEquals("https://github.com/$repo/releases/download/demo-v1.10.0/passkey-demo-1.10.0.apk", latest.apkUrl)
        assertEquals("notes demo-v1.10.0", latest.notes)
        assertNull(latest.sha256)
        assertEquals("abc", Releases.latest(list(release("demo-v1.2.0", digest = "sha256:abc")), repo)!!.sha256)
    }

    @Test fun refusesApksThatAreNotServedByThisRepositorysReleasePage() {
        assertNull(Releases.latest(list(release("demo-v1.0.0", url = "https://evil.example/passkey-demo-1.0.0.apk")), repo))
        assertNull(Releases.latest(list(release("demo-v1.0.0", url = "https://github.com/other/repo/releases/download/demo-v1.0.0/passkey-demo-1.0.0.apk")), repo))
        // The file must sit under its own release's tag.
        assertNull(Releases.latest(list(release("demo-v1.0.0", url = "https://github.com/$repo/releases/download/demo-v2.0.0/passkey-demo-1.0.0.apk")), repo))
        assertNull(Releases.latest(list(release("demo-v1.0.0", name = "other-app.apk")), repo))
    }

    @Test fun refusesOddVersionsAndEmptyLists() {
        assertNull(Releases.latest("[]", repo))
        assertNull(Releases.latest(list(release("demo-v1.0"), release("demo-v1.0.0-beta"), release("demo-v100.0.0")), repo))
    }

    @Test fun versionComparison() {
        assertTrue(AppVersion.isNewer("1.0.1", "1.0.0"))
        assertTrue(AppVersion.isNewer("1.10.0", "1.9.9"))
        assertFalse(AppVersion.isNewer("1.0.0", "1.0.0"))
        assertFalse(AppVersion.isNewer("1.0.0", "1.0.1-debug"))
        assertFalse(AppVersion.isNewer("0.9.0", "0.10.0"))
    }
}

class AssetLinksTest {
    private val pkg = "io.github.amandhakar.passkeydemo"
    private val fp = "AA:BB:CC"

    @Test fun theFileWeTellPeopleToPublishPassesOurOwnCheck() {
        val text = AssetLinks.file(pkg, fp)
        assertEquals(1, JSONArray(text).length())
        assertTrue(text.contains("delegate_permission/common.get_login_creds")) // not escaped as "\/"
        assertTrue(AssetLinks.analyze(200, text, pkg, fp).all { it.ok })
    }

    @Test fun explainsWhatIsMissing() {
        fun failed(status: Int?, body: String?, p: String = pkg, f: String = fp) =
            AssetLinks.analyze(status, body, p, f).filter { !it.ok }.map { it.name }
        assertEquals(1, failed(404, null).size)
        assertEquals(1, failed(null, "UnknownHostException").size)
        assertTrue(failed(200, "<html>").any { it.startsWith("It is a JSON list") })
        assertTrue(failed(200, "[]").any { it.startsWith("A statement names this app") })
        assertTrue(failed(200, AssetLinks.file("other.app", fp)).any { it.startsWith("A statement names this app") })
        assertTrue(failed(200, AssetLinks.file(pkg, "AA:BB:00")).any { it.startsWith("...and this app's signing certificate") })
        assertTrue(failed(200, AssetLinks.file(pkg, fp).replace("get_login_creds", "handle_all_urls")).any { it.startsWith("...with the get_login_creds") })
        // Fingerprint case does not matter.
        assertEquals(emptyList<String>(), failed(200, AssetLinks.file(pkg, fp.lowercase())))
    }
}
