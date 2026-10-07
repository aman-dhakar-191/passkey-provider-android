package io.github.amandhakar.passkeydemo

import android.annotation.SuppressLint
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject

/**
 * A web page shown inside the app, the way some apps show their login page. Passkeys in a WebView only work
 * if the app turns WebAuthn on for it; the request then reaches the passkey provider as coming from this
 * app, which the site must vouch for in assetlinks.json.
 *
 * With no URL the demo site's own login page is loaded for real from https://<site>/ (WebAuthn needs a page
 * that really came over HTTPS, so a page faked from local HTML is refused by the WebView). What it gets back
 * from the passkey provider is sent here and checked, like the native buttons do: only pages from the
 * demo's own origin can reach that bridge. With a URL, any page can be tried; the provider's own activity
 * log then tells what it did.
 */
class WebLoginActivity : ComponentActivity() {
    private lateinit var status: TextView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val customUrl = intent.getStringExtra(EXTRA_URL)

        status = TextView(this).apply {
            textSize = 12f
            setPadding(24, 16, 24, 16)
            maxLines = 14
            movementMethod = ScrollingMovementMethod()
        }
        val web = WebView(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(status, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(web, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        }
        setContentView(root)
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.ime())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        val notes = mutableListOf<String>()
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.webViewClient = WebViewClient()

        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_AUTHENTICATION)) {
            WebSettingsCompat.setWebAuthenticationSupport(web.settings, WebSettingsCompat.WEB_AUTHENTICATION_SUPPORT_FOR_APP)
            notes += "WebAuthn is switched on for this WebView (for this app)."
        } else {
            notes += "This WebView has no WebAuthn support, so passkeys cannot work in it."
        }

        // Only a page from the demo's own site can talk to this app; any other page gets no bridge.
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            WebViewCompat.addWebMessageListener(web, "demoBridge", setOf("https://${BuildConfig.RP_ID}")) { _, message, _, _, _ ->
                handle(message.data)
            }
        } else {
            notes += "No message bridge: results will only show inside the page."
        }
        val url = customUrl ?: "https://${BuildConfig.RP_ID}/"
        web.loadUrl(url)
        notes += if (customUrl == null) {
            "Loaded the demo site's login page ($url)."
        } else {
            "Loaded $url. Open Passkey Vault's activity log to see what it did with the request."
        }
        status.text = notes.joinToString("\n")
    }

    private fun handle(data: String?) {
        val report = try {
            val message = JSONObject(data.orEmpty())
            when (val kind = message.optString("kind")) {
                "error" -> Report(
                    "Web page: passkey request",
                    listOf(Check("The page's passkey request succeeded", false, "${message.optString("name")}: ${message.optString("message")}")),
                    "If the site does not vouch for this app, the provider refuses; see its activity log.",
                )
                "create" -> {
                    val result = PasskeyVerifier.verifyRegistration(
                        BuildConfig.RP_ID,
                        PasskeyVerifier.unb64u(message.getString("challenge")),
                        message.getJSONObject("response").toString(),
                        expectedOrigin = null,
                    )
                    if (result.ok) {
                        DemoStore.save(this, result.credentialId.orEmpty(), result.publicKey ?: byteArrayOf(), "web page", "web")
                    }
                    Report("Web page: create passkey", result.checks)
                }
                "get" -> Report(
                    "Web page: sign in",
                    PasskeyVerifier.verifySignIn(
                        BuildConfig.RP_ID,
                        PasskeyVerifier.unb64u(message.getString("challenge")),
                        message.getJSONObject("response").toString(),
                        expectedOrigin = null,
                    ) { DemoStore.publicKey(this, it) },
                )
                else -> Report("Web page", listOf(Check("Message from the page was understood", false, "kind: $kind")))
            }
        } catch (e: Exception) {
            Report("Web page", listOf(Check("Message from the page could be read", false, "${e.javaClass.simpleName}: ${e.message}")))
        }
        status.text = report.toText()
    }

    companion object {
        const val EXTRA_URL = "url"
    }
}
