package com.visi8.myapplication

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.Bitmap
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.net.Uri
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.CookieManager
import android.webkit.WebSettings
import android.view.WindowManager
import android.util.Log
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.view.KeyEvent
import android.webkit.WebChromeClient
import java.security.KeyStore

//class KeystoreHelper {
//    companion object {
//        private const val KEY_ALIAS = "Visi8WebcomicCookieKey"
//        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
//        private const val TRANSFORMATION = "AES/CBC/PKCS7Padding"
//    }
//
//    init {
//        createKey()
//    }
//
//    private fun createKey() {
//        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
//        val keyGenParameterSpec = KeyGenParameterSpec.Builder(KEY_ALIAS,
//            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
//            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
//            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
//            .build()
//        keyGenerator.init(keyGenParameterSpec)
//        keyGenerator.generateKey()
//    }
//
//    private fun getSecretKey(): SecretKey {
//        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
//        keyStore.load(null)
//        return keyStore.getKey(KEY_ALIAS, null) as SecretKey
//    }
//
//    fun encrypt(data: String): String {
//        val cipher = Cipher.getInstance(TRANSFORMATION)
//        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
//        val iv = cipher.iv
//        val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
//        return Base64.encodeToString(iv + encrypted, Base64.DEFAULT)
//    }
//
//    fun decrypt(data: String): String {
//        val dataArray = Base64.decode(data, Base64.DEFAULT)
//        val cipher = Cipher.getInstance(TRANSFORMATION)
//        val ivSpec = IvParameterSpec(dataArray.copyOfRange(0, 16))
//        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), ivSpec)
//        val decrypted = cipher.doFinal(dataArray.copyOfRange(16, dataArray.size))
//        return String(decrypted, Charsets.UTF_8)
//    }
//}

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var sharedPreferences: SharedPreferences
//    private lateinit var keystoreHelper: KeystoreHelper

    override fun dispatchKeyEvent(event: KeyEvent?): Boolean {
        if (event?.keyCode == 4 && webView.canGoBack()) {
            webView.goBack()
            return true
        }
        return super.dispatchKeyEvent(event)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleIntent(it) }
    }

    private fun handleIntent(intent: Intent) {
        val action = intent.action
        val data = intent.data

        if (Intent.ACTION_VIEW == action && data != null) {
            navigateToPage(data)
        }
    }

    private fun navigateToPage(uri: Uri) {
        uri.let {
            val pathSegments = it.pathSegments
            Log.d("navigateToPage", pathSegments.joinToString())
            if (pathSegments.size >= 2) {
                if (pathSegments[0] == "ping" && pathSegments[1] == "pong") {
                    val newUrl = "https://rqcbppup9ngtdtz1mazunlsap7ywijlzugrryfgbb4lk0sqjny.web.app/ping-pong/"
                    webView.loadUrl(newUrl)
                } else {
                    val newUrl = "https://rqcbppup9ngtdtz1mazunlsap7ywijlzugrryfgbb4lk0sqjny.web.app/comic/${pathSegments[0]}/chapter/${pathSegments[1]}/"
                    webView.loadUrl(newUrl)
                }
            }
        }
    }

    private fun saveCookies() {
        val cookieManager = CookieManager.getInstance()
        val cookieString = cookieManager.getCookie("https://rqcbppup9ngtdtz1mazunlsap7ywijlzugrryfgbb4lk0sqjny.web.app/")
        if (cookieString != null) {
            sharedPreferences.edit().apply {
                putString("cookies", cookieString)
                apply()
            }
        }
    }

    private fun loadCookies() {
        val cookies = sharedPreferences.getString("cookies", null)
        cookies?.let {
            val cookieManager = CookieManager.getInstance()
            it.split(";").forEach { cookie ->
                cookieManager.setCookie("https://rqcbppup9ngtdtz1mazunlsap7ywijlzugrryfgbb4lk0sqjny.web.app/", cookie)
            }
        }
    }

    override fun onPause() {
        super.onPause()
        saveCookies() // Save cookies when the app is paused
    }

    private fun saveLocalStorageData(data: String) {
        Log.d("saveLocalStorageData", data)
        sharedPreferences.edit().putString("localStorageData", data).apply()
    }

    private fun deleteLocalStorageData() {
        sharedPreferences.edit().remove("localStorageData").apply()
    }

    private fun loadLocalStorageData() {
        val encryptedData = sharedPreferences.getString("localStorageData", null)
        encryptedData?.let {
            Log.d("loadLocalStorageData", it)
            webView.evaluateJavascript(
                "(function() { var data = JSON.parse($it); for (var key in data) { localStorage.setItem(key, data[key]); } })();",
                null
            )
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.d("onCreate", "start")

        val deviceModel = Build.MODEL
        val chromeVersion = "120.0.6099.109" // Replace with the desired Chrome version
        val androidVersion = Build.VERSION.RELEASE
        val customUserAgent = "Mozilla/5.0 (Linux; Android $androidVersion; $deviceModel) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$chromeVersion Mobile Safari/537.36"

        sharedPreferences = getSharedPreferences("WebViewCookies", Context.MODE_PRIVATE)
        // Prevent taking screenshots and recording screen
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // setContentView(R.layout.activity_main)

        webView = WebView(this)
        setContentView(webView)

        webView.apply {
            Log.d("onCreate", "apply webview")
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowContentAccess = true
            settings.allowFileAccess = true
            settings.javaScriptCanOpenWindowsAutomatically = true
            settings.cacheMode = WebSettings.LOAD_CACHE_ELSE_NETWORK
            settings.mixedContentMode = 0
            settings.mediaPlaybackRequiresUserGesture = false
            settings.useWideViewPort = true
            settings.loadWithOverviewMode = true
            settings.pluginState = WebSettings.PluginState.ON
            settings.userAgentString = customUserAgent

            webViewClient = object : WebViewClient() {
                override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                    super.onPageStarted(view, url, favicon)
                    loadLocalStorageData()
                }
                override fun shouldOverrideUrlLoading(
                    view: WebView?,
                    url: String?
                ): Boolean {
                    if (url != null) {
                        val uri = Uri.parse(url)
                        val browserOverride = uri.getQueryParameter("browserOverride")

                        if (browserOverride == "true") {
                            view?.context?.startActivity(
                                Intent(Intent.ACTION_VIEW, uri)
                            )
                            return true
                        }
                    }

                    return false
                }
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    view?.evaluateJavascript(
                        "(function() { var ls = localStorage; var data = {}; for (var i = 0; i < ls.length; i++) { var key = ls.key(i); data[key] = ls.getItem(key); } return JSON.stringify(data); })();"
                    ) { localStorageData ->
                        // Handle the localStorage data
                        saveLocalStorageData(localStorageData)
                    }
                    saveCookies()
                }
            }
            loadCookies()
            loadUrl("https://rqcbppup9ngtdtz1mazunlsap7ywijlzugrryfgbb4lk0sqjny.web.app/")
        }

        intent?.let { handleIntent(it) }
    }
}