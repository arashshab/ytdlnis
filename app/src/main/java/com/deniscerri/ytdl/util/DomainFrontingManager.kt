package com.deniscerri.ytdl.util

import android.content.Context
import android.util.Log
import androidx.preference.PreferenceManager
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.Interceptor
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.ConnectionSpec
import okhttp3.TlsVersion
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * DomainFrontingManager
 *
 * این کلاس Domain Fronting را داخل خود اپ پیاده‌سازی می‌کنه
 * بدون نیاز به نصب هیچ certificate روی سیستم
 *
 * منطق کار:
 * - وقتی درخواست به google.com/youtube/drive رفت
 * - IP اصلی از CDN گرفته می‌شه (Fastly, Google, Microsoft)
 * - SNI (Server Name Indication) با یه دامنه دیگه پر می‌شه
 * - فیلترینگ فکر می‌کنه داری به یه دامنه دیگه وصل می‌شی
 *
 * پیکربندی قابل تغییر در Settings > Network
 */
object DomainFrontingManager {

    private const val TAG = "DomainFrontingManager"

    // ===== کانفیگ پیش‌فرض (از کانفیگ MITM-DomainFronting_v22) =====
    data class FrontingConfig(
        val enabled: Boolean = false,
        val frontingProfile: String = "google", // google | fastly | microsoft | custom
        // Custom تنظیمات
        val customFrontDomain: String = "www.google.com",       // SNI که ارسال می‌شه
        val customTargetHost: String = "www.googleapis.com",    // هدف واقعی
        val customResolveIp: String = ""                        // IP مستقیم (اختیاری)
    )

    // پروفایل‌های آماده
    val PROFILES = mapOf(
        "google" to ProfileDef(
            name = "Google / YouTube / Drive",
            frontDomain = "www.google.com",
            acceptedDomains = listOf(
                "google.com", "youtube.com", "googleapis.com",
                "googlevideo.com", "ggpht.com", "gstatic.com",
                "drive.google.com", "docs.google.com"
            ),
            resolveViaDomain = "www.google.com"
        ),
        "fastly" to ProfileDef(
            name = "Fastly CDN (GitHub, Reddit, Python...)",
            frontDomain = "github.githubassets.com",
            acceptedDomains = listOf(
                "github.com", "githubusercontent.com", "githubassets.com",
                "reddit.com", "redd.it", "python.org", "pypi.org",
                "fastly.com", "fastly.net", "buzzfeed.com"
            ),
            resolveViaDomain = "github.githubassets.com"
        ),
        "microsoft" to ProfileDef(
            name = "Microsoft / Meta / WhatsApp",
            frontDomain = "www.microsoft.com",
            acceptedDomains = listOf(
                "microsoft.com", "whatsapp.com", "facebook.com",
                "instagram.com", "meta.com", "fbcdn.net", "whatsapp.net"
            ),
            resolveViaDomain = "www.microsoft.com"
        )
    )

    data class ProfileDef(
        val name: String,
        val frontDomain: String,
        val acceptedDomains: List<String>,
        val resolveViaDomain: String
    )

    // ===== ساخت OkHttpClient با Domain Fronting =====

    /**
     * یه OkHttpClient می‌سازه که:
     * 1. دامنه‌های هدف رو تشخیص می‌ده
     * 2. SNI رو عوض می‌کنه (Domain Fronting)
     * 3. cert validation رو برای دامنه‌های CDN انجام می‌ده (بدون نصب cert)
     * 4. اگه Domain Fronting غیرفعال باشه، مثل OkHttp معمولی رفتار می‌کنه
     */
    fun buildClient(context: Context, baseBuilder: OkHttpClient.Builder = OkHttpClient.Builder()): OkHttpClient {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        val config = loadConfig(prefs)

        if (!config.enabled) {
            // Domain Fronting غیرفعاله - کلاینت معمولی
            return baseBuilder.build()
        }

        Log.d(TAG, "Domain Fronting فعال - پروفایل: ${config.frontingProfile}")

        val profile = if (config.frontingProfile == "custom") {
            ProfileDef(
                name = "Custom",
                frontDomain = config.customFrontDomain,
                acceptedDomains = listOf(config.customTargetHost),
                resolveViaDomain = config.customFrontDomain
            )
        } else {
            PROFILES[config.frontingProfile] ?: PROFILES["google"]!!
        }

        // SSL Context که cert validation رو کنترل می‌کنه
        val sslContext = buildDomainFrontingSSLContext(profile)
        val hostnameVerifier = buildDomainFrontingHostnameVerifier(profile)

        return baseBuilder
            .sslSocketFactory(
                DomainFrontingSSLSocketFactory(sslContext.socketFactory, profile),
                buildTrustManager()
            )
            .hostnameVerifier(hostnameVerifier)
            .addInterceptor(DomainFrontingInterceptor(profile))
            .dns(DomainFrontingDns(profile))
            .build()
    }

    // ===== Interceptor: هدر Host رو عوض می‌کنه =====
    private class DomainFrontingInterceptor(private val profile: ProfileDef) : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val originalRequest = chain.request()
            val host = originalRequest.url.host

            val isTarget = profile.acceptedDomains.any { domain ->
                host == domain || host.endsWith(".$domain")
            }

            if (!isTarget) {
                return chain.proceed(originalRequest)
            }

            Log.d(TAG, "Domain Fronting فعال برای: $host → SNI: ${profile.frontDomain}")

            // درخواست رو با SNI front domain بفرست
            // ولی Host header اصلی رو نگه دار
            val newRequest = originalRequest.newBuilder()
                .build()

            return chain.proceed(newRequest)
        }
    }

    // ===== DNS: IP سرور front domain رو برمی‌گردونه =====
    private class DomainFrontingDns(private val profile: ProfileDef) : okhttp3.Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            val isTarget = profile.acceptedDomains.any { domain ->
                hostname == domain || hostname.endsWith(".$domain")
            }

            return if (isTarget) {
                try {
                    // IP از front domain بگیر (مثلاً www.google.com)
                    val addresses = InetAddress.getAllByName(profile.resolveViaDomain).toList()
                    Log.d(TAG, "DNS: $hostname → از ${profile.resolveViaDomain} → ${addresses.map { it.hostAddress }}")
                    addresses
                } catch (e: Exception) {
                    Log.e(TAG, "DNS lookup خطا: $e")
                    okhttp3.Dns.SYSTEM.lookup(hostname)
                }
            } else {
                okhttp3.Dns.SYSTEM.lookup(hostname)
            }
        }
    }

    // ===== SSL Socket Factory: SNI رو تغییر می‌ده =====
    private class DomainFrontingSSLSocketFactory(
        private val delegate: SSLSocketFactory,
        private val profile: ProfileDef
    ) : SSLSocketFactory() {

        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        override fun createSocket(): Socket = delegate.createSocket()

        override fun createSocket(host: String, port: Int): Socket {
            val socket = delegate.createSocket(host, port)
            setSni(socket, host)
            return socket
        }

        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket {
            val socket = delegate.createSocket(host, port, localHost, localPort)
            setSni(socket, host)
            return socket
        }

        override fun createSocket(host: InetAddress, port: Int): Socket {
            return delegate.createSocket(host, port)
        }

        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket {
            return delegate.createSocket(address, port, localAddress, localPort)
        }

        override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
            val isTarget = profile.acceptedDomains.any { domain ->
                host == domain || host.endsWith(".$domain")
            }

            // SNI رو با front domain عوض کن
            val sniToUse = if (isTarget) {
                Log.d(TAG, "SSL SNI: $host → ${profile.frontDomain}")
                profile.frontDomain
            } else {
                host
            }

            val socket = delegate.createSocket(s, sniToUse, port, autoClose) as SSLSocket
            socket.sslParameters = socket.sslParameters.apply {
                serverNames = listOf(javax.net.ssl.SNIHostName(sniToUse))
            }
            return socket
        }

        private fun setSni(socket: Socket, host: String) {
            if (socket is SSLSocket) {
                val isTarget = profile.acceptedDomains.any { domain ->
                    host == domain || host.endsWith(".$domain")
                }
                if (isTarget) {
                    socket.sslParameters = socket.sslParameters.apply {
                        serverNames = listOf(javax.net.ssl.SNIHostName(profile.frontDomain))
                    }
                }
            }
        }
    }

    // ===== Hostname Verifier: cert از front domain رو قبول می‌کنه =====
    private fun buildDomainFrontingHostnameVerifier(profile: ProfileDef): HostnameVerifier {
        return HostnameVerifier { hostname, session ->
            // اگه target domain هست، cert از front domain قبول کن
            val isTarget = profile.acceptedDomains.any { domain ->
                hostname == domain || hostname.endsWith(".$domain")
            }

            if (isTarget) {
                // cert از front domain باشه قبوله (هر دو روی یه CDN هستن)
                try {
                    val peerCerts = session.peerCertificates
                    val cert = peerCerts.firstOrNull() as? X509Certificate
                    if (cert != null) {
                        val san = cert.subjectAlternativeNames
                        val validNames = buildList {
                            add(profile.frontDomain)
                            addAll(profile.acceptedDomains)
                            // wildcard رو هم قبول کن
                            profile.acceptedDomains.forEach { d ->
                                add("*.$d")
                            }
                            add("*.${profile.frontDomain.substringAfter(".")}")
                        }

                        // اگه cert از یه دامنه شناخته‌شده روی همین CDN بود، قبوله
                        val certName = cert.subjectDN?.name ?: ""
                        val sanNames = san?.flatMap { it.toList() }
                            ?.filterIsInstance<String>() ?: emptyList()

                        val allCertNames = sanNames + certName

                        val isValid = allCertNames.any { certHost ->
                            validNames.any { validName ->
                                if (validName.startsWith("*")) {
                                    certHost.endsWith(validName.substring(1))
                                } else {
                                    certHost == validName || certHost.endsWith(".${validName.substringAfter(".")}")
                                }
                            }
                        }

                        if (isValid) {
                            Log.d(TAG, "✓ cert معتبر برای $hostname از CDN ${profile.frontDomain}")
                            return@HostnameVerifier true
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "خطا در بررسی cert: $e")
                }
                // fallback: default verifier
                HttpsURLConnection.getDefaultHostnameVerifier().verify(profile.frontDomain, session)
            } else {
                HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session)
            }
        }
    }

    // ===== SSL Context استاندارد =====
    private fun buildDomainFrontingSSLContext(profile: ProfileDef): SSLContext {
        val trustManager = buildTrustManager()
        return SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustManager), SecureRandom())
        }
    }

    private fun buildTrustManager(): X509TrustManager {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        return factory.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    // ===== ذخیره و بارگذاری تنظیمات =====

    fun loadConfig(prefs: android.content.SharedPreferences): FrontingConfig {
        return FrontingConfig(
            enabled = prefs.getBoolean(PREF_ENABLED, false),
            frontingProfile = prefs.getString(PREF_PROFILE, "google") ?: "google",
            customFrontDomain = prefs.getString(PREF_CUSTOM_FRONT, "www.google.com") ?: "www.google.com",
            customTargetHost = prefs.getString(PREF_CUSTOM_TARGET, "www.googleapis.com") ?: "www.googleapis.com",
            customResolveIp = prefs.getString(PREF_CUSTOM_IP, "") ?: ""
        )
    }

    fun saveConfig(prefs: android.content.SharedPreferences, config: FrontingConfig) {
        prefs.edit().apply {
            putBoolean(PREF_ENABLED, config.enabled)
            putString(PREF_PROFILE, config.frontingProfile)
            putString(PREF_CUSTOM_FRONT, config.customFrontDomain)
            putString(PREF_CUSTOM_TARGET, config.customTargetHost)
            putString(PREF_CUSTOM_IP, config.customResolveIp)
            apply()
        }
    }

    // کلیدهای SharedPreferences
    const val PREF_ENABLED = "domain_fronting_enabled"
    const val PREF_PROFILE = "domain_fronting_profile"
    const val PREF_CUSTOM_FRONT = "domain_fronting_custom_front"
    const val PREF_CUSTOM_TARGET = "domain_fronting_custom_target"
    const val PREF_CUSTOM_IP = "domain_fronting_custom_ip"
}
