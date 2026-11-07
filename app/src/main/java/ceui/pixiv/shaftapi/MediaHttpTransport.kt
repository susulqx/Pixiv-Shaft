package ceui.pixiv.shaftapi

import ceui.lisa.activities.Shaft
import ceui.lisa.http.CronetInterceptor
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

/** Process-wide pools. Auth and media metadata share TLS connections; only the API pool may carry the
 * direct-connect interceptor (see [apiClient]). */
internal object MediaHttpTransport {
    /**
     * api.pixshaft.com rides Cronet when direct connect is on: its TCP+TLS ClientHello is reset on
     * this network while HTTP/3 to the same Cloudflare IP answers 200. Everything derived from this
     * client (history, auth, plaza, stickers, [prewarm]) inherits that path.
     *
     * storageClient deliberately does not: it only serves media.pixshaft.com, a Tencent COS bucket
     * with no HTTP/3, and media.pixshaft.com is not in the interceptor's host allowlist anyway.
     */
    @Volatile private var api: OkHttpClient = buildApiClient()
    val apiClient: OkHttpClient get() = api
    val storageClient: OkHttpClient =
        OkHttpClient.Builder().eventListenerFactory(MediaNetworkTiming.factory).build()

    private fun buildApiClient(): OkHttpClient =
        OkHttpClient.Builder()
            .eventListenerFactory(MediaNetworkTiming.factory)
            .apply {
                if (Shaft.sSettings?.isDirectConnect == true) {
                    CronetInterceptor.installOn(this, Shaft.getContext())
                }
            }
            .build()

    /**
     * 直连开关切换后必须重建：拦截器只在这一刻挂载，不重建就要重启 App 才生效
     * （与 [ceui.pixiv.api.Client.reset] 同款诉求）。派生出本 client 的 history/auth/plaza/
     * sticker 客户端都在用点上取 [apiClient]，所以换掉这里等于全部换掉。
     */
    fun reset() {
        api = buildApiClient()
    }

    private val warmingApi = AtomicBoolean()
    private val warmingStorage = AtomicBoolean()

    /** Hide cold DNS/TCP/TLS setup behind the picker. Never wait for this in upload(). */
    fun prewarm() {
        warm(apiClient, "https://api.pixshaft.com/health", warmingApi)
        warm(storageClient, "https://media.pixshaft.com/", warmingStorage)
    }

    internal fun warm(client: OkHttpClient, url: String, running: AtomicBoolean) {
        if (client.connectionPool.connectionCount() > 0 || !running.compareAndSet(false, true))
            return
        val trace = MediaUploadTrace("prewarm")
        val request =
            Request.Builder().url(url).head().tag(MediaUploadTrace::class.java, trace).build()
        trace.stage("connection", "host=${request.url.host}")
        client
            .newBuilder()
            .callTimeout(3, TimeUnit.SECONDS)
            .build()
            .newCall(request)
            .enqueue(
                object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        running.set(false)
                        trace.event("unavailable", "type=${e.javaClass.simpleName}")
                    }

                    override fun onResponse(call: Call, response: Response) {
                        // A private COS root may answer 403/404; its HTTPS connection is still
                        // reusable.
                        response.use { trace.event("ready", "http=${it.code}") }
                        running.set(false)
                    }
                }
            )
    }
}
