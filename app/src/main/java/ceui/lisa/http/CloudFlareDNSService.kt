package ceui.lisa.http

import okhttp3.OkHttpClient
import okhttp3.Protocol
import retrofit2.Call
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.Query
import retrofit2.http.Url
import java.util.Collections

interface CloudFlareDNSService {

    /**
     * 一次 DoH JSON 查询。
     *
     * <p>端点走 {@link Url} 逐次传入而不是拼在 baseUrl 上：预设端点与用户自定义端点
     * 的路径各不相同（/dns-query、/resolve、腾讯的 /dns-query…），写死 @GET("/dns-query")
     * 会把自定义地址上的路径整段覆盖掉。
     */
    @Headers("Accept: application/dns-json")
    @GET
    fun query(
        @Url url: String,
        @Query("name") name: String?,
        @Query("type") type: String = "A"
    ): Call<CloudFlareDNSResponse>

    companion object {

        //DOH:DNS over HTTPS。IP 形式，避免解析 DoH 域名这一步又落回被污染的本地 DNS。
        val CLOUDFLARE_DOH_POINT: String = "https://1.0.0.1/dns-query"
        val DNSSB_DOH_POINT: String = "https://185.222.222.222/dns-query"
        val TENCENT_DOH_POINT: String = "https://1.12.12.12/dns-query"

        private val dohClient: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .protocols(Collections.singletonList(Protocol.HTTP_1_1))
                .connectTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                .build()
        }

        private val service: CloudFlareDNSService by lazy {
            Retrofit.Builder()
                // 端点由 query(@Url) 逐次给出，baseUrl 只是 Retrofit 的必填占位。
                .baseUrl("https://localhost/")
                .addConverterFactory(GsonConverterFactory.create())
                .client(dohClient)
                .build()
                .create(CloudFlareDNSService::class.java)
        }

        operator fun invoke(): CloudFlareDNSService = service
    }
}
