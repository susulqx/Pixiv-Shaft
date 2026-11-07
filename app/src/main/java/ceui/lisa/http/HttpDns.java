package ceui.lisa.http;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import ceui.lisa.activities.Shaft;
import ceui.lisa.utils.Common;
import ceui.lisa.utils.Settings;
import okhttp3.Dns;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

public class HttpDns implements Dns {

    private static final String[] DOMAINS = {
            "app-api.pixiv.net",
            "oauth.secure.pixiv.net",
    };

    // Pixiv API/OAuth 已迁移至 Cloudflare CDN (2026-04)，与 CronetInterceptor 共享
    private static final String[] FALLBACK_API_IPS = {
            CronetInterceptor.CF_IP_PRIMARY,
            CronetInterceptor.CF_IP_SECONDARY,
    };

    // 图片服务器还在旧 Pixiv 基础设施
    private static final String[] FALLBACK_IMAGE_IPS = {
            "210.140.139.134",
            "210.140.139.133",
            "210.140.139.131",
    };

    /**
     * Pixiv API 域名只认 Cloudflare 的这两个 /13（104.16–104.23 与 172.64–172.71）：
     * {@link CronetInterceptor#CF_IP_PRIMARY} 与实测的正解都落在里面。
     */
    static boolean isCloudflareIp(InetAddress address) {
        byte[] b = address.getAddress();
        if (b.length != 4) {
            return false;
        }
        int second = b[1] & 0xFF;
        return (b[0] == 104 && second >= 16 && second <= 23)
                || (b[0] == (byte) 172 && second >= 64 && second <= 71);
    }

    /** 图片服务器仍是旧 Pixiv 基础设施，实测全部落在 210.140.139.0/24。 */
    static boolean isPixivImageIp(InetAddress address) {
        byte[] b = address.getAddress();
        return b.length == 4
                && b[0] == (byte) 210 && b[1] == (byte) 140 && b[2] == (byte) 139;
    }

    /**
     * DoH 答案是否可信。墙内的 DoH（实测 223.5.5.5）对 pixiv 域名会返回**污染但有值**的答案
     * —— 阿里把 app-api 解到 104.244.43.248、把 i.pximg.net 解到 108.160.169.55。这类答案
     * 一旦进缓存，{@link #lookup(String)} 永远走不到硬编码兜底，比解析失败更难排查。
     *
     * <p>只校验我们自己认得的域名族；不认识的 host 原样放行，免得替别人的域名做主。
     */
    static boolean isTrustedAnswer(String hostname, InetAddress address) {
        if (hostname.endsWith("pximg.net")) {
            return isPixivImageIp(address);
        }
        if (hostname.endsWith("pixiv.net")) {
            return isCloudflareIp(address);
        }
        return true;
    }

    private final Map<String, List<InetAddress>> resolvedHosts = new ConcurrentHashMap<>();
    private static volatile HttpDns sHttpDns = null;
    private List<InetAddress> fallbackApiAddresses;
    private List<InetAddress> fallbackImageAddresses;

    private HttpDns() {
        fallbackApiAddresses = new ArrayList<>();
        for (String ip : FALLBACK_API_IPS) {
            try {
                fallbackApiAddresses.add(InetAddress.getByName(ip));
            } catch (UnknownHostException ignored) {
            }
        }
        fallbackImageAddresses = new ArrayList<>();
        for (String ip : FALLBACK_IMAGE_IPS) {
            try {
                fallbackImageAddresses.add(InetAddress.getByName(ip));
            } catch (UnknownHostException ignored) {
            }
        }
        if (isSecureDnsEnabled()) {
            for (String domain : DOMAINS) {
                resolveViaDoH(domain);
            }
        }
    }

    public static HttpDns getInstance() {
        if (sHttpDns == null) {
            synchronized (HttpDns.class) {
                if (sHttpDns == null) {
                    sHttpDns = new HttpDns();
                }
            }
        }
        return sHttpDns;
    }

    // 设置项切换时调用：Glide 等持有的 OkHttpClient 仍引用同一个 HttpDns 实例，
    // 所以这里清空已缓存的 DoH 结果，并按当前设置重新预热，让切换立即生效。
    public static void invalidate() {
        HttpDns instance = sHttpDns;
        if (instance == null) {
            return;
        }
        instance.resolvedHosts.clear();
        if (isSecureDnsEnabled()) {
            for (String domain : DOMAINS) {
                instance.resolveViaDoH(domain);
            }
        }
    }

    private static boolean isSecureDnsEnabled() {
        return Shaft.sSettings != null && Shaft.sSettings.isUseSecureDns();
    }

    /**
     * 当前设置对应的 DoH 端点，{@code null} 表示不启用 DoH。
     *
     * <p>每个档位只对应**一个**端点：用户选哪个就走哪个，不做按序回落 ——
     * 回落会让「我选了 Cloudflare」在不经意间变成走 DNS.SB，这比解析失败更难排查。
     * 失败时 {@link #lookup(String)} 会落到下面的硬编码兜底 IP。
     */
    private static String currentEndpoint() {
        if (Shaft.sSettings == null) {
            return null;
        }
        switch (Shaft.sSettings.getDohMode()) {
            case Settings.DOH_MODE_CLOUDFLARE:
                return CloudFlareDNSService.Companion.getCLOUDFLARE_DOH_POINT();
            case Settings.DOH_MODE_DNSSB:
                return CloudFlareDNSService.Companion.getDNSSB_DOH_POINT();
            case Settings.DOH_MODE_TENCENT:
                return CloudFlareDNSService.Companion.getTENCENT_DOH_POINT();
            case Settings.DOH_MODE_CUSTOM:
                // 非法地址一律当作关闭，避免每次请求都在一个拼不出的 URL 上超时 3 秒。
                return normalizeEndpoint(Shaft.sSettings.getCustomDohUrl());
            default:
                return null;
        }
    }

    /**
     * 校验并规整自定义 DoH 端点。只接受 http(s) 绝对地址；裸域名补 https://。
     *
     * <p>与 {@link AppApiProxyInterceptor#normalizeBase(String)} 同款取舍，但**不去掉结尾斜杠**：
     * /dns-query 这类路径是 DoH 端点的组成部分，不能被当成多余的尾巴吃掉。
     */
    public static String normalizeEndpoint(String raw) {
        if (raw == null) {
            return null;
        }
        String url = raw.trim();
        if (url.isEmpty()) {
            return null;
        }
        if (!url.contains("://")) {
            url = "https://" + url;
        }
        String lower = url.toLowerCase();
        if (!lower.startsWith("https://") && !lower.startsWith("http://")) {
            return null;
        }
        // 带 query / fragment 的地址不是 DoH 端点，直接拒绝。
        if (url.indexOf('?') >= 0 || url.indexOf('#') >= 0) {
            return null;
        }
        return url;
    }

    private void resolveViaDoH(String hostname) {
        String endpoint = currentEndpoint();
        if (endpoint == null) {
            Common.showLog("HttpDns no DoH endpoint for " + hostname + ", will use fallback IPs");
            return;
        }
        try {
            CloudFlareDNSService.Companion.invoke()
                    .query(endpoint, hostname, "A")
                    .enqueue(new Callback<CloudFlareDNSResponse>() {
                        @Override
                        public void onResponse(Call<CloudFlareDNSResponse> call,
                                               Response<CloudFlareDNSResponse> response) {
                            CloudFlareDNSResponse body = response.body();
                            if (body != null && !Common.isEmpty(body.getAnswer())) {
                                List<InetAddress> addresses = new ArrayList<>();
                                List<String> rejected = new ArrayList<>();
                                for (CloudFlareDNSResponse.DNSAnswer answer : body.getAnswer()) {
                                    try {
                                        if (answer.getType() == 1) {
                                            InetAddress address = InetAddress.getByName(answer.getData());
                                            if (isTrustedAnswer(hostname, address)) {
                                                addresses.add(address);
                                            } else {
                                                rejected.add(answer.getData());
                                            }
                                        }
                                    } catch (Exception ignored) {
                                    }
                                }
                                if (!rejected.isEmpty()) {
                                    // 有值但落在别的网段 = 被污染。记下来，别让它在缓存里冒充正解。
                                    Common.showLog("HttpDns rejected polluted answer for " + hostname
                                            + " via " + endpoint + ": " + rejected);
                                }
                                if (!addresses.isEmpty()) {
                                    resolvedHosts.put(hostname, addresses);
                                    Common.showLog("HttpDns resolved " + hostname + " -> " + addresses
                                            + " via " + endpoint);
                                    return;
                                }
                            }
                            Common.showLog("HttpDns empty or untrusted answer for " + hostname + " via "
                                    + endpoint + ", will use fallback IPs");
                        }

                        @Override
                        public void onFailure(Call<CloudFlareDNSResponse> call, Throwable t) {
                            Common.showLog("HttpDns DoH failed for " + hostname + " via " + endpoint
                                    + ": " + t.getMessage());
                        }
                    });
        } catch (Exception e) {
            Common.showLog("HttpDns DoH threw for " + hostname + " via " + endpoint
                    + ": " + e.getMessage());
        }
    }

    @Override
    public List<InetAddress> lookup(String hostname) throws UnknownHostException {
        long start = System.nanoTime();
        if (isSecureDnsEnabled()) {
            // DoH 开：优先用 DoH 缓存的解析结果
            List<InetAddress> cached = resolvedHosts.get(hostname);
            if (cached != null && !cached.isEmpty()) {
                long elapsed = (System.nanoTime() - start) / 1_000_000;
                Common.showLog("HttpDns lookup " + hostname + " → DoH cached " + cached + " [" + elapsed + "ms]");
                return cached;
            }
        } else {
            // DoH 关：用户主动表示本地 DNS 可信，先走系统 DNS（issue #616 的核心诉求）
            try {
                List<InetAddress> systemResult = Dns.SYSTEM.lookup(hostname);
                if (!systemResult.isEmpty()) {
                    long elapsed = (System.nanoTime() - start) / 1_000_000;
                    Common.showLog("HttpDns lookup " + hostname + " → system " + systemResult + " [" + elapsed + "ms]");
                    return systemResult;
                }
            } catch (UnknownHostException ignored) {
                // 系统 DNS 失败再落到下面的硬编码 fallback
            }
        }
        // 图片域名用旧 Pixiv 服务器 IP，API 域名用 Cloudflare IP
        List<InetAddress> result;
        String source;
        if (hostname.endsWith("pximg.net")) {
            result = fallbackImageAddresses;
            source = "fallback-image";
        } else {
            result = fallbackApiAddresses;
            source = "fallback-api";
        }
        long elapsed = (System.nanoTime() - start) / 1_000_000;
        Common.showLog("HttpDns lookup " + hostname + " → " + source + " " + result + " [" + elapsed + "ms]");
        return result;
    }
}
