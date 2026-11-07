package ceui.lisa.http

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/**
 * DoH 答案的可信性判据。
 *
 * 存在的理由是一次实测：墙内的 223.5.5.5 对 pixiv 域名返回**污染但有值**的答案
 * （app-api → 104.244.43.248、i.pximg.net → 108.160.169.55）。这类答案一旦进缓存，
 * lookup() 就再也走不到硬编码兜底，所以必须在写缓存之前挡掉。
 */
class HttpDnsAnswerTrustTest {

    private fun addr(ip: String): InetAddress = InetAddress.getByName(ip)

    @Test
    fun `pixiv api domains accept only cloudflare ranges`() {
        // 实测正解：腾讯 DoH 与 CF_IP_PRIMARY / CF_IP_SECONDARY。
        assertTrue(HttpDns.isTrustedAnswer("app-api.pixiv.net", addr("104.18.42.239")))
        assertTrue(HttpDns.isTrustedAnswer("oauth.secure.pixiv.net", addr("172.64.145.17")))
        assertTrue(HttpDns.isTrustedAnswer("www.pixiv.net", addr("104.21.48.130")))
        assertTrue(HttpDns.isTrustedAnswer("accounts.pixiv.net", addr("172.71.0.1")))
        // 实测的污染答案：全部落在 CF 段外。
        assertFalse(HttpDns.isTrustedAnswer("app-api.pixiv.net", addr("104.244.43.248")))
        assertFalse(HttpDns.isTrustedAnswer("oauth.secure.pixiv.net", addr("103.230.123.190")))
        assertFalse(HttpDns.isTrustedAnswer("www.pixiv.net", addr("67.228.102.32")))
        assertFalse(HttpDns.isTrustedAnswer("accounts.pixiv.net", addr("108.160.162.115")))
        assertFalse(HttpDns.isTrustedAnswer("comic.pixiv.net", addr("108.160.161.20")))
    }

    @Test
    fun `cloudflare ranges stop at the documented edges`() {
        assertTrue(HttpDns.isCloudflareIp(addr("104.16.0.1")))
        assertTrue(HttpDns.isCloudflareIp(addr("104.23.255.254")))
        assertFalse(HttpDns.isCloudflareIp(addr("104.15.255.255")))
        assertFalse(HttpDns.isCloudflareIp(addr("104.24.0.1")))
        assertTrue(HttpDns.isCloudflareIp(addr("172.64.0.1")))
        assertTrue(HttpDns.isCloudflareIp(addr("172.71.255.254")))
        assertFalse(HttpDns.isCloudflareIp(addr("172.63.255.255")))
        assertFalse(HttpDns.isCloudflareIp(addr("172.72.0.1")))
    }

    @Test
    fun `image domains accept only the pixiv image range`() {
        assertTrue(HttpDns.isTrustedAnswer("i.pximg.net", addr("210.140.139.133")))
        assertTrue(HttpDns.isTrustedAnswer("s.pximg.net", addr("210.140.139.129")))
        // 实测污染：阿里与系统 DNS 都解到别的网段。
        assertFalse(HttpDns.isTrustedAnswer("i.pximg.net", addr("108.160.169.55")))
        assertFalse(HttpDns.isTrustedAnswer("i.pximg.net", addr("173.252.108.21")))
        assertFalse(HttpDns.isTrustedAnswer("i.pximg.net", addr("210.140.138.133")))
    }

    @Test
    fun `unrecognised hosts are left alone`() {
        // 不认识的域名不替别人做主 —— 用户自建 DoH 解出来的私网地址也要放行。
        assertTrue(HttpDns.isTrustedAnswer("example.com", addr("93.184.216.34")))
        assertTrue(HttpDns.isTrustedAnswer("dns.example", addr("10.0.0.1")))
    }
}
