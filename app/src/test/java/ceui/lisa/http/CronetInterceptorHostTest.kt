package ceui.lisa.http

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CronetInterceptorHostTest {

    @Test
    fun `direct connect is restricted to explicit Pixiv services`() {
        assertTrue(CronetInterceptor.shouldInterceptHost("app-api.pixiv.net"))
        assertTrue(CronetInterceptor.shouldInterceptHost("OAUTH.SECURE.PIXIV.NET"))
        assertTrue(CronetInterceptor.shouldInterceptHost("www.pixiv.net"))
        assertTrue(CronetInterceptor.shouldInterceptHost("accounts.pixiv.net"))
        assertTrue(CronetInterceptor.shouldInterceptHost("comic.pixiv.net"))
        assertTrue(CronetInterceptor.shouldInterceptHost("api.fanbox.cc"))
    }

    @Test
    fun `first-party backend is direct connected too`() {
        assertTrue(CronetInterceptor.shouldInterceptHost("pixshaft.com"))
        assertTrue(CronetInterceptor.shouldInterceptHost("API.PIXSHAFT.COM"))
    }

    @Test
    fun `storage bucket proxies and lookalike domains stay on OkHttp`() {
        // media.pixshaft.com is a Tencent COS bucket with no HTTP/3 — it must fall through.
        assertFalse(CronetInterceptor.shouldInterceptHost("media.pixshaft.com"))
        assertFalse(CronetInterceptor.shouldInterceptHost("proxy.example.com"))
        assertFalse(CronetInterceptor.shouldInterceptHost("app-api.pixiv.net.example.com"))
        assertFalse(CronetInterceptor.shouldInterceptHost("pixshaft.com.example.com"))
        assertFalse(CronetInterceptor.shouldInterceptHost(null))
    }

    @Test
    fun `direct connect keeps its established total deadline`() {
        assertEquals(30_000L, CronetInterceptor.requestTimeoutMillis())
    }
}
