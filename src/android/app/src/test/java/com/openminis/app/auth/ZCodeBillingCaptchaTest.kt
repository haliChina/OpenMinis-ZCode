package com.openminis.app.auth

import android.content.Context
import android.content.SharedPreferences
import com.openminis.app.util.EncryptedPrefsFactory
import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * [T-zcode-billing-skip] Regression (user report 2026-11-08): billingRaw
 * consulted skip_model_request and returned the raw 3007, so the claim
 * dialog never opened. skip_model_request is for MODEL requests only —
 * a claim 3007 must still reach requestVerification and retry once with
 * the param. In this test no dialog is mounted, so requestVerification
 * resolves from the prefetched param cache; the observable proof is the
 * retry itself (verify header present, code 0, retriedWithCaptcha) — on
 * the old code the result would be the raw 3007 with no retry at all.
 *
 * Runs under Robolectric: a real Context is required (ZCodeOAuthManager
 * reads EncryptedPrefs), and the real Android Context is abstract — a
 * plain `Context()` only compiles against the harness stub. The network
 * is a real seam: a test subclass of ZCodeOAuthManager overrides the
 * open [OAuthManager.httpClient] with an interceptor client answering
 * canned upstream responses. No harness stub members are referenced.
 */
@RunWith(RobolectricTestRunner::class)
class ZCodeBillingCaptchaTest {

    private val ctx: Context get() = RuntimeEnvironment.getApplication()
    private lateinit var prefs: SharedPreferences

    @Before
    fun setUp() {
        EncryptedPrefsFactory.resetCacheForTest()
        prefs = ctx.getSharedPreferences("oauth_prefs_test", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        EncryptedPrefsFactory.cached("oauth_prefs") { prefs }
    }

    @After
    fun tearDown() {
        ZCodeCaptchaGate.takeCachedParam()
        EncryptedPrefsFactory.resetCacheForTest()
    }

    private fun cannedResponse(request: okhttp3.Request, code: Int, body: String): Response =
        Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message("OK")
            .body(body.toResponseBody("application/json".toMediaType()))
            .build()

    /** Test seam: ZCodeOAuthManager with the HTTP layer replaced by a
     *  canned-response interceptor client. */
    private class CannedZCodeOAuthManager(
        context: Context,
        client: OkHttpClient,
    ) : ZCodeOAuthManager(context, "test-billing-3007") {
        private val cannedClient = client
        override val httpClient: OkHttpClient get() = cannedClient
    }

    @Test
    fun `billing claim still opens the captcha dialog when skipModelRequest is true`() {
        val seen = mutableListOf<String>()
        val client = OkHttpClient.Builder()
            .addInterceptor(Interceptor { chain ->
                val req = chain.request()
                val url = req.url.toString()
                when {
                    url.contains("client/configs") -> {
                        seen.add("configs")
                        cannedResponse(
                            req, 200,
                            """{"code":0,"data":{"configs":{"captcha":{"sceneId":"11xygtvd","region":"sgp","prefix":"no8xfe","skip_model_request":true,"enabled":true}}}}""",
                        )
                    }
                    url.contains("billing/claim") && req.header("X-Aliyun-Captcha-Verify-Param") != null -> {
                        seen.add("claim+verify:" + req.header("X-Aliyun-Captcha-Verify-Param"))
                        cannedResponse(
                            req, 200,
                            """{"code":0,"data":{"plan":{"plan_id":"zcode-v3-start-plan-0817","show_name":"Start"}}}""",
                        )
                    }
                    url.contains("billing/claim") -> {
                        seen.add("claim")
                        cannedResponse(req, 200, """{"code":3007,"msg":"captcha required"}""")
                    }
                    else -> cannedResponse(req, 404, """{"code":404,"msg":"unexpected call: $url"}""")
                }
            })
            .build()
        val manager = CannedZCodeOAuthManager(ctx, client)
        manager.saveManualBearerToken("test-jwt")
        ZCodeCaptchaGate.cachePrefetchedParam("verify-param-test")
        val result = runBlocking { manager.claimPlan("zcode-v3-start-plan-0817") }
        assertEquals(0, result.code)
        assertTrue(result.retriedWithCaptcha)
        assertEquals(
            listOf("claim", "configs", "claim+verify:verify-param-test"),
            seen,
        )
    }
}
