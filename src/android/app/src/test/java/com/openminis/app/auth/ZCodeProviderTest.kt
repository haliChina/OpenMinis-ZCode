package com.openminis.app.auth

import com.openminis.app.provider.zcode.ZCodeChatWire
import com.openminis.app.provider.zcode.ZCodeSystemPrompt
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * [T-zcode-provider] Covers the decision surface of the ZCode provider —
 * the parts where a wrong answer is silent rather than loud: plan
 * filtering (a Start Plan account offered GLM-5.3 gets a 400 on first
 * send), JWT expiry parsing (no refresh exists), captcha classification
 * (3012 must never be treated as a captcha), and the 3-block system
 * shape (the gateway checks block 1's identity).
 */
class ZCodeProviderTest {

    // ── Plan filtering ───────────────────────────────────────────────────

    @Test
    fun `start plan has no GLM-5_3`() {
        val ids = ZCodeConstants.modelsForPlan(ZCodeConstants.PlanMode.START).map { it.id }
        assertEquals(
            listOf("GLM-5.3-Flash", "GLM-5.2", "GLM-5-Turbo"),
            ids,
        )
    }

    @Test
    fun `coding plan has GLM-5_3`() {
        val ids = ZCodeConstants.modelsForPlan(ZCodeConstants.PlanMode.CODING).map { it.id }
        assertTrue(ids.contains("GLM-5.3"))
        assertEquals(4, ids.size)
    }

    @Test
    fun `unknown plan defaults to the start plan list`() {
        assertEquals(
            ZCodeConstants.modelsForPlan(ZCodeConstants.PlanMode.START),
            ZCodeConstants.modelsForPlan(ZCodeConstants.PlanMode.UNKNOWN),
        )
    }

    @Test
    fun `plan mode is derived from billing current`() {
        val coding = """{"code":0,"data":{"plans":[{"plan_id":"zcode-v3-coding-plan","show_name":"Coding Plan"}]}}"""
        assertEquals(
            ZCodeConstants.PlanMode.CODING,
            ZCodeOAuthManager.derivePlanModeFromBody(coding),
        )
        val start = """{"code":0,"data":{"plans":[{"plan_id":"zcode-v3-start-plan-0817","show_name":"Start Plan"}]}}"""
        assertEquals(
            ZCodeConstants.PlanMode.START,
            ZCodeOAuthManager.derivePlanModeFromBody(start),
        )
    }

    // ── Claim codes ──────────────────────────────────────────────────────

    @Test
    fun `claim codes have the documented meanings`() {
        assertEquals("已领取", ZCodeConstants.claimCodeMeaning(0))
        assertEquals("已领取过", ZCodeConstants.claimCodeMeaning(1003))
        assertEquals("名额已用完", ZCodeConstants.claimCodeMeaning(1005))
        assertEquals("风控拦截（unusual activity）", ZCodeConstants.claimCodeMeaning(3012))
    }

    // ── JWT parsing (no signature verification, expiry only) ────────────

    private fun makeJwt(userId: String, expSeconds: Long): String {
        fun b64(s: String) =
            Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(Charsets.UTF_8))
        // NOTE: do not inline the raw strings into one "${...}" template:
        // a raw string nested inside a multi-line template entry breaks
        // the Kotlin parser (syntax error at EOF). Build the parts first.
        val header = b64("""{"alg":"HS256","typ":"JWT"}""")
        val payload = b64("""{"user_id":"$userId","exp":$expSeconds}""")
        return "$header.$payload.signature"
    }

    @Test
    fun `jwt payload yields user id and expiry`() {
        val jwt = makeJwt("user-123", 2_000_000_000L)
        assertEquals("user-123", ZCodeOAuthManager.jwtUserId(jwt))
        assertEquals(2_000_000_000_000L, ZCodeOAuthManager.jwtExpiryMs(jwt))
    }

    @Test
    fun `malformed jwt yields nulls, not a crash`() {
        assertEquals(null, ZCodeOAuthManager.jwtUserId("not-a-jwt"))
        assertEquals(null, ZCodeOAuthManager.jwtExpiryMs("a.b"))
    }

    // ── Captcha classification ───────────────────────────────────────────

    @Test
    fun `code 3007 is a captcha challenge, 3012 is not`() {
        assertTrue(
            ZCodeCaptchaGate.isCaptchaChallenge(
                405, """{"code":3007,"msg":"captcha required"}""",
            ),
        )
        assertFalse(
            ZCodeCaptchaGate.isCaptchaChallenge(
                405, """{"code":3012,"msg":"unusual activity"}""",
            ),
        )
        assertFalse(
            ZCodeCaptchaGate.isCaptchaChallenge(200, """{"code":0}"""),
        )
    }

    @Test
    fun `captcha response header alone is a challenge`() {
        assertTrue(
            ZCodeCaptchaGate.isCaptchaChallenge(200, "{}", hasCaptchaHeader = true),
        )
    }

    // ── System prompt: 3-block shape ─────────────────────────────────────

    @Test
    fun `system prompt is three blocks with the prefix alone first`() {
        val system = ZCodeSystemPrompt.build(
            clientSystem = "Be terse.",
            modelId = "GLM-5.3-Flash",
            workingDirectory = "/tmp",
        )
        assertEquals(3, system.length())
        val block1 = system.getJSONObject(0)
        assertEquals("You are ZCode, an interactive coding agent", block1.getString("text"))
        // Block 1 carries cache_control: ephemeral like the official
        // bundle (all three blocks); the v1 omission triggered 405/3012.
        assertTrue(block1.has("cache_control"))
        assertEquals(
            "ephemeral",
            block1.getJSONObject("cache_control").getString("type"),
        )
        val block2 = system.getJSONObject(1)
        assertTrue(block2.has("cache_control"))
        assertTrue(block2.getString("text").contains("Be terse."))
        val block3 = system.getJSONObject(2)
        assertTrue(block3.has("cache_control"))
        assertTrue(block3.getString("text").startsWith("\n\n"))
        assertTrue(
            block3.getString("text")
                .contains("You are powered by the model named zai-api/GLM-5.3-Flash."),
        )
    }

    // ── BigModel login ───────────────────────────────────────────────

    private fun queryParams(url: String): Map<String, String> {
        val rawQuery = java.net.URI(url).rawQuery.orEmpty()
        return rawQuery.split("&").filter { it.isNotEmpty() }.associate {
            val eq = it.indexOf('=')
            if (eq >= 0) {
                java.net.URLDecoder.decode(it.substring(0, eq), "UTF-8") to
                    java.net.URLDecoder.decode(it.substring(eq + 1), "UTF-8")
            } else {
                java.net.URLDecoder.decode(it, "UTF-8") to ""
            }
        }
    }

    @Test
    fun `bigmodel relay url is the official page with app version`() {
        assertEquals(
            "https://zcode.z.ai/app/oauth/login?redirect=zcode://oauth/callback&app_version=3.17.1",
            ZCodeOAuthManager.buildBigModelRelayUrl(),
        )
    }

    @Test
    fun `bigmodel rewrite sets redirect to the relay page and keeps other params`() {
        val url = "https://zcode.z.ai/oauth/authorize?flow_id=abc&state=xyz&redirect=zcode://oauth/callback"
        val rewritten = ZCodeOAuthManager.rewriteAuthorizeUrlForProvider(
            ZCodeOAuthManager.LoginProvider.BIGMODEL, url,
        )
        val params = queryParams(rewritten)
        assertEquals(ZCodeOAuthManager.buildBigModelRelayUrl(), params["redirect"])
        assertEquals("abc", params["flow_id"])
        assertEquals("xyz", params["state"])
        assertEquals("https://zcode.z.ai/oauth/authorize", rewritten.substringBefore("?"))
    }

    @Test
    fun `bigmodel rewrite appends redirect when absent`() {
        val url = "https://zcode.z.ai/oauth/authorize?flow_id=abc&state=xyz"
        val rewritten = ZCodeOAuthManager.rewriteAuthorizeUrlForProvider(
            ZCodeOAuthManager.LoginProvider.BIGMODEL, url,
        )
        val params = queryParams(rewritten)
        assertEquals(ZCodeOAuthManager.buildBigModelRelayUrl(), params["redirect"])
        assertEquals("abc", params["flow_id"])
        assertEquals("xyz", params["state"])
    }

    @Test
    fun `zai rewrite leaves the authorize url untouched`() {
        val url = "https://z.ai/oauth/authorize?flow_id=abc&state=xyz&redirect=zcode://oauth/callback"
        assertEquals(
            url,
            ZCodeOAuthManager.rewriteAuthorizeUrlForProvider(
                ZCodeOAuthManager.LoginProvider.ZAI, url,
            ),
        )
    }

    @Test
    fun `bigmodel rewrite rejects a non-https url`() {
        org.junit.Assert.assertThrows(
            IllegalArgumentException::class.java,
        ) {
            ZCodeOAuthManager.rewriteAuthorizeUrlForProvider(
                ZCodeOAuthManager.LoginProvider.BIGMODEL,
                "http://zcode.z.ai/oauth/authorize?flow_id=abc",
            )
        }
        org.junit.Assert.assertThrows(
            IllegalArgumentException::class.java,
        ) {
            ZCodeOAuthManager.rewriteAuthorizeUrlForProvider(
                ZCodeOAuthManager.LoginProvider.BIGMODEL,
                "not a url",
            )
        }
    }

    @Test
    fun `ready parses bigmodel credentials and user id from data`() {
        val jwt = makeJwt("jwt-user", 2_000_000_000L)
        val data = JSONObject(
            """{"token":"$jwt","status":"ready","user":{"user_id":"body-user"},
                "bigmodel":{"access_token":"bm-access","refresh_token":"bm-refresh"}}""",
        )
        val result = ZCodeOAuthManager.parseReady(data, ZCodeOAuthManager.LoginProvider.BIGMODEL)
        assertEquals(jwt, result?.jwt)
        assertEquals("bm-access", result?.providerAccessToken)
        assertEquals("bm-refresh", result?.providerRefreshToken)
        // data.user wins over the JWT payload.
        assertEquals("body-user", result?.userId)
    }

    @Test
    fun `ready accepts camelCase provider fields`() {
        val jwt = makeJwt("jwt-user", 2_000_000_000L)
        val data = JSONObject(
            """{"token":"$jwt","bigmodel":{"accessToken":"bm-access","refreshToken":"bm-refresh"}}""",
        )
        val result = ZCodeOAuthManager.parseReady(data, ZCodeOAuthManager.LoginProvider.BIGMODEL)
        assertEquals("bm-access", result?.providerAccessToken)
        assertEquals("bm-refresh", result?.providerRefreshToken)
    }

    @Test
    fun `ready still parses zai and falls back to the jwt user id`() {
        val jwt = makeJwt("jwt-user", 2_000_000_000L)
        val data = JSONObject(
            """{"token":"$jwt","zai":{"access_token":"zai-access"}}""",
        )
        val result = ZCodeOAuthManager.parseReady(data, ZCodeOAuthManager.LoginProvider.ZAI)
        assertEquals("zai-access", result?.providerAccessToken)
        assertEquals("jwt-user", result?.userId)
    }

    @Test
    fun `ready without a token is not ready`() {
        val pending = JSONObject("""{"status":"pending"}""")
        assertEquals(
            null,
            ZCodeOAuthManager.parseReady(pending, ZCodeOAuthManager.LoginProvider.BIGMODEL),
        )
        assertEquals(
            null,
            ZCodeOAuthManager.parseReady(pending, ZCodeOAuthManager.LoginProvider.ZAI),
        )
    }

    // ── Identity headers (3001/3012) ──────────────────────────────────

    @Test
    fun `header values must be visible ascii only`() {
        assertEquals("abc-123", ZCodeOAuthManager.cleanHeaderValue("abc-123"))
        assertEquals("abc", ZCodeOAuthManager.cleanHeaderValue("  abc  "))
        assertEquals(null, ZCodeOAuthManager.cleanHeaderValue(""))
        assertEquals(null, ZCodeOAuthManager.cleanHeaderValue("   "))
        assertEquals(null, ZCodeOAuthManager.cleanHeaderValue(null))
        // Non-ASCII and control characters drop the whole header.
        assertEquals(null, ZCodeOAuthManager.cleanHeaderValue("中文"))
        assertEquals(null, ZCodeOAuthManager.cleanHeaderValue("a\nb"))
        assertEquals(null, ZCodeOAuthManager.cleanHeaderValue("a\tb"))
    }

    @Test
    fun `abi maps to the short arch label`() {
        assertEquals("arm64", ZCodeOAuthManager.archLabel("arm64-v8a"))
        assertEquals("x64", ZCodeOAuthManager.archLabel("x86_64"))
        assertEquals("arm", ZCodeOAuthManager.archLabel("armeabi-v7a"))
        assertEquals("arm", ZCodeOAuthManager.archLabel("armeabi"))
        assertEquals("x86", ZCodeOAuthManager.archLabel("x86"))
    }

    @Test
    fun `identity headers carry all six fields with real values`() {
        val headers = ZCodeOAuthManager.buildIdentityHeaders(
            deviceMid = "11111111-2222-3333-4444-555555555555",
            platform = "android-arm64",
            osVersion = "14",
            clientLanguage = "zh-CN",
            clientTimezone = "Asia/Shanghai",
        )
        assertEquals("11111111-2222-3333-4444-555555555555", headers["X-Device-Mid"])
        assertEquals("android-arm64", headers["X-Platform"])
        assertEquals("android", headers["X-Os-Category"])
        assertEquals("14", headers["X-Os-Version"])
        assertEquals("zh-CN", headers["X-Client-Language"])
        assertEquals("Asia/Shanghai", headers["X-Client-Timezone"])
        assertEquals(6, headers.size)
    }

    @Test
    fun `identity headers drop empty or non-ascii fields, never send them blank`() {
        val headers = ZCodeOAuthManager.buildIdentityHeaders(
            deviceMid = "11111111-2222-3333-4444-555555555555",
            platform = "android-arm64",
            osVersion = "",
            clientLanguage = "中文",
            clientTimezone = "Asia/Shanghai",
        )
        assertFalse(headers.containsKey("X-Os-Version"))
        assertFalse(headers.containsKey("X-Client-Language"))
        assertEquals("11111111-2222-3333-4444-555555555555", headers["X-Device-Mid"])
        assertEquals("android", headers["X-Os-Category"])
    }

    @Test
    fun `trace headers are six fresh uuids per call`() {
        val first = ZCodeChatWire.buildTraceHeaders()
        val second = ZCodeChatWire.buildTraceHeaders()
        assertEquals(
            setOf(
                "x-request-id", "x-zcode-session-type", "x-zcode-trace-id",
                "x-query-id", "x-zcode-query-source", "x-session-id",
            ),
            first.keys,
        )
        assertEquals("main", first["x-zcode-session-type"])
        assertEquals("main_turn", first["x-zcode-query-source"])
        val uuid = Regex(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        )
        for (key in listOf("x-request-id", "x-zcode-trace-id", "x-query-id", "x-session-id")) {
            assertTrue("$key is a uuid", uuid.matches(first[key].orEmpty()))
            assertFalse("$key is fresh per request", first[key] == second[key])
        }
    }

    @Test
    fun `metadata object carries the jwt user id, absent when unknown`() {
        assertEquals(
            "user-123",
            ZCodeChatWire.buildMetadataObject("user-123")?.getString("user_id"),
        )
        assertEquals(null, ZCodeChatWire.buildMetadataObject(null))
        assertEquals(null, ZCodeChatWire.buildMetadataObject(""))
        assertEquals(null, ZCodeChatWire.buildMetadataObject("   "))
        // The JWT sub fallback feeds the same helper.
        val jwt = makeJwt("sub-user", 2_000_000_000L)
        assertEquals(
            "sub-user",
            ZCodeChatWire.buildMetadataObject(ZCodeOAuthManager.jwtUserId(jwt))
                ?.getString("user_id"),
        )
    }

    // ── Activation report ──────────────────────────────────────────────

    private val uuid = Regex(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    )

    @Test
    fun `activation events are sent app_launch, app_daily_active, then app_login_success`() {
        assertEquals(
            listOf("app_launch", "app_daily_active", "app_login_success"),
            ZCodeActivation.ACTIVATION_ELEMENTS,
        )
    }

    @Test
    fun `app_login_success body uses app_profile region and carries the login provider`() {
        val body = ZCodeActivation.buildActivationEventBody(
            elementName = "app_login_success",
            userId = "user-1",
            deviceMid = "mid-1",
            clientTimezone = "Asia/Shanghai",
            clientLanguage = "zh-CN",
            screenResolution = "1080x2400",
            osVersion = "14",
        )
        assertEquals("app_login_success", body.getString("element_name"))
        assertEquals("app_profile", body.getString("event_region"))
        assertEquals("zai", body.getJSONObject("event_extra_detail").getString("login_provider"))
    }

    @Test
    fun `app_login_success body carries bigmodel when that is the login provider`() {
        val body = ZCodeActivation.buildActivationEventBody(
            elementName = "app_login_success",
            userId = "user-1",
            deviceMid = "mid-1",
            clientTimezone = "Asia/Shanghai",
            clientLanguage = "zh-CN",
            screenResolution = "1080x2400",
            osVersion = "14",
            loginProvider = "bigmodel",
        )
        assertEquals("app_profile", body.getString("event_region"))
        assertEquals("bigmodel", body.getJSONObject("event_extra_detail").getString("login_provider"))
    }

    @Test
    fun `app_launch and app_daily_active bodies keep app region and empty extra detail`() {
        for (element in listOf("app_launch", "app_daily_active")) {
            val body = ZCodeActivation.buildActivationEventBody(
                elementName = element,
                userId = "user-1",
                deviceMid = "mid-1",
                clientTimezone = "Asia/Shanghai",
                clientLanguage = "zh-CN",
                screenResolution = "1080x2400",
                osVersion = "14",
            )
            assertEquals(element, body.getString("element_name"))
            assertEquals("app", body.getString("event_region"))
            assertEquals(0, body.getJSONObject("event_extra_detail").length())
        }
    }

    @Test
    fun `activation event body has exactly the 16 official fields`() {
        val body = ZCodeActivation.buildActivationEventBody(
            elementName = "app_launch",
            userId = "user-1",
            deviceMid = "mid-1",
            clientTimezone = "Asia/Shanghai",
            clientLanguage = "zh-CN",
            screenResolution = "1080x2400",
            osVersion = "14",
        )
        val keys = mutableSetOf<String>()
        val it = body.keys()
        while (it.hasNext()) keys.add(it.next())
        assertEquals(
            setOf(
                "event_id", "client_timezone", "client_language",
                "element_name", "event_region", "event_type", "event_text",
                "event_extra_detail", "user_id", "screen_resolution",
                "app_version", "device_os_category", "device_os_version",
                "device_mid", "mac_id", "marketing_params",
            ),
            keys,
        )
        assertTrue("event_id is a uuid", uuid.matches(body.getString("event_id")))
        assertEquals("app_launch", body.getString("element_name"))
        assertEquals("app", body.getString("event_region"))
        assertEquals("view", body.getString("event_type"))
        assertEquals("", body.getString("event_text"))
        assertEquals(0, body.getJSONObject("event_extra_detail").length())
        assertEquals("user-1", body.getString("user_id"))
        assertEquals("1080x2400", body.getString("screen_resolution"))
        assertEquals("3.17.1", body.getString("app_version"))
        assertEquals("android", body.getString("device_os_category"))
        assertEquals("14", body.getString("device_os_version"))
        assertEquals("mid-1", body.getString("device_mid"))
        assertEquals("", body.getString("mac_id"))
        assertEquals("{}", body.getString("marketing_params"))
    }

    @Test
    fun `activation event ids are fresh per event`() {
        val first = ZCodeActivation.buildActivationEventBody(
            "app_launch", "u", "m", "Asia/Shanghai", "zh-CN", "1080x2400", "14",
        )
        val second = ZCodeActivation.buildActivationEventBody(
            "app_daily_active", "u", "m", "Asia/Shanghai", "zh-CN", "1080x2400", "14",
        )
        assertEquals("app_daily_active", second.getString("element_name"))
        assertFalse(first.getString("event_id") == second.getString("event_id"))
    }

    // ── Preview path ───────────────────────────────────────────────────

    @Test
    fun `preview path carries app_version and platform`() {
        assertEquals(
            "billing/preview?app_version=3.17.1&platform=android-arm64",
            ZCodeActivation.buildPreviewPath("3.17.1", "android-arm64"),
        )
    }

    // ── Preview parsing ────────────────────────────────────────────────

    @Test
    fun `preview plans parse with priority and name fallbacks`() {
        val body = """{"code":0,"data":{"plans":[
            {"plan_id":"p1","show_name":"Start Plan","priority":3},
            {"plan_id":"p2","name":"Second","priority":1}
        ]}}"""
        val plans = ZCodeActivation.parsePreviewPlans(body)
        assertEquals(listOf("p1", "p2"), plans.map { it.id })
        assertEquals("Start Plan", plans[0].name)
        assertEquals("Second", plans[1].name)
        assertEquals(3, plans[0].priority)
        assertEquals(ZCodeActivation.ClaimablePlan.Source.PREVIEW, plans[0].source)
    }

    @Test
    fun `preview plans fall back to the claimable key`() {
        val body = """{"code":0,"data":{"claimable":[{"plan_id":"c1"}]}}"""
        val plans = ZCodeActivation.parsePreviewPlans(body)
        assertEquals(listOf("c1"), plans.map { it.id })
        assertEquals("c1", plans[0].name)
    }

    // ── Touch parsing ──────────────────────────────────────────────────

    private val touchBody = """{"code":0,"data":{"deliveries":[
        {"id":"d1","content":{"zcode_plan":{
            "plan_id":"p-touch-1","show_name":"Touch Plan","description":"活动",
            "priority":5,
            "entitlements":[
                {"meter":"model_usage","unit_type":"token","show_name":"GLM-5.3-Flash","grant_units":8000000,"period":"daily"},
                {"meter":"model_usage","unit_type":"token","showName":"GLM-5.2","grantUnits":1000,"period":"daily"},
                {"meter":"other","unit_type":"token","show_name":"Nope","grant_units":5},
                {"meter":"model_usage","unit_type":"call","show_name":"Nope2","grant_units":5}
            ]
        }}},
        {"id":"d2","actions":[{"type":"claim_zcode_plan","args":{"plan_id":"p-action-1"}}]},
        {"id":"d3","actions":[{"type":"claim_zcode_plan","args":{"planId":"p-touch-1"}}]},
        {"id":"d4","wrapper":{"inner":{"zcodePlan":{
            "planId":"p-deep-1","showName":"Deep Plan","priority":2
        }}}}
    ]}}"""

    @Test
    fun `touch deliveries extract plan objects and grants`() {
        val plans = ZCodeActivation.parseTouchDeliveries(touchBody)
        // Complete objects in delivery order; synthetic action entries
        // are appended after the scan (the console sorts by priority
        // anyway, so this order is only stability, not display order).
        assertEquals(listOf("p-touch-1", "p-deep-1", "p-action-1"), plans.map { it.id })
        val touch = plans[0]
        assertEquals("Touch Plan", touch.name)
        assertEquals("活动", touch.description)
        assertEquals(5, touch.priority)
        assertEquals(ZCodeActivation.ClaimablePlan.Source.TOUCH, touch.source)
        // Only model_usage + token entitlements survive; snake and camel
        // keys both read.
        assertEquals(listOf("GLM-5.3-Flash", "GLM-5.2"), touch.grants.map { it.name })
        assertEquals(listOf(8000000L, 1000L), touch.grants.map { it.units })
        assertEquals(listOf("daily", "daily"), touch.grants.map { it.period })
        // Deep nesting is found by the recursive scan.
        assertEquals("Deep Plan", plans[1].name)
        assertEquals(2, plans[1].priority)
    }

    @Test
    fun `touch action without a plan object gets a synthetic entry`() {
        val plans = ZCodeActivation.parseTouchDeliveries(touchBody)
        val synthetic = plans[2]
        assertEquals("p-action-1", synthetic.id)
        assertEquals("p-action-1", synthetic.name)
        assertEquals("活动投放套餐", synthetic.description)
        assertEquals(100, synthetic.priority)
        assertTrue(synthetic.grants.isEmpty())
        // An action pointing at a plan that already has a complete
        // object does not duplicate it.
        assertEquals(1, plans.count { it.id == "p-touch-1" })
    }

    @Test
    fun `touch failures yield an empty list`() {
        assertTrue(ZCodeActivation.parseTouchDeliveries("").isEmpty())
        assertTrue(ZCodeActivation.parseTouchDeliveries("not json").isEmpty())
        assertTrue(
            ZCodeActivation.parseTouchDeliveries("""{"code":1005,"data":{"deliveries":[]}}""").isEmpty(),
        )
        assertTrue(
            ZCodeActivation.parseTouchDeliveries("""{"code":0,"data":{}}""").isEmpty(),
        )
    }

    // ── Merge ──────────────────────────────────────────────────────────

    @Test
    fun `merge dedupes by plan id with preview winning and sorts by priority`() {
        val preview = listOf(
            ZCodeActivation.ClaimablePlan("b", "Preview B", priority = 0),
            ZCodeActivation.ClaimablePlan("a", "Preview A", priority = 5),
        )
        val touch = listOf(
            ZCodeActivation.ClaimablePlan(
                "b", "Touch B", priority = 9,
                source = ZCodeActivation.ClaimablePlan.Source.TOUCH,
            ),
            ZCodeActivation.ClaimablePlan(
                "c", "Touch C", priority = 5,
                source = ZCodeActivation.ClaimablePlan.Source.TOUCH,
            ),
        )
        val merged = ZCodeActivation.mergePlans(preview, touch)
        assertEquals(listOf("a", "c", "b"), merged.map { it.id })
        assertEquals("Preview B", merged.first { it.id == "b" }.name)
    }
}
