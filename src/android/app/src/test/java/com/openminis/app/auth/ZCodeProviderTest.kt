package com.openminis.app.auth

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
        assertFalse(block1.has("cache_control"))
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

    @Test
    fun `system prompt never contains a captured local path`() {
        val system = ZCodeSystemPrompt.build(null, "GLM-5.2", null)
        val joined = (0 until system.length())
            .joinToString("") { system.getJSONObject(it).getString("text") }
        assertFalse(joined.contains("C:\\Users\\"))
        assertFalse(joined.contains("Angus"))
        // Still well-formed JSON when the client prompt is absent.
        assertEquals(3, system.length())
        assertTrue(JSONArray(system.toString()).length() == 3)
    }
}
