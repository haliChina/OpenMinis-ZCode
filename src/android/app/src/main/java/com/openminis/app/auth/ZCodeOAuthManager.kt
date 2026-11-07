package com.openminis.app.auth

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom

/**
 * [T-zcode-provider] ZCode OAuth + billing manager (Android).
 *
 * Login is the CLI init/poll flow, verified in four public gateways and in
 * the official repo (docs/oauth/desktop-oauth-polling.md,
 * apps/zcode-cli cli-oauth.ts):
 *
 *   1. `POST /api/v1/oauth/cli/init` with body `{"provider":"zai"}` (or
 *      `"bigmodel"`) and header `Authorization: Bearer <self-generated
 *      32-byte hex pollToken>`. No client_id, no PKCE, no redirect. The
 *      server may answer with its own `poll_token` — subsequent polls
 *      must use that.
 *   2. Open the returned `authorize_url` in a Custom Tab; the user
 *      authorizes on z.ai (or bigmodel.cn) in the browser. There is NO
 *      localhost callback server on this path. For `bigmodel` the
 *      authorize URL's `redirect` parameter is rewritten to the official
 *      relay page (`/app/oauth/login`, see [rewriteAuthorizeUrlForProvider])
 *      before it is opened; `zai` is passed through untouched.
 *   3. Poll `GET /api/v1/oauth/cli/poll/{flow_id}` with the same Bearer
 *      pollToken until `data.token` (the plan JWT) arrives, or 300s elapse.
 *      The provider credential lives in `data.<provider>` (`data.zai` /
 *      `data.bigmodel`); the JWT is the same either way, so chat and
 *      billing are identical for both login methods.
 *
 * Token model (official client behaviour — there is NO refresh):
 * the JWT is stored in the standard `oauth_tokens_<id>` blob (so the base
 * [OAuthManager.logout] clears it and backup export/import round-trip it),
 * its `exp` is parsed locally, and once expired the user must log in again
 * — [validAccessToken] returns null past expiry and never attempts a
 * refresh. The provider surfaces that as "登录已过期，请重新登录".
 *
 * Single account only. No multi-account pool, no auto-claim, no timers.
 * Billing calls (balance / current / preview / claim) are manual, one shot
 * each, and share the captcha retry in [billingCall]: on a 3007 challenge
 * the user is asked once through [ZCodeCaptchaGate]; cancel aborts.
 */
class ZCodeOAuthManager(
    context: Context,
    instanceId: String,
) : OAuthManager(context, instanceId) {

    /** One billing/claim call, raw. `code` is the upstream business
     *  code (0 = success); the raw body is kept so the console can show
     *  upstream values verbatim instead of a re-interpretation.
     *  (Nested directly in the class, not in the companion object:
     *  a class declared inside `companion` is only reachable as
     *  `ZCodeOAuthManager.Companion.ApiResult`, not `ZCodeOAuthManager.ApiResult`.) */
    data class ApiResult(
        val httpStatus: Int,
        val code: Int?,
        val body: String,
        val captchaChallenge: Boolean = false,
        val retriedWithCaptcha: Boolean = false,
        /** User cancelled the manual captcha dialog; request aborted. */
        val captchaCancelled: Boolean = false,
    )

    /** Which account the user signs in with. Both go through the same
     *  CLI init/poll flow and return the same ZCode JWT; they differ only
     *  in the authorize page and in the provider credential inside
     *  `ready`. (Official docs/oauth/desktop-oauth-polling.md: the
     *  polling `provider` is `zai` or `bigmodel`.) */
    enum class LoginProvider(val id: String) {
        ZAI("zai"),
        BIGMODEL("bigmodel");

        companion object {
            fun fromId(id: String): LoginProvider =
                values().firstOrNull { it.id == id } ?: ZAI
        }
    }

    data class InitResult(
        val flowId: String,
        val authorizeUrl: String,
        val pollToken: String,
        val pollIntervalSec: Long,
        val deadlineMs: Long,
        val provider: LoginProvider = LoginProvider.ZAI,
    )

    data class JwtResult(
        val jwt: String,
        val providerAccessToken: String?,
        val userId: String?,
        val expiresAtMs: Long,
        val providerRefreshToken: String? = null,
    )

    companion object {
        private const val TAG = "ZCodeOAuth"

        private const val KEY_PLAN_MODE = "zcode_plan_mode"

        private val JSON_MEDIA = "application/json".toMediaType()

        /**
         * Full CLI login. Suspends until the user authorizes in the browser
         * or a terminal failure. [onAuthorizeUrl] fires as soon as init
         * returns so the UI can open the URL — login is NOT complete then.
         */
        suspend fun login(
            context: Context,
            instanceId: String,
            provider: LoginProvider = LoginProvider.ZAI,
            onAuthorizeUrl: (String) -> Unit,
        ): String {
            val mgr = ZCodeOAuthManager(context, instanceId)
            val init = mgr.beginLogin(provider)
            onAuthorizeUrl(init.authorizeUrl)
            return mgr.finishLogin(init)
        }

        /**
         * The official BigModel relay page (packages/services
         * `buildDesktopOAuthRedirectUriFromEnv`): the authorize URL's
         * `redirect` is pointed here so the browser lands back on the
         * polling bridge instead of the deep link. `app_version` must be
         * above 3.9.1 for the website to enable the bridge; ours is
         * [ZCodeConstants.CLIENT_APP_VERSION].
         */
        fun buildBigModelRelayUrl(): String =
            "https://zcode.z.ai/app/oauth/login" +
                "?redirect=zcode://oauth/callback" +
                "&app_version=${ZCodeConstants.CLIENT_APP_VERSION}"

        /**
         * Rewrite the authorize URL for the chosen provider. `zai` is
         * returned untouched. For `bigmodel` the `redirect` query
         * parameter is set to [buildBigModelRelayUrl]; every other
         * parameter (`state`, `flow_id`, …) and the fragment are left
         * byte-for-byte, and an existing `redirect` is replaced rather
         * than duplicated. Throws [IllegalArgumentException] when the URL
         * is not a valid HTTPS URL — the caller must surface the error
         * and never open the original link.
         *
         * Pure java.net surgery (not android.net.Uri) on purpose: this
         * must stay unit-testable on the JVM, where android.net.Uri is a
         * stub that throws. Behaviour matches Uri.Builder: the relay URL
         * is encoded as a single query value.
         */
        fun rewriteAuthorizeUrlForProvider(
            provider: LoginProvider,
            authorizeUrl: String,
        ): String {
            if (provider != LoginProvider.BIGMODEL) return authorizeUrl
            val uri = runCatching { java.net.URI(authorizeUrl) }.getOrNull()
            if (uri == null || uri.scheme?.lowercase() != "https" || uri.host.isNullOrEmpty()) {
                throw IllegalArgumentException("ZCode 授权链接无效，无法改写 BigModel 回调")
            }
            val encodedRelay = java.net.URLEncoder.encode(
                buildBigModelRelayUrl(), Charsets.UTF_8,
            )
            val hashIndex = authorizeUrl.indexOf('#')
            val beforeFragment = if (hashIndex >= 0) authorizeUrl.substring(0, hashIndex) else authorizeUrl
            val fragment = if (hashIndex >= 0) authorizeUrl.substring(hashIndex) else ""
            val qIndex = beforeFragment.indexOf('?')
            val base = if (qIndex >= 0) beforeFragment.substring(0, qIndex) else beforeFragment
            val rawQuery = if (qIndex >= 0) beforeFragment.substring(qIndex + 1) else ""
            val pairs = rawQuery.split("&").filter { it.isNotEmpty() }.toMutableList()
            val redirectParam = "redirect=$encodedRelay"
            val existing = pairs.indexOfFirst { it.substringBefore("=") == "redirect" }
            if (existing >= 0) pairs[existing] = redirectParam else pairs.add(redirectParam)
            return base + "?" + pairs.joinToString("&") + fragment
        }

        /**
         * Parse one poll `data` object (official cli-oauth.ts
         * `parseReadyData`). Returns null while the flow is still pending
         * (no `data.token` yet); the caller keeps polling then. The token
         * is the ZCode JWT for both providers; the provider credential is
         * read from `data.<provider>` (`access_token` or camelCase
         * `accessToken`, same for the refresh token), falling back to a
         * top-level `access_token` for older `zai` responses. The user id
         * comes from `data.user.user_id`, with the JWT payload as fallback.
         */
        fun parseReady(data: JSONObject, provider: LoginProvider): JwtResult? {
            val token = data.optString("token", "").ifEmpty { return null }
            val providerObj = data.optJSONObject(provider.id)
            fun providerField(snake: String, camel: String): String? =
                providerObj?.optString(snake, "")?.ifEmpty { providerObj.optString(camel, "") }
                    ?.takeIf { it.isNotEmpty() }
            val providerAccess = providerField("access_token", "accessToken")
                ?: data.optString("access_token", "").takeIf { it.isNotEmpty() }
            val providerRefresh = providerField("refresh_token", "refreshToken")
            val userId = data.optJSONObject("user")
                ?.optString("user_id", "")?.takeIf { it.isNotEmpty() }
                ?: jwtUserId(token)
            val expiresAt = jwtExpiryMs(token) ?: (System.currentTimeMillis() + 3600_000)
            return JwtResult(token, providerAccess, userId, expiresAt, providerRefresh)
        }

        /** Decode a JWT payload without verifying the signature — the
         *  gateways do exactly this (dot-count + base64 payload) to read
         *  `user_id`/`exp`. Never used to trust the token, only to know
         *  when it expires and who it belongs to. */
        fun parseJwtPayload(jwt: String): JSONObject? {
            val parts = jwt.split(".")
            if (parts.size != 3) return null
            return runCatching {
                val decoded = java.util.Base64.getUrlDecoder().decode(
                    parts[1].padEnd((parts[1].length + 3) / 4 * 4, '='),
                )
                JSONObject(String(decoded, Charsets.UTF_8))
            }.getOrNull()
        }

        fun jwtExpiryMs(jwt: String): Long? {
            val exp = parseJwtPayload(jwt)?.optLong("exp", 0) ?: 0
            return if (exp > 0) exp * 1000 else null
        }

        fun jwtUserId(jwt: String): String? =
            parseJwtPayload(jwt)?.optString("user_id", "")
                ?.ifEmpty { parseJwtPayload(jwt)?.optString("sub", "") }
                ?.takeIf { it.isNotEmpty() }

        /** Heuristic, from the balances/plans shapes the gateways parse:
         *  plan ids/names containing CODING → Coding Plan, START → Start Plan.
         *  Defaults to START (the free trial is the common case). */
        fun derivePlanModeFromBody(currentBody: String): ZCodeConstants.PlanMode {
            val upper = currentBody.uppercase()
            // Prefer an explicit plan_mode field when present.
            val field = runCatching { JSONObject(currentBody) }.getOrNull()
                ?.optJSONObject("data")?.optString("plan_mode", "")
                ?.uppercase().orEmpty()
            if ("CODING" in field) return ZCodeConstants.PlanMode.CODING
            if ("START" in field) return ZCodeConstants.PlanMode.START
            if ("CODING" in upper) return ZCodeConstants.PlanMode.CODING
            if ("START" in upper) return ZCodeConstants.PlanMode.START
            return ZCodeConstants.PlanMode.START
        }
    }

    // Base-class abstract surface. The CLI flow uses neither a redirect nor
    // PKCE; these are inert placeholders, as in KimiOAuthManager.
    override val authURL = ZCodeConstants.OAUTH_INIT_URL
    override val tokenURL = ZCodeConstants.OAUTH_INIT_URL
    override val clientId: String get() = ZCodeConstants.PUBLIC_CLIENT_ID
    override val clientSecret: String? get() = null
    override val callbackPort: Int get() = 0
    override val redirectPath: String get() = ""
    override val scopes: String get() = ""

    /** The plan JWT, or null when absent/expired. No refresh exists. */
    override suspend fun validAccessToken(): String? = withContext(Dispatchers.IO) {
        loadManualBearerToken()?.takeIf { it.isNotEmpty() }?.let { return@withContext it }
        val stored = loadStoredTokens() ?: return@withContext null
        val token = stored.optString("access_token", "").ifEmpty { return@withContext null }
        val expireAt = stored.optLong("expire_at", 0)
        if (expireAt > 0 && System.currentTimeMillis() >= expireAt - 60_000) return@withContext null
        token
    }

    /** True while a non-expired JWT is stored. The session token tier
     *  Copilot has does not exist here — the JWT is the credential. */
    override fun isAuthenticated(): Boolean {
        if (loadManualBearerToken()?.isNotEmpty() == true) return true
        val stored = loadStoredTokens() ?: return false
        if (stored.optString("access_token", "").isEmpty()) return false
        val expireAt = stored.optLong("expire_at", 0)
        return expireAt <= 0 || System.currentTimeMillis() < expireAt - 60_000
    }

    // ── Stage 1: init ──────────────────────────────────────────────────

    /** Step 1 of [login], exposed so a UI can show the waiting dialog
     *  (and offer to re-open the authorize URL) while polling runs. */
    suspend fun beginLogin(provider: LoginProvider = LoginProvider.ZAI): InitResult =
        requestInit(provider)

    /** Step 2 of [login]: poll until authorized, then persist the JWT and
     *  seed the plan mode. Returns the JWT. */
    suspend fun finishLogin(init: InitResult): String {
        val result = pollForToken(init)
        saveJwt(result, init.provider)
        // Seed the plan mode so the model list filters correctly; a failure
        // here must not fail a login that already succeeded.
        runCatching { refreshPlanMode() }
            .onFailure { Log.w(TAG, "plan-mode seed failed after login: ${it.message}") }
        Log.i(TAG, "ZCode login complete (instance: ${instanceId.take(8)})")
        return result.jwt
    }

    private fun newPollToken(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    suspend fun requestInit(provider: LoginProvider = LoginProvider.ZAI): InitResult =
        withContext(Dispatchers.IO) {
            val pollToken = newPollToken()
            val request = Request.Builder()
                .url(ZCodeConstants.OAUTH_INIT_URL)
                .post(JSONObject().put("provider", provider.id).toString().toRequestBody(JSON_MEDIA))
                .header("Authorization", "Bearer $pollToken")
                .header("Content-Type", "application/json")
                .build()
            val response = httpClient.newCall(request).execute()
            val status = response.code
            val body = response.body?.string().orEmpty()
            response.close()
            if (status !in 200..299) {
                throw Exception("ZCode 登录初始化失败 (HTTP $status): ${sanitizedError(body)}")
            }
            val json = JSONObject(body)
            val code = json.optInt("code", 0)
            if (code != 0) {
                throw Exception("ZCode 登录初始化被拒绝 (code=$code): ${sanitizedError(body)}")
            }
            val data = json.optJSONObject("data")
                ?: throw Exception("ZCode 登录初始化返回不完整（无 data）")
            val flowId = data.optString("flow_id", "").ifEmpty {
                throw Exception("ZCode 登录初始化返回不完整（无 flow_id）")
            }
            val rawAuthorizeUrl = data.optString("authorize_url", "").ifEmpty {
                throw Exception("ZCode 登录初始化返回不完整（无 authorize_url）")
            }
            // BigModel only: point the authorize callback at the official
            // relay page. A bad URL fails here, before anything is opened.
            // Z.ai is passed through untouched.
            val authorizeUrl = rewriteAuthorizeUrlForProvider(provider, rawAuthorizeUrl)
            // Since 2026-09 the server may issue its own poll_token; polls
            // must use it when present, falling back to the self-made one.
            val effectivePollToken = data.optString("poll_token", "").ifEmpty { pollToken }
            val interval = data.optLong("poll_interval_sec", 2).coerceIn(1, 10)
            val deadlineMs = parseExpiresAtMs(data) ?: (System.currentTimeMillis() + 300_000)
            InitResult(flowId, authorizeUrl, effectivePollToken, interval, deadlineMs, provider)
        }

    private fun parseExpiresAtMs(data: JSONObject): Long? {
        // expires_at may be epoch seconds, epoch millis, or absent.
        if (data.has("expires_at")) {
            val raw = data.opt("expires_at")
            val num = when (raw) {
                is Number -> raw.toLong()
                is String -> raw.toLongOrNull()
                else -> null
            }
            if (num != null && num > 0) {
                return if (num > 1_000_000_000_000L) num else num * 1000
            }
        }
        val inSec = data.optLong("expires_in", 0)
        if (inSec > 0) return System.currentTimeMillis() + inSec * 1000
        return null
    }

    // ── Stage 2: poll ──────────────────────────────────────────────────

    suspend fun pollForToken(init: InitResult): JwtResult =
        withContext(Dispatchers.IO) {
            while (System.currentTimeMillis() < init.deadlineMs) {
                delay(init.pollIntervalSec * 1000)
                val request = Request.Builder()
                    .url("${ZCodeConstants.OAUTH_BASE}/cli/poll/${init.flowId}")
                    .get()
                    .header("Authorization", "Bearer ${init.pollToken}")
                    .build()
                val response = httpClient.newCall(request).execute()
                val status = response.code
                val body = response.body?.string().orEmpty()
                response.close()
                if (status !in 200..299) {
                    throw Exception("ZCode 登录轮询失败 (HTTP $status): ${sanitizedError(body)}")
                }
                val json = runCatching { JSONObject(body) }.getOrNull() ?: JSONObject()
                val data = json.optJSONObject("data") ?: json
                val ready = parseReady(data, init.provider)
                if (ready != null) {
                    return@withContext ready
                }
                when (data.optString("status", "").lowercase()) {
                    // Authorized but no token: a protocol error, not
                    // something polling longer will fix.
                    "ready" ->
                        throw Exception("ZCode 登录返回不完整（缺少 token）")
                    "expired", "denied", "cancelled", "canceled" ->
                        throw Exception("ZCode 登录已被${data.optString("status")}")
                }
                val code = json.optInt("code", 0)
                if (code != 0) {
                    val msg = json.optString("msg", "").ifEmpty { json.optString("message", "") }
                    throw Exception("ZCode 登录失败 (code=$code)${if (msg.isNotEmpty()) ": $msg" else ""}")
                }
                // Otherwise: still pending — keep polling until the deadline.
            }
            throw Exception("登录超时（300 秒内未完成授权），请重试。")
        }

    private fun saveJwt(result: JwtResult, provider: LoginProvider) {
        val blob = JSONObject().apply {
            put("access_token", result.jwt)
            put("expire_at", result.expiresAtMs)
            put("login_provider", provider.id)
            result.providerAccessToken?.let { put("provider_access_token", it) }
            result.providerRefreshToken?.let { put("provider_refresh_token", it) }
            result.userId?.let { put("user_id", it) }
        }
        // Stored under the standard "tokens" key so base logout() clears it
        // and backup export/import round-trip it. saveOAuthString("tokens")
        // also clears any stale needs-re-login mark.
        saveOAuthString("tokens", blob.toString())
    }

    private fun sanitizedError(body: String): String =
        OAuthManager.sanitizeBody(body, 200)

    // ── Plan mode ──────────────────────────────────────────────────────

    /** Last known plan mode (non-secret metadata; refreshed on login and
     *  on every manual 查额度). UNKNOWN before the first billing read. */
    fun planMode(): ZCodeConstants.PlanMode =
        runCatching {
            ZCodeConstants.PlanMode.valueOf(
                loadOAuthString(KEY_PLAN_MODE) ?: "UNKNOWN",
            )
        }.getOrDefault(ZCodeConstants.PlanMode.UNKNOWN)

    /**
     * Read billing/current and derive the plan mode from its plans list.
     * Throws on HTTP failure — callers that only seed state must wrap in
     * runCatching (login does).
     */
    suspend fun refreshPlanMode(): ZCodeConstants.PlanMode {
        val jwt = validAccessToken()
            ?: throw Exception("未登录 ZCode，无法读取套餐。")
        val result = billingRaw("GET", "billing/current", jwt, null, allowCaptchaRetry = false)
        if (result.httpStatus !in 200..299) {
            throw Exception("读取套餐失败 (HTTP ${result.httpStatus}): ${sanitizedError(result.body)}")
        }
        val mode = derivePlanMode(result.body)
        saveOAuthString(KEY_PLAN_MODE, mode.name)
        return mode
    }

    /** Heuristic, from the balances/plans shapes the gateways parse:
     *  plan ids/names containing CODING → Coding Plan, START → Start Plan.
     *  Defaults to START (the free trial is the common case). */
    fun derivePlanMode(currentBody: String): ZCodeConstants.PlanMode =
        derivePlanModeFromBody(currentBody)

    // ── Billing / claim (manual console) ───────────────────────────────

    suspend fun fetchBillingBalance(): ApiResult = billingAuthed("GET", "billing/balance", null)
    suspend fun fetchBillingCurrent(): ApiResult = billingAuthed("GET", "billing/current", null)
    suspend fun fetchBillingPreview(): ApiResult = billingAuthed("GET", "billing/preview", null)

    /** POST billing/claim {"plan_id": id}. One id, once — the caller
     *  chooses the id from the preview; nothing here auto-selects or
     *  loops over candidates. */
    suspend fun claimPlan(planId: String): ApiResult =
        billingAuthed("POST", "billing/claim", JSONObject().put("plan_id", planId))

    private suspend fun billingAuthed(method: String, path: String, jsonBody: JSONObject?): ApiResult {
        val jwt = validAccessToken() ?: throw Exception("未登录 ZCode，登录已过期请重新登录。")
        return billingRaw(method, path, jwt, jsonBody, allowCaptchaRetry = true)
    }

    /**
     * One billing call with at most one manual-captcha retry. On a
     * challenge the user is asked once via [ZCodeCaptchaGate]; cancel (or
     * no dialog mounted) returns the ORIGINAL result with
     * [ApiResult.captchaCancelled] set — the caller reports "已取消，未扣额度".
     */
    private suspend fun billingRaw(
        method: String,
        path: String,
        jwt: String,
        jsonBody: JSONObject?,
        allowCaptchaRetry: Boolean,
    ): ApiResult = withContext(Dispatchers.IO) {
        val first = executeBilling(method, path, jwt, jsonBody, verifyParam = null, region = null)
        if (!allowCaptchaRetry || !first.captchaChallenge) return@withContext first
        val config = runCatching { fetchCaptchaConfig(jwt) }
            .getOrDefault(ZCodeCaptchaGate.Config.FALLBACK)
        val param = ZCodeCaptchaGate.requestVerification(config)
            ?: return@withContext first.copy(captchaCancelled = true)
        // Param is single-use and ~95s TTL: use it immediately, once.
        executeBilling(method, path, jwt, jsonBody, verifyParam = param, region = config.region)
            .copy(retriedWithCaptcha = true)
    }

    private fun executeBilling(
        method: String,
        path: String,
        jwt: String,
        jsonBody: JSONObject?,
        verifyParam: String?,
        region: String?,
    ): ApiResult {
        val builder = Request.Builder()
            .url("${ZCodeConstants.PLAN_BASE}/$path")
            .header("Authorization", "Bearer $jwt")
            .header("anthropic-version", "2023-06-01")
        if (verifyParam != null) {
            builder.header("X-Aliyun-Captcha-Verify-Param", verifyParam)
            if (!region.isNullOrBlank()) builder.header("X-Aliyun-Captcha-Verify-Region", region)
        }
        if (method == "POST") {
            builder.post((jsonBody ?: JSONObject()).toString().toRequestBody(JSON_MEDIA))
        } else {
            builder.get()
        }
        val response = httpClient.newCall(builder.build()).execute()
        val status = response.code
        val body = response.body?.string().orEmpty()
        val hasCaptchaHeader =
            response.header("x-aliyun-captcha-verify-param") != null
        response.close()
        val code = runCatching { JSONObject(body).optInt("code", -1) }.getOrDefault(-1)
            .takeIf { it >= 0 }
        return ApiResult(
            httpStatus = status,
            code = code,
            body = body,
            captchaChallenge = ZCodeCaptchaGate.isCaptchaChallenge(status, body, hasCaptchaHeader),
        )
    }

    /** GET client/configs → data.configs.captcha {sceneId, region, prefix}.
     *  Falls back to the documented defaults on any failure. */
    suspend fun fetchCaptchaConfig(jwt: String? = null): ZCodeCaptchaGate.Config =
        withContext(Dispatchers.IO) {
            runCatching {
                val builder = Request.Builder()
                    .url("${ZCodeConstants.CLIENT_CONFIG_URL}?app_version=${ZCodeConstants.CLIENT_APP_VERSION}")
                    .get()
                jwt?.let { builder.header("Authorization", "Bearer $it") }
                val response = httpClient.newCall(builder.build()).execute()
                val body = response.body?.string().orEmpty()
                response.close()
                if (!response.isSuccessful) return@runCatching null
                val captcha = JSONObject(body)
                    .optJSONObject("data")
                    ?.optJSONObject("configs")
                    ?.optJSONObject("captcha") ?: return@runCatching null
                ZCodeCaptchaGate.Config(
                    sceneId = captcha.optString("sceneId", "").ifEmpty { return@runCatching null },
                    region = captcha.optString("region", "cn"),
                    prefix = captcha.optString("prefix", "no8xfe"),
                )
            }.getOrNull() ?: ZCodeCaptchaGate.Config.FALLBACK
        }
}
