package com.openminis.app.auth

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
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
 *
 * Identity headers (added after live 3001/3012 failures — the v1
 * "no device fingerprint" stance was wrong): every billing and chat
 * request carries the full client identity — a stable per-device id
 * ([deviceMid]), this phone's real platform/OS/language/timezone (see
 * [buildIdentityHeaders]) and the ZCode client version. Billing 400s
 * with 3001 parameter error when X-Device-Mid is missing; chat 405s
 * with 3012 when the identity set is incomplete. Values are the
 * phone's own, never a desktop spoof.
 */
/** Open so tests can subclass it and replace the HTTP layer via the
 *  open [OAuthManager.httpClient] seam (production code never subclasses
 *  this manager). */
open class ZCodeOAuthManager(
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

        /** EncryptedPrefs key for the stable device id (see [deviceMid]). */
        const val KEY_DEVICE_MID = "zcode_device_mid"

        /** Persisted balance-derived model ids (#14), JSON array string. */
        private const val KEY_BALANCE_MODELS = "zcode_balance_models"

        /** 1005 circuit-breaker states (#9), JSON map string. */
        private const val KEY_CLAIM_CIRCUIT = "zcode_claim_circuit"

        /** Same-day claim ledger entries (#11), JSON array string. */
        private const val KEY_CLAIM_LEDGER = "zcode_claim_ledger"

        /** Last version-manifest check, epoch ms (#19). */
        private const val KEY_VERSION_CHECK_AT = "zcode_version_check_at"

        /** Adopted client version override (#19), e.g. "3.17.2". */
        private const val KEY_CLIENT_VERSION = "zcode_client_version"

        /** 5 days between manifest checks (#19). */
        const val VERSION_CHECK_INTERVAL_MS = 5 * 24 * 60 * 60 * 1000L

        /** 429 backoff for billing/claim calls (#12): 1s then 3s, at
         *  most two retries. (hj01857655 uses 60s/120s — too long for a
         *  manual console tap; pjpv uses 500/1500/4000ms. 1s/3s is the
         *  middle ground for a user waiting on a button.) */
        val RETRY_429_DELAYS_MS = longArrayOf(1_000L, 3_000L)

        fun retry429DelayMs(attempt: Int): Long? =
            RETRY_429_DELAYS_MS.getOrNull(attempt)

        /**
         * marketing/touch seq counter (#6): starts at 0, +1 per call
         * (hj01857655 claim.go:506-511 `touchSeq atomic.Uint64`). A
         * fixed seq=0 may be deduped upstream as a repeat.
         */
        private val touchSeq = java.util.concurrent.atomic.AtomicLong(0)

        fun nextTouchSeq(): Long = touchSeq.getAndIncrement()

        /** Parse a client/configs body into a captcha config (#16).
         *  Null when the body carries no usable captcha section. */
        fun parseCaptchaConfig(body: String): ZCodeCaptchaGate.Config? {
            val captcha = runCatching {
                JSONObject(body).optJSONObject("data")
                    ?.optJSONObject("configs")?.optJSONObject("captcha")
            }.getOrNull() ?: return null
            val sceneId = captcha.optString("sceneId", "").ifEmpty { return null }
            return ZCodeCaptchaGate.Config(
                sceneId = sceneId,
                region = captcha.optString("region", "cn"),
                prefix = captcha.optString("prefix", "no8xfe"),
                skipModelRequest = captcha.optBoolean("skip_model_request", false),
                enabled = captcha.optBoolean("enabled", true),
            )
        }

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
         * [ZCodeConstants.appVersion].
         */
        fun buildBigModelRelayUrl(): String =
            "https://zcode.z.ai/app/oauth/login" +
                "?redirect=zcode://oauth/callback" +
                "&app_version=${ZCodeConstants.appVersion()}"

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

        /**
         * Visible-ASCII gate, mirroring the gateway `_clean`: a header
         * value is sent only when it is non-empty after trimming and
         * consists entirely of printable ASCII (0x20–0x7E). Anything
         * else returns null and the caller drops that header instead of
         * sending a blank or malformed value.
         */
        fun cleanHeaderValue(value: String?): String? {
            val v = value?.trim().orEmpty()
            if (v.isEmpty()) return null
            if (v.any { it.code !in 0x20..0x7E }) return null
            return v
        }

        /** Short arch label for X-Platform, from an Android ABI string. */
        fun archLabel(abi: String): String = when (abi) {
            "arm64-v8a" -> "arm64"
            "x86_64" -> "x64"
            "armeabi-v7a", "armeabi" -> "arm"
            "x86" -> "x86"
            else -> cleanHeaderValue(abi) ?: "unknown"
        }

        /**
         * Pure identity-header builder: the device-derived fields both
         * the billing set and the chat set need. [platform] is the full
         * value, e.g. "android-arm64" — see [currentIdentityHeaders] for
         * the Android-derived call. Every value passes through
         * [cleanHeaderValue]; a field that ends up empty is omitted,
         * never sent blank. X-Os-Category is always "android" here —
         * this client runs on a phone, and nothing is spoofed as a
         * desktop client.
         */
        fun buildIdentityHeaders(
            deviceMid: String,
            platform: String,
            osVersion: String,
            clientLanguage: String,
            clientTimezone: String,
        ): Map<String, String> {
            val out = linkedMapOf<String, String>()
            fun put(name: String, value: String?) {
                cleanHeaderValue(value)?.let { out[name] = it }
            }
            put("X-Device-Mid", deviceMid)
            put("X-Platform", platform)
            put("X-Os-Category", "android")
            put("X-Os-Version", osVersion)
            put("X-Client-Language", clientLanguage)
            put("X-Client-Timezone", clientTimezone)
            return out
        }

        /**
         * The X-Platform value, e.g. "android-arm64". Shared by the
         * identity headers and the preview query parameter — the two must
         * agree, they describe the same phone.
         */
        fun currentPlatform(): String {
            val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
            return "android-${archLabel(abi)}"
        }

        /**
         * Identity headers from this phone's real values: first ABI in
         * [android.os.Build.SUPPORTED_ABIS], [android.os.Build.VERSION.RELEASE],
         * the default locale's language tag and the default timezone id.
         * Delegates to [buildIdentityHeaders], so the sanitizing rules
         * are shared and unit-tested.
         */
        fun currentIdentityHeaders(deviceMid: String): Map<String, String> {
            return buildIdentityHeaders(
                deviceMid = deviceMid,
                platform = currentPlatform(),
                osVersion = android.os.Build.VERSION.RELEASE ?: "",
                clientLanguage = java.util.Locale.getDefault().toLanguageTag(),
                clientTimezone = java.util.TimeZone.getDefault().id,
            )
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

    init {
        // Adopt a previously stored version override (#19) so the
        // manifest auto-follow survives restarts. Only upgrades are
        // ever stored, so this never moves the version backwards.
        loadOAuthString(KEY_CLIENT_VERSION)?.takeIf { it.isNotBlank() }?.let {
            if (ZCodeConstants.isNewerVersion(it, ZCodeConstants.appVersion())) {
                ZCodeConstants.appVersionOverride = it
            }
        }
    }

    /** The logged-in account's user id, from the JWT payload. */
    suspend fun userId(): String? = validAccessToken()?.let { jwtUserId(it) }

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

    /**
     * Stable device id for this provider instance. Generated once
     * (random UUID) and persisted with [saveOAuthString] under
     * [KEY_DEVICE_MID], so it survives restarts and is the SAME value
     * for billing and chat. Required: billing returns 3001 parameter
     * error without X-Device-Mid, and chat risk-control (3012) wants
     * the full identity set.
     *
     * Note: this key is NOT part of the exported `oauth_tokens` blob,
     * so a backup restore generates a fresh id — upstream accepts that
     * as a new device. It is stable for the life of the install, which
     * is what the 3001/3012 checks need.
     */
    fun deviceMid(): String {
        loadOAuthString(KEY_DEVICE_MID)?.takeIf { it.isNotBlank() }?.let { return it }
        val fresh = java.util.UUID.randomUUID().toString()
        saveOAuthString(KEY_DEVICE_MID, fresh)
        return fresh
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
        .also { result ->
            // #14: remember the balance-derived model ids so the model
            // list can prefer them over the static plan list. Only on
            // HTTP success — a failed read must not wipe the last good
            // list.
            if (result.httpStatus in 200..299) {
                val ids = ZCodeActivation.parseBalanceModelIds(result.body)
                if (ids.isNotEmpty()) {
                    saveOAuthString(KEY_BALANCE_MODELS, JSONArray(ids).toString())
                }
            }
        }

    suspend fun fetchBillingCurrent(): ApiResult = billingAuthed("GET", "billing/current", null)

    /** Balance-derived model ids (#14), or empty when no balance has
     *  been read yet — the caller falls back to the static plan list. */
    fun balanceModelIds(): List<String> {
        val raw = loadOAuthString(KEY_BALANCE_MODELS) ?: return emptyList()
        val arr = runCatching { JSONArray(raw) }.getOrNull() ?: return emptyList()
        val out = mutableListOf<String>()
        for (i in 0 until arr.length()) {
            arr.optString(i, "").takeIf { it.isNotEmpty() }?.let { out.add(it) }
        }
        return out
    }

    /** Preview carries the query parameters upstream wants
     *  (app_version + platform, same platform value as X-Platform). */
    suspend fun fetchBillingPreview(): ApiResult = billingAuthed(
        "GET",
        ZCodeActivation.buildPreviewPath(
            ZCodeConstants.appVersion(),
            currentPlatform(),
        ),
        null,
    )

    /**
     * GET marketing/touch — the campaign-drop discovery channel. The
     * seq increments on every call (#6, hj01857655 `touchSeq`). Never
     * throws and never triggers a captcha dialog: any failure (no login,
     * network, HTTP, business code) is reported as an empty result and
     * the caller falls back to the preview list alone. The raw body is
     * still returned on HTTP responses so the console can show it.
     */
    suspend fun fetchMarketingTouch(): ApiResult = withContext(Dispatchers.IO) {
        runCatching {
            val jwt = validAccessToken() ?: return@withContext ApiResult(0, null, "")
            val builder = Request.Builder()
                .url(ZCodeConstants.touchUrl(nextTouchSeq()))
                .get()
            applyBillingHeaders(builder, jwt)
            val response = httpClient.newCall(builder.build()).execute()
            val status = response.code
            val body = response.body?.string().orEmpty()
            response.close()
            val code = runCatching { JSONObject(body).optInt("code", -1) }.getOrDefault(-1)
                .takeIf { it >= 0 }
            ApiResult(status, code, body)
        }.getOrElse { ApiResult(0, null, "") }
    }

    /**
     * Post-claim touch confirm receipt (#7): `POST
     * /marketing/touch/action {"campaign_id":…, "action_type":"confirm"}`.
     * Best-effort only — a failure is logged and never affects the
     * claim result (hj01857655 claim.go:601-616). Returns true when
     * upstream accepted it (HTTP < 400 and code == 0). Never throws.
     */
    suspend fun confirmTouchAction(campaignId: String): Boolean =
        withContext(Dispatchers.IO) {
            runCatching {
                val jwt = validAccessToken() ?: return@runCatching false
                val builder = Request.Builder()
                    .url(ZCodeConstants.TOUCH_CONFIRM_URL)
                    .post(
                        ZCodeActivation.buildTouchConfirmBody(campaignId).toString()
                            .toRequestBody(JSON_MEDIA),
                    )
                applyBillingHeaders(builder, jwt)
                val response = httpClient.newCall(builder.build()).execute()
                val status = response.code
                val body = response.body?.string().orEmpty()
                response.close()
                if (status >= 400) return@runCatching false
                runCatching { JSONObject(body).optInt("code", -1) }.getOrDefault(-1) == 0
            }.getOrDefault(false)
        }

    // ── Claim outcome bookkeeping (#9, #11) ───────────────────────────

    private fun loadClaimCircuit(): MutableMap<String, ZCodeActivation.ClaimCircuit.State> =
        ZCodeActivation.ClaimCircuit.deserialize(
            loadOAuthString(KEY_CLAIM_CIRCUIT).orEmpty(),
        ).toMutableMap()

    private fun saveClaimCircuit(states: Map<String, ZCodeActivation.ClaimCircuit.State>) =
        saveOAuthString(KEY_CLAIM_CIRCUIT, ZCodeActivation.ClaimCircuit.serialize(states))

    /** True when the plan is inside its 30-minute 1005 block (#9). */
    fun isClaimBlocked(planId: String): Boolean {
        val state = loadClaimCircuit()[planId] ?: return false
        return ZCodeActivation.ClaimCircuit.isBlocked(state, System.currentTimeMillis())
    }

    /** Record one 1005 on the plan; returns the updated state. */
    fun recordClaim1005(planId: String): ZCodeActivation.ClaimCircuit.State {
        val states = loadClaimCircuit()
        val updated = ZCodeActivation.ClaimCircuit.record1005(
            states[planId] ?: ZCodeActivation.ClaimCircuit.State(),
            System.currentTimeMillis(),
        )
        states[planId] = updated
        saveClaimCircuit(states)
        return updated
    }

    /** A claim success (or 1003 "already claimed") resets the count. */
    fun resetClaimCircuit(planId: String) {
        val states = loadClaimCircuit()
        states[planId] = ZCodeActivation.ClaimCircuit.recordSuccess()
        saveClaimCircuit(states)
    }

    private fun loadClaimLedger(): MutableSet<String> =
        ZCodeActivation.ClaimLedger.deserialize(
            loadOAuthString(KEY_CLAIM_LEDGER).orEmpty(),
        ).toMutableSet()

    /** True when this account already claimed this plan today (#11). */
    fun isClaimedToday(userId: String, planId: String): Boolean {
        val day = ZCodeActivation.ClaimLedger.todayCst(System.currentTimeMillis())
        return loadClaimLedger().contains(
            ZCodeActivation.ClaimLedger.entryKey(userId, planId, day),
        )
    }

    /** Record a successful (0) or already-claimed (1003) claim for today. */
    fun recordClaimedToday(userId: String, planId: String) {
        val entries = loadClaimLedger()
        val day = ZCodeActivation.ClaimLedger.todayCst(System.currentTimeMillis())
        entries.add(ZCodeActivation.ClaimLedger.entryKey(userId, planId, day))
        saveOAuthString(KEY_CLAIM_LEDGER, ZCodeActivation.ClaimLedger.serialize(entries))
    }

    /**
     * Daily-active activation report: the three events the official client
     * sends before preview (`app_launch`, `app_daily_active`, then
     * `app_login_success`). Upstream dedupes by device_mid + date, so
     * there is no local once-a-day gate — this runs on every manual 查可领
     * tap and the server ignores repeats. The first event failing aborts
     * the rest. Never throws and never blocks the caller: a failure is
     * reported in the returned [ZCodeActivation.ActivationResult] and the
     * console continues to preview anyway.
     */
    suspend fun reportActivation(): ZCodeActivation.ActivationResult =
        withContext(Dispatchers.IO) {
            val total = ZCodeActivation.ACTIVATION_ELEMENTS.size
            try {
                val jwt = validAccessToken()
                    ?: return@withContext ZCodeActivation.ActivationResult(0, total, "失败：未登录")
                val userId = jwtUserId(jwt)
                    ?: return@withContext ZCodeActivation.ActivationResult(0, total, "失败：token 里没有 user_id")
                val mid = deviceMid()
                // The login provider recorded at sign-in (token blob
                // "login_provider": LoginProvider.id, "zai" or "bigmodel").
                // Normalized through fromId so a missing or unknown value
                // falls back to "zai" — never the enum name, never hardcoded.
                val loginProviderId = LoginProvider.fromId(
                    loadStoredTokens()?.optString("login_provider", "").orEmpty(),
                ).id
                val timezone = java.util.TimeZone.getDefault().id
                val language = java.util.Locale.getDefault().toLanguageTag()
                val resolution = screenResolution()
                val osVersion = android.os.Build.VERSION.RELEASE ?: ""
                var sent = 0
                for (element in ZCodeActivation.ACTIVATION_ELEMENTS) {
                    val body = ZCodeActivation.buildActivationEventBody(
                        elementName = element,
                        userId = userId,
                        deviceMid = mid,
                        clientTimezone = timezone,
                        clientLanguage = language,
                        screenResolution = resolution,
                        osVersion = osVersion,
                        loginProvider = loginProviderId,
                    )
                    val failure = postActivationEvent(body)
                    if (failure != null) {
                        return@withContext ZCodeActivation.ActivationResult(
                            sent, total, "失败：$element $failure",
                        )
                    }
                    sent++
                }
                ZCodeActivation.ActivationResult(sent, total, "成功（$sent/$total）")
            } catch (e: Exception) {
                ZCodeActivation.ActivationResult(
                    0, total, "失败：${e.message?.take(120) ?: "网络异常"}",
                )
            }
        }

    /** One activation event POST. No Authorization header — the event is
     *  keyed by device_mid + user_id in the body. Returns null on
     *  success (HTTP < 400 and code == 0), a short failure reason
     *  otherwise. */
    private fun postActivationEvent(body: JSONObject): String? {
        val request = Request.Builder()
            .url(ZCodeConstants.EVENT_REPORT_URL)
            .post(body.toString().toRequestBody(JSON_MEDIA))
            .header("Content-Type", "application/json")
            .build()
        val response = httpClient.newCall(request).execute()
        val status = response.code
        val respBody = response.body?.string().orEmpty()
        response.close()
        if (status >= 400) return "HTTP $status"
        val code = runCatching { JSONObject(respBody).optInt("code", -1) }.getOrDefault(-1)
        return if (code == 0) null else "code=$code"
    }

    /** "1080x2400" from the real display metrics. */
    private fun screenResolution(): String {
        val dm = context.resources.displayMetrics
        return "${dm.widthPixels}x${dm.heightPixels}"
    }

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
     * One billing call with a 429 backoff retry table (#12) and at most
     * one manual-captcha retry. On a challenge the user is asked once
     * via [ZCodeCaptchaGate]. Note [ZCodeCaptchaGate.Config.skipModelRequest]
     * ("model requests skip verification", #16) applies to MODEL requests
     * (chat) only — billing calls (claim, balance, preview) still open
     * the dialog once and retry once on a 3007. Cancel (or no dialog
     * mounted) returns the ORIGINAL result with
     * [ApiResult.captchaCancelled] set — the caller reports "已取消，未扣额度".
     * 3012 is never retried: it is not a captcha challenge and a fresh
     * param does not help.
     */
    private suspend fun billingRaw(
        method: String,
        path: String,
        jwt: String,
        jsonBody: JSONObject?,
        allowCaptchaRetry: Boolean,
    ): ApiResult = withContext(Dispatchers.IO) {
        var first = executeBilling(method, path, jwt, jsonBody, verifyParam = null, region = null)
        // #12: 429 (rate limit) backs off and retries — at most twice.
        // 3012 / 3007 / anything else is not retried here: 3007 goes
        // through the captcha path below, 3012 is risk-control.
        var attempt = 0
        while (first.httpStatus == 429) {
            val waitMs = retry429DelayMs(attempt) ?: break
            delay(waitMs)
            attempt++
            first = executeBilling(method, path, jwt, jsonBody, verifyParam = null, region = null)
        }
        if (!allowCaptchaRetry || !first.captchaChallenge) return@withContext first
        val config = runCatching { fetchCaptchaConfig(jwt) }
            .getOrDefault(ZCodeCaptchaGate.Config.FALLBACK)
        // NOTE: skipModelRequest is NOT consulted here — it means "model
        // requests skip verification" (chat only). Billing calls always
        // open the dialog once on a 3007; consulting it here used to
        // swallow the claim 3007 and return the raw error with no dialog.
        val param = ZCodeCaptchaGate.requestVerification(config)
            ?: return@withContext first.copy(captchaCancelled = true)
        // Param is single-use and ~40s TTL (#15): use it immediately, once.
        executeBilling(method, path, jwt, jsonBody, verifyParam = param, region = config.region)
            .copy(retriedWithCaptcha = true)
    }

    /**
     * One billing request with the full gateway `_auth_headers` set
     * (verified in dengyie `quota.py`): the billing family 400s with
     * 3001 parameter error when X-Device-Mid is missing, so the whole
     * identity set is sent — Content-Type, User-Agent, HTTP-Referer,
     * X-Title, X-ZCode-App-Version, X-Platform, X-Release-Channel,
     * X-Client-Language, X-Client-Timezone, X-Os-Category, X-Os-Version,
     * X-Device-Mid, a fresh x-request-id per request, and Authorization.
     * There is NO anthropic-version on this path (the gateway's billing
     * headers do not have one). Captcha verify headers are added on the
     * retry only, as before.
     */
    /**
     * Shared billing header set (gateway `_auth_headers`): identity +
     * client-version/referer/title/channel + a fresh x-request-id per
     * request. Used by [executeBilling] and the marketing/touch call.
     */
    private fun applyBillingHeaders(builder: Request.Builder, jwt: String) {
        builder.header("Authorization", "Bearer $jwt")
            .header("Content-Type", "application/json")
            .header("User-Agent", "ZCode/${ZCodeConstants.appVersion()}")
            .header("HTTP-Referer", "https://zcode.z.ai")
            .header("X-Title", "Z Code@electron")
            .header("X-ZCode-App-Version", ZCodeConstants.appVersion())
            .header("X-Release-Channel", "production")
            .header("x-request-id", java.util.UUID.randomUUID().toString())
        for ((name, value) in currentIdentityHeaders(deviceMid())) {
            builder.header(name, value)
        }
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
        applyBillingHeaders(builder, jwt)
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

    /** GET client/configs → data.configs.captcha {sceneId, region,
     *  prefix, skip_model_request, enabled}. Falls back to the
     *  documented defaults on any failure. The URL carries app_version
     *  only — adding platform=android-arm64 3001s (verified 2026-11-07:
     *  the endpoint accepts no platform or a desktop platform, not
     *  android-arm64), and no Authorization is needed (code 0 without
     *  one). The dynamic fetch is the primary source for scene/region/
     *  prefix — the fallback is only for when the fetch itself fails. */
    suspend fun fetchCaptchaConfig(jwt: String? = null): ZCodeCaptchaGate.Config =
        withContext(Dispatchers.IO) {
            runCatching {
                val builder = Request.Builder()
                    .url("${ZCodeConstants.CLIENT_CONFIG_URL}?app_version=${ZCodeConstants.appVersion()}")
                    .get()
                jwt?.let { builder.header("Authorization", "Bearer $it") }
                val response = httpClient.newCall(builder.build()).execute()
                val body = response.body?.string().orEmpty()
                response.close()
                if (!response.isSuccessful) return@runCatching null
                parseCaptchaConfig(body)
            }.getOrNull() ?: ZCodeCaptchaGate.Config.FALLBACK
        }

    // ── Client version auto-follow (#19) ─────────────────────────────

    /**
     * Check the official Electron manifest for a newer client version,
     * at most once per 5 days, only when the console is opened (no
     * timer, no background job). Only upgrades are adopted
     * ([ZCodeConstants.isNewerVersion]); a failed fetch or an
     * unparseable manifest leaves the current version untouched and
     * does NOT update the last-check time, so the next console open
     * retries. Returns the effective version after the check.
     */
    suspend fun checkClientVersionIfDue(): String = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        val lastCheck = loadOAuthString(KEY_VERSION_CHECK_AT)?.toLongOrNull() ?: 0L
        if (now - lastCheck < VERSION_CHECK_INTERVAL_MS && lastCheck > 0) {
            return@withContext ZCodeConstants.appVersion()
        }
        runCatching {
            val request = Request.Builder()
                .url(ZCodeConstants.ELECTRON_MANIFEST_URL)
                .header("Accept", "application/x-yaml, text/yaml, */*")
                .header("X-Platform", "win32-x64")
                .header("X-Release-Channel", "1")
                .get()
                .build()
            val response = httpClient.newCall(request).execute()
            val body = response.body?.string().orEmpty()
            response.close()
            if (!response.isSuccessful) return@runCatching null
            ZCodeConstants.parseManifestVersion(body)
        }.getOrNull()?.let { latest ->
            if (ZCodeConstants.isNewerVersion(latest, ZCodeConstants.appVersion())) {
                saveOAuthString(KEY_CLIENT_VERSION, latest)
                ZCodeConstants.appVersionOverride = latest
                Log.i(TAG, "ZCode client version followed to $latest")
            }
            saveOAuthString(KEY_VERSION_CHECK_AT, now.toString())
        }
        ZCodeConstants.appVersion()
    }
}
