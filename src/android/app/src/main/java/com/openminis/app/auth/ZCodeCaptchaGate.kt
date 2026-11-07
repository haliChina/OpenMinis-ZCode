package com.openminis.app.auth

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject

/**
 * [T-zcode-provider] Manual Aliyun captcha verification — no solver.
 *
 * When upstream answers a chat or claim request with a captcha challenge
 * (business code 3007, a 403 mentioning captcha/verify, or the
 * `x-aliyun-captcha-verify-param` response header), the request layer does
 * NOT solve anything itself: there is no jsdom / happy-dom / headless
 * browser here, no token pool, no background pre-solving. It asks this gate
 * for a VERIFY_PARAM, and the gate only resolves if a
 * [ZCodeCaptchaDialog] is currently mounted (i.e. the user is looking at a
 * screen that hosts it — v1 mounts it in the ZCode console on the provider
 * detail screen). The dialog shows a real WebView running the official
 * Aliyun SDK; traceless verification passes on its own, and if Aliyun wants
 * a slider/puzzle it shows it inside the WebView for the user to complete.
 *
 * - One challenge = at most one dialog + one retry of the original request.
 * - The param is used once, immediately, and never cached or reused
 *   (upstream TTL is ~95s).
 * - The user cancelling resolves to null: the caller aborts that request
 *   and tells the user "已取消，未扣额度". No loop, no retry.
 * - If no dialog is mounted (e.g. a chat turn while the console is not
 *   open), [requestVerification] returns null immediately instead of
 *   hanging — the caller surfaces the upstream 3007 error as-is.
 */
object ZCodeCaptchaGate {

    /** Captcha config from `client/configs`, or the documented fallback. */
    data class Config(
        val sceneId: String,
        val region: String,
        val prefix: String,
        /** Live `configs.captcha.skip_model_request` (verified true on
         *  2026-11-07): when true, model requests are sent without a
         *  verify param and a 3007 must NOT open the dialog — the user
         *  is not asked to verify something upstream says to skip. */
        val skipModelRequest: Boolean = false,
        /** Live `configs.captcha.enabled`. */
        val enabled: Boolean = true,
    ) {
        companion object {
            /** Fallback when `client/configs` cannot be fetched. Values
             *  verified in dengyie/liu gateway code. Note the live
             *  configs return region "sgp" from this VM's egress while
             *  the gateway code says "cn" — the dynamic fetch is the
             *  primary source, so the fallback region only matters when
             *  the fetch itself fails. */
            val FALLBACK = Config(sceneId = "11xygtvd", region = "cn", prefix = "no8xfe")
        }
    }

    data class PendingRequest(
        val config: Config,
        val result: CompletableDeferred<String?>,
        /** True when this request is a prefetch (the param is cached for
         *  a later request instead of completing a blocked call). */
        val isPrefetch: Boolean = false,
    )

    private val _pending = MutableStateFlow<PendingRequest?>(null)
    val pending: StateFlow<PendingRequest?> = _pending

    /** How many captcha dialogs are currently mounted. */
    private val listeners = MutableStateFlow(0)

    fun registerListener() { listeners.value += 1 }
    fun unregisterListener() { listeners.value = (listeners.value - 1).coerceAtLeast(0) }

    // ── Verify-param freshness (#15) ───────────────────────────────────

    /**
     * A verify param is usable for 40s after it is issued (a137460387
     * captcha/pool.js:14-19: usable 40s, judged 3007 at 48s; 7sen1ot:
     * ticket TTL 75s; liu5269: cache TTL 45s — 40s is the strictest).
     * The clock starts when the dialog hands the param back
     * ([complete]); a stale param is never sent — the caller treats it
     * like a cancellation and surfaces the original error.
     */
    const val PARAM_TTL_MS = 40_000L

    fun isParamFresh(issuedAtMs: Long, nowMs: Long): Boolean =
        issuedAtMs > 0 && nowMs - issuedAtMs <= PARAM_TTL_MS

    private var paramIssuedAtMs: Long = 0

    // ── Prefetched param cache (#17) ───────────────────────────────────

    /**
     * Prefetched verify params live 45s (liu5269 app/captcha.py:51-65).
     * A prefetched param is single-use: [takeCachedParam] returns it
     * once when fresh and clears it; a stale one is dropped. The cache
     * is filled by an explicit manual prefetch from the console — there
     * is no background pre-solving here, and nothing here is jsdom.
     */
    const val PREFETCH_TTL_MS = 45_000L

    private var cachedParam: String? = null
    private var cachedAtMs: Long = 0

    fun cachePrefetchedParam(param: String) {
        cachedParam = param
        cachedAtMs = System.currentTimeMillis()
    }

    fun takeCachedParam(): String? {
        val param = cachedParam ?: return null
        val issuedAt = cachedAtMs
        cachedParam = null
        cachedAtMs = 0
        return if (isParamFresh(issuedAt, System.currentTimeMillis())) param else null
    }

    /**
     * Ask the user to complete one manual verification. Returns the
     * VERIFY_PARAM, or null when the user cancels, the dialog times out
     * (5 min), or no dialog is mounted. A fresh prefetched param is
     * returned first without opening any dialog.
     */
    suspend fun requestVerification(config: Config): String? {
        takeCachedParam()?.let { return it }
        if (listeners.value == 0) return null
        val deferred = CompletableDeferred<String?>()
        _pending.value = PendingRequest(config, deferred)
        return try {
            val param = withTimeoutOrNull(300_000) { deferred.await() }
            if (param != null && isParamFresh(paramIssuedAtMs, System.currentTimeMillis())) param else null
        } finally {
            if (_pending.value?.result === deferred) _pending.value = null
        }
    }

    /**
     * Prefetch one verify param for a later request: shows the same
     * dialog (the user still completes it by hand), but the caller
     * caches the result with [cachePrefetchedParam] instead of spending
     * it on a blocked request. Returns null when no dialog is mounted
     * or another verification is already pending.
     */
    suspend fun requestPrefetch(config: Config): String? {
        if (listeners.value == 0) return null
        if (_pending.value != null) return null
        val deferred = CompletableDeferred<String?>()
        _pending.value = PendingRequest(config, deferred, isPrefetch = true)
        return try {
            withTimeoutOrNull(300_000) { deferred.await() }
        } finally {
            if (_pending.value?.result === deferred) _pending.value = null
        }
    }

    /** Called by the dialog when the user completes or cancels. */
    fun complete(param: String?) {
        if (param != null) paramIssuedAtMs = System.currentTimeMillis()
        _pending.value?.result?.complete(param)
        _pending.value = null
    }

    /**
     * True when an upstream response is a captcha challenge that the user
     * can clear by hand. 3012 (risk-control) is deliberately NOT here: a
     * 3012 is not a captcha, and retrying it with a fresh param does not
     *   help — it is surfaced as-is.
     */
    fun isCaptchaChallenge(httpStatus: Int, body: String, hasCaptchaHeader: Boolean = false): Boolean {
        if (hasCaptchaHeader) return true
        val code = runCatching { JSONObject(body).optInt("code", -1) }.getOrDefault(-1)
        if (code == 3007) return true
        if (httpStatus == 403) {
            val lower = body.lowercase()
            if ("captcha" in lower || "verify" in lower) return true
        }
        return false
    }
}
