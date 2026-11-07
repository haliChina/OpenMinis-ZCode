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
    ) {
        companion object {
            /** Fallback when `client/configs` cannot be fetched. Values
             *  verified in dengyie/liu gateway code. */
            val FALLBACK = Config(sceneId = "11xygtvd", region = "cn", prefix = "no8xfe")
        }
    }

    data class PendingRequest(
        val config: Config,
        val result: CompletableDeferred<String?>,
    )

    private val _pending = MutableStateFlow<PendingRequest?>(null)
    val pending: StateFlow<PendingRequest?> = _pending

    /** How many captcha dialogs are currently mounted. */
    private val listeners = MutableStateFlow(0)

    fun registerListener() { listeners.value += 1 }
    fun unregisterListener() { listeners.value = (listeners.value - 1).coerceAtLeast(0) }

    /**
     * Ask the user to complete one manual verification. Returns the
     * VERIFY_PARAM, or null when the user cancels, the dialog times out
     * (5 min), or no dialog is mounted.
     */
    suspend fun requestVerification(config: Config): String? {
        if (listeners.value == 0) return null
        val deferred = CompletableDeferred<String?>()
        _pending.value = PendingRequest(config, deferred)
        return try {
            withTimeoutOrNull(300_000) { deferred.await() }
        } finally {
            if (_pending.value?.result === deferred) _pending.value = null
        }
    }

    /** Called by the dialog when the user completes or cancels. */
    fun complete(param: String?) {
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
