package com.openminis.app.auth

import com.openminis.app.data.model.LLMModel

/**
 * [T-zcode-provider] ZCode (z.ai) — constants for the built-in Android provider.
 *
 * What is verified vs. what is not:
 * - The CLI init/poll login flow, the free-plan Anthropic endpoint, the
 *   billing/preview/claim endpoints and the 3-block system shape are all
 *   verified against the four public zcode2api implementations
 *   (dengyie / angusdevgo / liu5269 / KilimcininKorOglu) and against the
 *   official zai-org/ZCode repo (docs/oauth/desktop-oauth-polling.md,
 *   config/provider/zcode-builtin.json, revision 43).
 * - The model list below is taken from that builtin file: Coding Plan offers
 *   GLM-5.3 / GLM-5.3-Flash; Start Plan (the free trial, what most users
 *   have) offers GLM-5.3-Flash / GLM-5.2 / GLM-5-Turbo and has NO GLM-5.3.
 *   Sending GLM-5.3 on a Start Plan account returns 400 — the provider
 *   deliberately does NOT rewrite it (dengyie rewrites Turbo→GLM-5.3, which
 *   disagrees with the builtin file; a 400 is shown to the user as-is).
 * - The system-prompt TEXT is transcribed verbatim from the official
 *   3.17.1 client bundle (`zcode.cjs` ContextBuilder; extraction
 *   report `~/workspace/scratch-zcode-official/system-prompt-3.17.1.md`,
 *   every sentence grep-verified). The earlier v1 self-written wording
 *   is gone. Known deviations from the official desktop session: no
 *   ZCode Desktop Context section (that surface is `zcode_desktop`
 *   only), no skills/memory sections (not configured), the caller's
 *   system prompt is appended to block 2 instead of replacing the
 *   Identity section, and the date/environment/"powered by" lines are
 *   NOT sent at all (officially they are `meta_user` attachments, not
 *   system — re-adding them needs that mechanism, not a 4th block).
 *   Block 1 has no `cache_control` in the official client either.
 *   Whether upstream actually fingerprint-checks the text (3012) is
 *   still unproven — the bundle only shows what the client sends.
 */
object ZCodeConstants {

    // ── Upstream endpoints ─────────────────────────────────────────────

    /** Free (Start Plan) channel — Anthropic wire format. */
    const val PLAN_BASE = "https://zcode.z.ai/api/v1/zcode-plan"
    const val MESSAGES_URL = "$PLAN_BASE/anthropic/v1/messages"

    /** OAuth CLI flow base (same host, outside the plan prefix). */
    const val OAUTH_BASE = "https://zcode.z.ai/api/v1/oauth"
    const val OAUTH_INIT_URL = "$OAUTH_BASE/cli/init"

    /** Client-config endpoint (captcha scene/region/prefix). */
    const val CLIENT_CONFIG_URL = "https://zcode.z.ai/api/v1/client/configs"

    /** Daily-active event report (activation signal before preview). */
    const val EVENT_REPORT_URL = "https://zcode.z.ai/api/v1/event/report"

    /** Campaign-drop discovery (activity plans, merged with preview). */
    const val MARKETING_TOUCH_URL = "https://zcode.z.ai/api/v1/marketing/touch?seq=0"

    /** Touch URL for an explicit seq (seq increments per call, #6). */
    fun touchUrl(seq: Long): String =
        "https://zcode.z.ai/api/v1/marketing/touch?seq=$seq"

    /** Post-claim touch confirm receipt (#7). */
    const val TOUCH_CONFIRM_URL = "https://zcode.z.ai/api/v1/marketing/touch/action"

    /** Official Electron release manifest (#19): latest desktop client
     *  version + download URL. Needs a real platform value — an empty
     *  platform 3001s (verified 2026-11-07). win32-x64 is used because
     *  the manifest reports the same version for every platform. The
     *  request also carries the YAML Accept header plus X-Platform /
     *  X-Release-Channel: without them some platform/header
     *  combinations answer `code 1000` or 3001 instead of the YAML. */
    const val ELECTRON_MANIFEST_URL =
        "https://zcode.z.ai/api/v1/releases/electron/manifest?platform=win32-x64&channel=1"

    /** Parse the manifest's `version: X.Y.Z` line (the manifest is YAML,
     *  not JSON). Null when the text carries no version line. */
    fun parseManifestVersion(manifestText: String): String? {
        for (line in manifestText.lines()) {
            val trimmed = line.trim()
            if (trimmed.startsWith("version:")) {
                return trimmed.removePrefix("version:").trim()
                    .takeIf { it.isNotEmpty() }
            }
        }
        return null
    }

    /** True when [candidate] is a strictly newer dotted version than
     *  [current] (numeric parts, missing parts count as 0). Used by the
     *  version auto-follow: only upgrades are ever adopted. */
    fun isNewerVersion(candidate: String, current: String): Boolean {
        fun parts(v: String): List<Int> =
            v.trim().split(".", "-", "+").mapNotNull { it.toIntOrNull() }
        val c = parts(candidate)
        val o = parts(current)
        if (c.isEmpty() || o.isEmpty()) return false
        val len = maxOf(c.size, o.size)
        for (i in 0 until len) {
            val a = c.getOrElse(i) { 0 }
            val b = o.getOrElse(i) { 0 }
            if (a != b) return a > b
        }
        return false
    }

    /**
     * Public OAuth client id, published in zai-org/ZCode `.env.example`.
     * It is a PUBLIC client id, not a secret: it is only used by the web
     * auth-code flow, the CLI init/poll flow used here does not send it.
     * Kept here so a future auth-code path does not have to re-discover it,
     * and so nobody mistakes it for something to hide or rotate.
     */
    const val PUBLIC_CLIENT_ID = "client_P8X5CMWmlaRO9gyO-KSqtg"

    /** Client version we claim. Pinned to the version dengyie's gateway
     *  verified against the live service (3.17.1); claim bumps have
     *  previously flipped 1004 "not eligible" on claim calls. */
    const val CLIENT_APP_VERSION = "3.17.1"

    /**
     * Runtime version override from the manifest auto-follow (#19).
     * Only ever moves up (see [isNewerVersion]); null means "use the
     * pinned [CLIENT_APP_VERSION]". [appVersion] is what network code
     * sends — never read [CLIENT_APP_VERSION] directly for a request.
     */
    @Volatile
    var appVersionOverride: String? = null

    fun appVersion(): String = appVersionOverride ?: CLIENT_APP_VERSION

    // ── Models (zai-org/ZCode config/provider/zcode-builtin.json) ─────

    const val MODEL_FLASH_ID = "GLM-5.3-Flash"
    const val MODEL_53_ID = "GLM-5.3"
    const val MODEL_52_ID = "GLM-5.2"
    const val MODEL_TURBO_ID = "GLM-5-Turbo"

    /** Default model: the one BOTH plans offer. */
    const val DEFAULT_MODEL_ID = MODEL_FLASH_ID

    /** Plan modes, from billing/current. */
    enum class PlanMode { START, CODING, UNKNOWN }

    /**
     * Models offered for a plan mode. Start Plan has no GLM-5.3 — do not
     * add it back "for convenience"; the upstream 400s it (code 3006).
     */
    fun modelsForPlan(mode: PlanMode): List<LLMModel> = when (mode) {
        PlanMode.CODING -> LLMModel.allZCode
        // START and UNKNOWN both get the Start Plan list: UNKNOWN is what a
        // fresh login looks like before the first billing read, and the user
        // is overwhelmingly likely to be on Start Plan.
        PlanMode.START, PlanMode.UNKNOWN -> LLMModel.allZCodeStartPlan
    }

    /** Models for balance-derived ids (#14): canonical entries in the
     *  balance order, unknown ids dropped. Empty in → empty out. */
    fun modelsForIds(ids: List<String>): List<LLMModel> {
        val byId = LLMModel.allZCode.associateBy { it.id.lowercase() }
        return ids.mapNotNull { normalizeModelId(it)?.lowercase()?.let { n -> byId[n] } }
    }

    /**
     * Normalize a model id string to its canonical spelling (#23):
     * case-insensitive match against the four known ZCode models, with
     * "[1m]"/"[200k]" context suffixes stripped first. Null when the id
     * is not a known ZCode model — the caller keeps its fallback then.
     */
    fun normalizeModelId(input: String): String? {
        val cleaned = input.trim()
            .removeSuffix("[1m]").removeSuffix("[200k]").trim()
        if (cleaned.isEmpty()) return null
        val lower = cleaned.lowercase()
        return listOf(MODEL_FLASH_ID, MODEL_53_ID, MODEL_52_ID, MODEL_TURBO_ID)
            .firstOrNull { it.lowercase() == lower }
    }

    /**
     * The model id as sent on the wire (#22): upstream receives
     * lowercase (`glm-5.3` / `glm-5.3-flash`) — a137460387
     * zcode-plan.js:16 lowercases `body.model` before sending. Unknown
     * ids are lowercased as-is rather than dropped.
     */
    fun wireModelId(modelId: String): String =
        normalizeModelId(modelId)?.lowercase() ?: modelId.trim().lowercase()

    /**
     * Whether the model accepts image input (#24): verified against the
     * official builtin config revision 43 (modelRules `.*glm-5.3.*` →
     * supportsImage false, `.*glm-5.3-flash.*` → supportsImage true;
     * GLM-5.2 and GLM-5-Turbo are false too). Only Flash has vision.
     */
    fun supportsVision(modelId: String): Boolean =
        normalizeModelId(modelId) == MODEL_FLASH_ID

    // ── Billing / claim business codes (verified in gateway code) ──────

    /**
     * Human-readable meaning of a billing/claim `code`. 0 means success;
     * anything else is shown verbatim alongside the raw response — never
     * silently retried, never auto-advanced to the next plan id.
     */
    fun claimCodeMeaning(code: Int): String = when (code) {
        0 -> "已领取"
        1001 -> "计划不存在"
        1002 -> "活动已结束"
        1003 -> "已领取过"
        1004 -> "不符合领取条件"
        1005 -> "名额已用完"
        3001 -> "参数错误"
        3007 -> "需要验证码"
        3009 -> "模型并发已满"
        3012 -> "风控拦截（unusual activity）"
        1113 -> "额度不足 / 无余额"
        401 -> "未登录"
        else -> "未知返回码"
    }
}
