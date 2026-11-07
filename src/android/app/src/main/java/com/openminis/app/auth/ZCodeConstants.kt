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
 * - The system-prompt TEXT here is our own wording in the verified 3-block
 *   structure, NOT a byte copy of any gateway's captured official prompt
 *   (angusdevgo's zcode-profile.json, 10701 chars, contains a hardcoded
 *   `C:\Users\Angus\...` path and must never be shipped). The upstream
 *   fingerprint check compares the official text, so this wording may be
 *   rejected with 3012 after an official client upgrade — see the known
 *   limitations in the provider file. That is a deliberate trade-off: we do
 *   not ship another project's captured client fingerprint.
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
