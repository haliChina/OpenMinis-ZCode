package com.openminis.app.auth

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * [T-zcode-provider] Activation reporting + campaign-plan discovery for
 * the manual ZCode console.
 *
 * Why this exists: after the 3001/3012 header fix, billing calls succeed
 * but come back empty — no plan, no balance, preview always empty. The
 * cause (verified in dengyie `claim.py`): the official client reports a
 * daily-active event BEFORE preview, and upstream treats that signal
 * (deduped by device_mid + date) as the eligibility gate for dropping
 * activity plans. Without the report, preview is permanently empty — a
 * deadlock. The console therefore runs, on each manual 查可领 tap:
 * activation report → billing/preview → marketing/touch, and merges the
 * last two by plan_id.
 *
 * Everything in this object is pure and unit-testable on the JVM: no
 * Android imports, no network, no clock. The network calls live in
 * [ZCodeOAuthManager] ([ZCodeOAuthManager.reportActivation] /
 * [ZCodeOAuthManager.fetchMarketingTouch]); the UI flow lives in
 * ZCodeConsoleSection. Nothing here runs on a timer or in the
 * background — the report is sent only when the user taps 查可领.
 */
object ZCodeActivation {

    /** The two events, in the order the official client sends them. */
    val ACTIVATION_ELEMENTS: List<String> = listOf("app_launch", "app_daily_active")

    /** One activation report run: how many of the two events upstream
     *  accepted, and a one-line outcome for the console. Never throws. */
    data class ActivationResult(
        val sent: Int,
        val total: Int,
        val message: String,
    ) {
        val ok: Boolean get() = sent == total
    }

    /** One claimable plan, from preview or from a marketing delivery. */
    data class ClaimablePlan(
        val id: String,
        val name: String,
        val description: String = "",
        val priority: Int = 0,
        val grants: List<Grant> = emptyList(),
        val source: Source = Source.PREVIEW,
    ) {
        enum class Source { PREVIEW, TOUCH }
    }

    /** One token grant inside a plan's entitlements. */
    data class Grant(
        val name: String,
        val units: Long,
        val period: String = "",
    )

    /**
     * One activation event body — exactly the 16 fields the official
     * client sends (gateway `claim.py` / event report). [elementName] is
     * one of [ACTIVATION_ELEMENTS]; [screenResolution] is e.g.
     * "1080x2400"; [appVersion] defaults to [ZCodeConstants.CLIENT_APP_VERSION].
     * `event_extra_detail` is an empty object and `marketing_params` is
     * the literal string "{}" — both are what the gateway sends.
     */
    fun buildActivationEventBody(
        elementName: String,
        userId: String,
        deviceMid: String,
        clientTimezone: String,
        clientLanguage: String,
        screenResolution: String,
        osVersion: String,
        appVersion: String = ZCodeConstants.CLIENT_APP_VERSION,
    ): JSONObject = JSONObject().apply {
        put("event_id", UUID.randomUUID().toString())
        put("client_timezone", clientTimezone)
        put("client_language", clientLanguage)
        put("element_name", elementName)
        put("event_region", "app")
        put("event_type", "view")
        put("event_text", "")
        put("event_extra_detail", JSONObject())
        put("user_id", userId)
        put("screen_resolution", screenResolution)
        put("app_version", appVersion)
        put("device_os_category", "android")
        put("device_os_version", osVersion)
        put("device_mid", deviceMid)
        put("mac_id", "")
        put("marketing_params", "{}")
    }

    /**
     * The preview path with the query parameters upstream wants:
     * `billing/preview?app_version=3.17.1&platform=android-arm64`.
     * Both values are URL-safe by construction (digits, dots, hyphens),
     * so no encoding is needed.
     */
    fun buildPreviewPath(appVersion: String, platform: String): String =
        "billing/preview?app_version=$appVersion&platform=$platform"

    // ── Plan parsing ───────────────────────────────────────────────────

    /**
     * Plans from a billing/preview body: `data.plans` (or the older
     * `data.claimable` key). Priority is read when present, default 0.
     * Unparseable / empty bodies yield an empty list, never an exception.
     */
    fun parsePreviewPlans(body: String): List<ClaimablePlan> {
        val data = runCatching { JSONObject(body).optJSONObject("data") }.getOrNull() ?: return emptyList()
        val plans = data.optJSONArray("plans") ?: data.optJSONArray("claimable") ?: return emptyList()
        val out = mutableListOf<ClaimablePlan>()
        for (i in 0 until plans.length()) {
            parsePlanObject(plans.optJSONObject(i) ?: continue, ClaimablePlan.Source.PREVIEW)
                ?.let { out.add(it) }
        }
        return out
    }

    /**
     * Plans from a marketing/touch body. Two extraction paths, both found
     * by recursively scanning every delivery:
     *  1. `zcode_plan` / `zcodePlan` objects — full plan records (plan_id,
     *     name, description, priority, entitlements → grants).
     *  2. action buttons with `type == "claim_zcode_plan"` — their
     *     `args.plan_id` / `args.planId`; when no complete object exists
     *     for that id, a synthetic entry is added (priority 100, so it
     *     sorts first).
     * A non-zero business code, a missing `data.deliveries`, or an
     * unparseable body yields an empty list — a touch failure never
     * blocks the preview list.
     */
    fun parseTouchDeliveries(body: String): List<ClaimablePlan> {
        val root = runCatching { JSONObject(body) }.getOrNull() ?: return emptyList()
        if (root.optInt("code", 0) != 0) return emptyList()
        val deliveries = root.optJSONObject("data")?.optJSONArray("deliveries") ?: return emptyList()
        val plans = linkedMapOf<String, ClaimablePlan>()
        val actionIds = mutableListOf<String>()
        for (i in 0 until deliveries.length()) {
            scanTouchValue(deliveries.opt(i), plans, actionIds)
        }
        for (id in actionIds) {
            if (!plans.containsKey(id)) {
                plans[id] = ClaimablePlan(
                    id = id,
                    name = id,
                    description = "活动投放套餐",
                    priority = 100,
                    source = ClaimablePlan.Source.TOUCH,
                )
            }
        }
        return plans.values.toList()
    }

    private fun scanTouchValue(
        value: Any?,
        plans: MutableMap<String, ClaimablePlan>,
        actionIds: MutableList<String>,
    ) {
        when (value) {
            is JSONObject -> {
                for (key in listOf("zcode_plan", "zcodePlan")) {
                    value.optJSONObject(key)?.let { planObj ->
                        parsePlanObject(planObj, ClaimablePlan.Source.TOUCH)
                            ?.let { plans.putIfAbsent(it.id, it) }
                    }
                }
                if (value.optString("type", "") == "claim_zcode_plan") {
                    val args = value.optJSONObject("args")
                    val id = args?.optString("plan_id", "")
                        ?.ifEmpty { args.optString("planId", "") }.orEmpty()
                    if (id.isNotEmpty() && id !in actionIds) actionIds.add(id)
                }
                val keys = value.keys()
                while (keys.hasNext()) {
                    scanTouchValue(value.opt(keys.next()), plans, actionIds)
                }
            }
            is JSONArray -> {
                for (i in 0 until value.length()) {
                    scanTouchValue(value.opt(i), plans, actionIds)
                }
            }
            else -> Unit
        }
    }

    /** One plan object from either source. Null when it has no id. */
    private fun parsePlanObject(p: JSONObject, source: ClaimablePlan.Source): ClaimablePlan? {
        val id = p.optString("plan_id", "").ifEmpty { p.optString("planId", "") }
        if (id.isEmpty()) return null
        val name = p.optString("show_name", "")
            .ifEmpty { p.optString("showName", "") }
            .ifEmpty { p.optString("name", "") }
            .ifEmpty { p.optString("title", "") }
            .ifEmpty { id }
        return ClaimablePlan(
            id = id,
            name = name,
            description = p.optString("description", ""),
            priority = p.optInt("priority", 0),
            grants = parseEntitlements(p.optJSONArray("entitlements")),
            source = source,
        )
    }

    /** Token grants: only entitlements with meter=model_usage and
     *  unit_type=token. Name/units accept snake_case or camelCase keys. */
    private fun parseEntitlements(entitlements: JSONArray?): List<Grant> {
        if (entitlements == null) return emptyList()
        val out = mutableListOf<Grant>()
        for (i in 0 until entitlements.length()) {
            val e = entitlements.optJSONObject(i) ?: continue
            if (e.optString("meter", "") != "model_usage") continue
            val unitType = e.optString("unit_type", "").ifEmpty { e.optString("unitType", "") }
            if (unitType != "token") continue
            val name = e.optString("show_name", "")
                .ifEmpty { e.optString("showName", "") }
                .ifEmpty { e.optString("name", "") }
            val units = if (e.has("grant_units")) e.optLong("grant_units", 0)
            else e.optLong("grantUnits", 0)
            out.add(Grant(name, units, e.optString("period", "")))
        }
        return out
    }

    /**
     * Merge preview and touch plans by plan_id — preview wins on a
     * duplicate id — then sort by priority descending, plan_id ascending.
     */
    fun mergePlans(
        preview: List<ClaimablePlan>,
        touch: List<ClaimablePlan>,
    ): List<ClaimablePlan> {
        val seen = linkedMapOf<String, ClaimablePlan>()
        for (plan in preview) seen.putIfAbsent(plan.id, plan)
        for (plan in touch) seen.putIfAbsent(plan.id, plan)
        return seen.values.sortedWith(
            compareByDescending<ClaimablePlan> { it.priority }.thenBy { it.id },
        )
    }
}
