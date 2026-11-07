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

    /** The three events, in the order the official client sends them. */
    val ACTIVATION_ELEMENTS: List<String> = listOf("app_launch", "app_daily_active", "app_login_success")

    /** One activation report run: how many of the three events upstream
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
        /** Campaign the plan came from (touch deliveries only) — needed
         *  for the post-claim confirm receipt (#7). Empty when unknown. */
        val campaignId: String = "",
    ) {
        enum class Source { PREVIEW, TOUCH, FALLBACK }
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
     * "1080x2400"; [appVersion] defaults to the effective client
     * version ([ZCodeConstants.appVersion]).
     * `event_extra_detail` is an empty object and `marketing_params` is
     * the literal string "{}" — both are what the gateway sends — except
     * for `app_login_success`, where `event_region` is "app_profile" and
     * `event_extra_detail` carries `{"login_provider": [loginProvider]}`
     * (zcode-pool sends this third event on every claim refresh).
     */
    fun buildActivationEventBody(
        elementName: String,
        userId: String,
        deviceMid: String,
        clientTimezone: String,
        clientLanguage: String,
        screenResolution: String,
        osVersion: String,
        appVersion: String = ZCodeConstants.appVersion(),
        loginProvider: String = "zai",
    ): JSONObject = JSONObject().apply {
        // [T-zcode-provider] zcode-pool sends a third event,
        // app_login_success, on every claim refresh: same 16 fields, but
        // event_region is "app_profile" and event_extra_detail carries the
        // login provider. The other two events keep "app" and an empty object.
        val isLoginSuccess = elementName == "app_login_success"
        put("event_id", UUID.randomUUID().toString())
        put("client_timezone", clientTimezone)
        put("client_language", clientLanguage)
        put("element_name", elementName)
        put("event_region", if (isLoginSuccess) "app_profile" else "app")
        put("event_type", "view")
        put("event_text", "")
        put(
            "event_extra_detail",
            if (isLoginSuccess) {
                JSONObject().apply { put("login_provider", loginProvider) }
            } else {
                JSONObject()
            },
        )
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
        val actionCampaigns = mutableMapOf<String, String>()
        for (i in 0 until deliveries.length()) {
            val delivery = deliveries.optJSONObject(i) ?: continue
            // The confirm receipt (#7) needs the campaign id: prefer an
            // explicit campaign_id/campaignId, fall back to the delivery id.
            val campaignId = delivery.optString("campaign_id", "")
                .ifEmpty { delivery.optString("campaignId", "") }
                .ifEmpty { delivery.optString("id", "") }
            val before = actionIds.size
            scanTouchValue(delivery, plans, actionIds, campaignId)
            for (j in before until actionIds.size) {
                actionCampaigns[actionIds[j]] = campaignId
            }
        }
        for (id in actionIds) {
            if (!plans.containsKey(id)) {
                plans[id] = ClaimablePlan(
                    id = id,
                    name = id,
                    description = "活动投放套餐",
                    priority = 100,
                    source = ClaimablePlan.Source.TOUCH,
                    campaignId = actionCampaigns[id].orEmpty(),
                )
            }
        }
        return plans.values.toList()
    }

    private fun scanTouchValue(
        value: Any?,
        plans: MutableMap<String, ClaimablePlan>,
        actionIds: MutableList<String>,
        campaignId: String,
    ) {
        when (value) {
            is JSONObject -> {
                for (key in listOf("zcode_plan", "zcodePlan")) {
                    value.optJSONObject(key)?.let { planObj ->
                        parsePlanObject(planObj, ClaimablePlan.Source.TOUCH)
                            ?.let { plans.putIfAbsent(it.id, it.copy(campaignId = campaignId)) }
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
                    scanTouchValue(value.opt(keys.next()), plans, actionIds, campaignId)
                }
            }
            is JSONArray -> {
                for (i in 0 until value.length()) {
                    scanTouchValue(value.opt(i), plans, actionIds, campaignId)
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
     * Merge preview and touch plans by plan_id — touch wins on a
     * duplicate id — then sort by priority descending, plan_id ascending.
     * Touch is the real claim entry (hj01857655: preview is dead code,
     * always empty; 7sen1ot: marketing first); preview is only a backup.
     */
    fun mergePlans(
        preview: List<ClaimablePlan>,
        touch: List<ClaimablePlan>,
    ): List<ClaimablePlan> {
        val seen = linkedMapOf<String, ClaimablePlan>()
        for (plan in touch) seen.putIfAbsent(plan.id, plan)
        for (plan in preview) seen.putIfAbsent(plan.id, plan)
        return seen.values.sortedWith(
            compareByDescending<ClaimablePlan> { it.priority }.thenBy { it.id },
        )
    }

    // ── Touch claim entry (#5–#7) ───────────────────────────────────────

    /** marketing/touch URL for a seq value (seq increments, see #6). */
    fun buildTouchUrl(seq: Long): String = "marketing/touch?seq=$seq"

    /** Post-claim confirm receipt body (hj01857655 claim.go:601-616):
     *  `{"campaign_id":…, "action_type":"confirm"}`. */
    fun buildTouchConfirmBody(campaignId: String): JSONObject =
        JSONObject().apply {
            put("campaign_id", campaignId)
            put("action_type", "confirm")
        }

    // ── Claim outcome (#8, #10) ─────────────────────────────────────────

    /**
     * A claim really succeeded only when code == 0 AND `data.plan` is a
     * non-empty object (7sen1ot claims.go:323, angusdevgo
     * zcgw-server.mjs:1569-1572: code 0 with an empty plan is a failure).
     */
    fun claimSucceeded(code: Int?, body: String): Boolean {
        if (code != 0) return false
        val plan = runCatching {
            JSONObject(body).optJSONObject("data")?.optJSONObject("plan")
        }.getOrNull() ?: return false
        return plan.length() > 0
    }

    /** Next claimable time from a 1005 response: `data.plan.ends_at`,
     *  verbatim (pjpv claim.rs:70-76). Null when absent. */
    fun parseClaimNextAvailableAt(body: String): String? {
        val endsAt = runCatching {
            JSONObject(body).optJSONObject("data")
                ?.optJSONObject("plan")?.optString("ends_at", "")
        }.getOrNull().orEmpty()
        return endsAt.ifEmpty { null }
    }

    // ── 1005 circuit breaker (#9) ──────────────────────────────────────

    /**
     * Per-plan 1005 tracker: 3 consecutive 1005s on the same plan block
     * it for 30 minutes (a137460387 accounts.js:187-220). Pure state
     * machine — the manager persists the map (plan id → state) as JSON.
     * A success (or a 1003 "already claimed") resets the count.
     */
    object ClaimCircuit {
        const val MAX_CONSECUTIVE_1005 = 3
        const val BLOCK_MS = 30 * 60 * 1000L

        data class State(val consecutive1005: Int = 0, val blockedUntilMs: Long = 0)

        fun record1005(state: State, nowMs: Long): State {
            val count = state.consecutive1005 + 1
            return if (count >= MAX_CONSECUTIVE_1005) {
                State(count, nowMs + BLOCK_MS)
            } else {
                State(count, state.blockedUntilMs)
            }
        }

        fun recordSuccess(): State = State(0, 0)

        fun isBlocked(state: State, nowMs: Long): Boolean =
            state.blockedUntilMs > nowMs

        fun serialize(states: Map<String, State>): String {
            val obj = JSONObject()
            for ((planId, st) in states) {
                obj.put(planId, JSONObject().apply {
                    put("n", st.consecutive1005)
                    put("until", st.blockedUntilMs)
                })
            }
            return obj.toString()
        }

        fun deserialize(raw: String): Map<String, State> {
            val out = linkedMapOf<String, State>()
            val obj = runCatching { JSONObject(raw) }.getOrNull() ?: return out
            val keys = obj.keys()
            while (keys.hasNext()) {
                val planId = keys.next()
                val st = obj.optJSONObject(planId) ?: continue
                out[planId] = State(
                    consecutive1005 = st.optInt("n", 0),
                    blockedUntilMs = st.optLong("until", 0),
                )
            }
            return out
        }
    }

    // ── Daily claim ledger (#11) ───────────────────────────────────────

    /**
     * Same-day claim ledger: after a claim returns 0 or 1003, the
     * (account, plan) pair is recorded for the day (hj01857655
     * claim.go:322-383). The day is the Asia/Shanghai calendar date, so
     * the ledger follows the server's day boundary. Pure helpers — the
     * manager persists the entry set as a JSON array string.
     */
    object ClaimLedger {
        fun todayCst(nowMs: Long): String =
            java.time.Instant.ofEpochMilli(nowMs)
                .atZone(java.time.ZoneId.of("Asia/Shanghai"))
                .toLocalDate().toString()

        fun entryKey(userId: String, planId: String, dayCst: String): String =
            "$userId|$planId|$dayCst"

        fun serialize(entries: Set<String>): String {
            val arr = JSONArray()
            for (e in entries) arr.put(e)
            return arr.toString()
        }

        fun deserialize(raw: String): Set<String> {
            val out = linkedSetOf<String>()
            val arr = runCatching { JSONArray(raw) }.getOrNull() ?: return out
            for (i in 0 until arr.length()) {
                arr.optString(i, "").takeIf { it.isNotEmpty() }?.let { out.add(it) }
            }
            return out
        }
    }

    // ── Preview-empty cross-check (#13) ────────────────────────────────

    /** What billing/current + billing/balance say about the account,
     *  used when preview comes back empty: distinguishes "no plan at
     *  all" from "has a plan but nothing claimable" (liu5269
     *  app/quota.py:61-89). */
    data class CrossCheck(
        val hasPlan: Boolean,
        val hasBalance: Boolean,
        val summary: String,
    )

    fun crossCheckPlan(balanceBody: String, currentBody: String): CrossCheck {
        val plans = runCatching {
            JSONObject(currentBody).optJSONObject("data")?.optJSONArray("plans")
        }.getOrNull()
        val hasPlan = (plans?.length() ?: 0) > 0
        var hasBalance = false
        val balances = runCatching {
            JSONObject(balanceBody).optJSONObject("data")?.optJSONArray("balances")
        }.getOrNull()
        if (balances != null) {
            for (i in 0 until balances.length()) {
                val b = balances.optJSONObject(i) ?: continue
                if (b.optLong("remaining_units", 0) > 0) {
                    hasBalance = true
                    break
                }
            }
        }
        val summary = when {
            !hasPlan && !hasBalance -> "账号无套餐、无余额（current 与 balance 均为空）"
            !hasPlan -> "current 无套餐，但 balance 仍有余额"
            !hasBalance -> "账号有套餐，但 balance 余额为 0"
            else -> "账号有套餐且有余额，只是当前没有可领计划"
        }
        return CrossCheck(hasPlan, hasBalance, summary)
    }

    // ── Balance-derived models (#14) ───────────────────────────────────

    /**
     * Model ids from a billing/balance body: `data.balances[]` entries
     * carry `capabilities` ("model:GLM-5.3-Flash", …) and/or a `model`
     * field. "model:" prefixes and "[1m]"/"[200k]" context suffixes
     * (7sen1ot gateway.go:119-151, request.go:8) are stripped, and ids
     * are normalized to the canonical spelling. Unknown ids are dropped.
     */
    fun parseBalanceModelIds(balanceBody: String): List<String> {
        val out = linkedSetOf<String>()
        val balances = runCatching {
            JSONObject(balanceBody).optJSONObject("data")?.optJSONArray("balances")
        }.getOrNull() ?: return emptyList()
        for (i in 0 until balances.length()) {
            val b = balances.optJSONObject(i) ?: continue
            fun add(raw: String) {
                var id = raw.trim()
                    .removePrefix("model:")
                    .removeSuffix("[1m]").removeSuffix("[200k]")
                    .trim()
                if (id.isEmpty()) return
                ZCodeConstants.normalizeModelId(id)?.let { out.add(it) }
            }
            b.optString("model", "").takeIf { it.isNotEmpty() }?.let { add(it) }
            when (val caps = b.opt("capabilities")) {
                is JSONArray -> for (j in 0 until caps.length()) {
                    caps.optString(j, "").takeIf { it.isNotEmpty() }?.let { add(it) }
                }
                is JSONObject -> {
                    val keys = caps.keys()
                    while (keys.hasNext()) add(keys.next())
                }
            }
        }
        return out.toList()
    }

    // ── Date-coded fallback plan ids (#20) ─────────────────────────────

    /**
     * Fallback claimable ids when preview AND touch are both empty
     * (angusdevgo zcgw-server.mjs:1470-1535). The daily package has a
     * fixed id; the weekend package is date-coded `zcode-v3-start-plan-
     * {MMDD}-wk`, generated for yesterday/today/tomorrow (Beijing time)
     * because the server's day boundary is not guaranteed to match the
     * phone's. These ids are the author's empirical values — they are
     * offered only as selectable fallback entries, never auto-claimed,
     * and the console marks them "兑底（待实测）".
     */
    fun buildDateCodedFallbackIds(todayCst: java.time.LocalDate): List<String> {
        val out = mutableListOf<String>()
        out.add("zcode-v3-start-plan-0817")
        for (delta in listOf(-1L, 0L, 1L)) {
            val mmdd = todayCst.plusDays(delta)
                .format(java.time.format.DateTimeFormatter.ofPattern("MMdd"))
            out.add("zcode-v3-start-plan-$mmdd-wk")
        }
        return out
    }

    /**
     * Which package categories look missing from a billing/current
     * body — heuristic only: a weekend ("-wk") plan id and a daily
     * plan id are looked for among the current plans. Used as a display
     * hint next to the claimable list, never as an auto-claim trigger.
     */
    fun classifyMissingCategories(currentBody: String): Set<String> {
        val ids = mutableListOf<String>()
        val plans = runCatching {
            JSONObject(currentBody).optJSONObject("data")?.optJSONArray("plans")
        }.getOrNull()
        if (plans != null) {
            for (i in 0 until plans.length()) {
                plans.optJSONObject(i)?.optString("plan_id", "")
                    ?.takeIf { it.isNotEmpty() }?.let { ids.add(it) }
            }
        }
        val missing = mutableSetOf<String>()
        if (ids.none { "-wk" in it }) missing.add("weekend")
        if (ids.none { "0817" in it || "daily" in it.lowercase() }) missing.add("daily")
        return missing
    }

    // ── Balance detail (#25) ───────────────────────────────────────────

    /** One quota bucket from billing/balance, with full fields. */
    data class BalanceBucket(
        val name: String,
        val remaining: Long,
        val total: Long,
        val used: Long,
        val period: String,
        val expiresAt: String,
        val capabilities: List<String>,
    ) {
        /** "daily" → 每日重置；anything else shown verbatim. */
        val periodLabel: String get() = when (period.lowercase()) {
            "daily" -> "每日重置"
            "" -> ""
            else -> period
        }
    }

    /** One plan from billing/current, with full fields. */
    data class BalancePlan(
        val id: String,
        val name: String,
        val period: String,
        val expiresAt: String,
        val capabilities: List<String>,
    )

    data class BalanceDetail(
        val plans: List<BalancePlan>,
        val buckets: List<BalanceBucket>,
    )

    /** Parse plans[] + balances[] with all fields (hj01857655
     *  accounts.go:315-424): capabilities, period, expires_at — so the
     *  console can tell the GLM-5.3-Flash bucket apart from the GLM-5.3
     *  bucket and say when a bucket resets. Never throws. */
    fun parseBalanceDetail(body: String): BalanceDetail {
        val data = runCatching { JSONObject(body).optJSONObject("data") }.getOrNull()
            ?: return BalanceDetail(emptyList(), emptyList())
        fun capsOf(obj: JSONObject): List<String> {
            val out = mutableListOf<String>()
            when (val caps = obj.opt("capabilities")) {
                is JSONArray -> for (j in 0 until caps.length()) {
                    caps.optString(j, "").takeIf { it.isNotEmpty() }?.let { out.add(it) }
                }
                is JSONObject -> {
                    val keys = caps.keys()
                    while (keys.hasNext()) out.add(keys.next())
                }
            }
            return out
        }
        val plans = mutableListOf<BalancePlan>()
        data.optJSONArray("plans")?.let { arr ->
            for (i in 0 until arr.length()) {
                val p = arr.optJSONObject(i) ?: continue
                val id = p.optString("plan_id", "").ifEmpty { p.optString("planId", "") }
                if (id.isEmpty()) continue
                plans.add(
                    BalancePlan(
                        id = id,
                        name = p.optString("show_name", "")
                            .ifEmpty { p.optString("showName", "") }
                            .ifEmpty { p.optString("name", "") }
                            .ifEmpty { id },
                        period = p.optString("period", ""),
                        expiresAt = p.optString("expires_at", "")
                            .ifEmpty { p.optString("expiresAt", "") },
                        capabilities = capsOf(p),
                    ),
                )
            }
        }
        val buckets = mutableListOf<BalanceBucket>()
        data.optJSONArray("balances")?.let { arr ->
            for (i in 0 until arr.length()) {
                val b = arr.optJSONObject(i) ?: continue
                buckets.add(
                    BalanceBucket(
                        name = b.optString("show_name", "").ifEmpty { b.optString("model", "") },
                        remaining = b.optLong("remaining_units", -1),
                        total = b.optLong("total_units", -1),
                        used = b.optLong("used_units", -1),
                        period = b.optString("period", ""),
                        expiresAt = b.optString("expires_at", "")
                            .ifEmpty { b.optString("expiresAt", "") },
                        capabilities = capsOf(b),
                    ),
                )
            }
        }
        return BalanceDetail(plans, buckets)
    }
}
