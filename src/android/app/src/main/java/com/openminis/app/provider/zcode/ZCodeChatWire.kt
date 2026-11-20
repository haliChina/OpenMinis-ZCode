package com.openminis.app.provider.zcode

import com.openminis.app.data.model.ThinkingLevel
import org.json.JSONObject

/**
 * [T-zcode-provider] Pure wire-format builders for the ZCode chat
 * request — kept in their own object (no Android imports) so they stay
 * unit-testable on the JVM. [ZCodeProvider] calls them; the values they
 * produce are covered by [com.openminis.app.auth.ZCodeProviderTest].
 */
object ZCodeChatWire {

    /**
     * The six per-request trace headers (gateway `identity.py`
     * `build_trace_headers`, full set, no tiers): fresh UUIDs on
     * every call — never reuse a value across requests.
     */
    fun buildTraceHeaders(): Map<String, String> = linkedMapOf(
        "x-request-id" to java.util.UUID.randomUUID().toString(),
        "x-zcode-session-type" to "main",
        "x-zcode-trace-id" to java.util.UUID.randomUUID().toString(),
        "x-query-id" to java.util.UUID.randomUUID().toString(),
        "x-zcode-query-source" to "main_turn",
        "x-session-id" to java.util.UUID.randomUUID().toString(),
    )

    /**
     * The chat body's `metadata` object, or null when no user id is
     * known. user_id comes from the JWT payload (user_id/sub) — the
     * gateway injects metadata.user_id from the same source; when
     * the JWT has none, no metadata is sent at all.
     */
    fun buildMetadataObject(userId: String?): JSONObject? {
        val id = userId?.trim().orEmpty()
        if (id.isEmpty()) return null
        return JSONObject().put("user_id", id)
    }

    /**
     * The thinking fields for one request, as top-level body entries
     * to merge into the request body (an empty object when the request
     * must carry none). The shapes are the official client's own
     * contract — zcode-builtin.json (revision 43/44)
     * `modelConfigRules.modelApiRules` for `anthropic-messages`, keyed
     * by the model's `reasoningLevel` option:
     *
     * - GLM-5.3 / GLM-5.3-Flash (levels: low, high, max):
     *   `thinking: {type: "enabled"}` +
     *   `output_config: {effort: <level>}`. The family declares NO
     *   disabled level — the official client always thinks — so an
     *   OFF request omits both fields instead of inventing a disabled
     *   literal the family never declares. That keeps OFF byte-for-
     *   byte what this provider sent before thinking was wired up.
     * - GLM-5.2 (levels: disabled, high, max): OFF is the family's own
     *   `thinking: {type: "disabled"}` (omitting the field is not
     *   "off" on a think-by-default backend); enabled levels send
     *   `thinking: {type: "enabled"}` + `output_config.effort`.
     * - GLM-5-Turbo and any other glm-5 (levels: disabled, enabled):
     *   `thinking: {type: "enabled" | "disabled"}` only — the family
     *   takes no effort tier.
     * - Any other model id: no fields. The contract above is only
     *   verified for the GLM-5 families; guessing a shape for an
     *   unknown id is how working requests start 400ing.
     *
     * Minis levels snap UP onto the family's declared tiers (the
     * ThinkingRuleResolver clampEffort convention): MEDIUM has no
     * GLM counterpart and becomes "high"; XHIGH/ULTRA collapse onto
     * "max" (the same collapse AnthropicProvider.thinkingEffort
     * applies); on GLM-5.2, whose lowest enabled tier is "high",
     * LOW and MEDIUM both become "high".
     */
    fun buildThinkingFields(modelId: String, level: ThinkingLevel): JSONObject {
        val id = modelId.lowercase()
        val fields = JSONObject()
        when {
            // glm-5.3 also matches glm-5.3-flash; the official rules
            // give both the same values and the same map.
            id.contains("glm-5.3") -> {
                if (level == ThinkingLevel.OFF) return fields
                fields.put("thinking", JSONObject().put("type", "enabled"))
                fields.put(
                    "output_config",
                    JSONObject().put("effort", effortTier(level, low = "low")),
                )
            }
            id.contains("glm-5.2") -> {
                if (level == ThinkingLevel.OFF) {
                    fields.put("thinking", JSONObject().put("type", "disabled"))
                } else {
                    fields.put("thinking", JSONObject().put("type", "enabled"))
                    fields.put(
                        "output_config",
                        JSONObject().put("effort", effortTier(level, low = "high")),
                    )
                }
            }
            id.contains("glm-5") -> {
                fields.put(
                    "thinking",
                    JSONObject().put(
                        "type",
                        if (level == ThinkingLevel.OFF) "disabled" else "enabled",
                    ),
                )
            }
        }
        return fields
    }

    /**
     * Snap an enabled Minis level onto a GLM effort ladder whose
     * tiers are [low] / "high" / "max" ([low] is the family's lowest
     * enabled tier: "low" on GLM-5.3, "high" on GLM-5.2). OFF never
     * reaches here — callers handle it per family.
     */
    private fun effortTier(level: ThinkingLevel, low: String): String = when (level) {
        ThinkingLevel.LOW -> low
        ThinkingLevel.MEDIUM, ThinkingLevel.HIGH -> "high"
        ThinkingLevel.XHIGH, ThinkingLevel.MAX, ThinkingLevel.ULTRA -> "max"
        ThinkingLevel.OFF -> low // unreached: callers handle OFF first
    }
}
