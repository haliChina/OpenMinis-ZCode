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
     *   `output_config: {effort: <level>}`.
     * - GLM-5.2 (levels: disabled, high, max): the same enabled
     *   shape; its lowest enabled tier is "high".
     * - GLM-5-Turbo and any other glm-5 (levels: disabled, enabled):
     *   `thinking: {type: "enabled"}` only — the family takes no
     *   effort tier.
     * - Any other model id: no fields. The contract above is only
     *   verified for the GLM-5 families; guessing a shape for an
     *   unknown id is how working requests start 400ing.
     *
     * OFF means the family default here, NOT "no thinking". The
     * official client fills a missing reasoningLevel with the family's
     * LAST declared option and always sends a thinking object (the
     * GLM-5.3 family does not even declare a disabled level), and
     * Minis gives this provider no way to tell "the user never chose
     * a level" from "the user chose OFF": the session row keeps the
     * two apart (`thinking_override` NULL vs "OFF"), but ChatViewModel
     * hydrates it into a non-null ThinkingLevel (`persisted ?: OFF`)
     * and the LLMProvider entry points take a non-null level
     * defaulting to OFF, so both arrive here as OFF. Reading OFF as
     * the official default — "max" on GLM-5.3/GLM-5.2, "enabled" on
     * GLM-5-Turbo — is the behaviour the user chose.
     *
     * Accepted consequence, stated plainly: an explicit OFF picked in
     * Minis is indistinguishable at this seam and ALSO yields the
     * family default, so the `thinking: {type: "disabled"}` literal
     * the GLM-5.2 / GLM-5-Turbo rules declare is unreachable through
     * this provider. Nothing is lost on GLM-5.3, whose rules declare
     * no disabled level in the first place.
     *
     * Explicit Minis levels snap UP onto the family's declared tiers
     * (the ThinkingRuleResolver clampEffort convention): MEDIUM has
     * no GLM counterpart and becomes "high"; XHIGH/ULTRA collapse
     * onto "max" (the same collapse AnthropicProvider.thinkingEffort
     * applies); on GLM-5.2, whose lowest enabled tier is "high",
     * LOW and MEDIUM both become "high".
     */
    fun buildThinkingFields(modelId: String, level: ThinkingLevel): JSONObject {
        val id = modelId.lowercase()
        val fields = JSONObject()
        // OFF carries the official default (see the KDoc above): the
        // family's last declared option — MAX for the effort-tiered
        // families, plain "enabled" for the toggle family.
        val effective = if (level == ThinkingLevel.OFF) ThinkingLevel.MAX else level
        when {
            // glm-5.3 also matches glm-5.3-flash; the official rules
            // give both the same values and the same map.
            id.contains("glm-5.3") -> {
                fields.put("thinking", JSONObject().put("type", "enabled"))
                fields.put(
                    "output_config",
                    JSONObject().put("effort", effortTier(effective, low = "low")),
                )
            }
            id.contains("glm-5.2") -> {
                fields.put("thinking", JSONObject().put("type", "enabled"))
                fields.put(
                    "output_config",
                    JSONObject().put("effort", effortTier(effective, low = "high")),
                )
            }
            id.contains("glm-5") -> {
                fields.put("thinking", JSONObject().put("type", "enabled"))
            }
        }
        return fields
    }

    /**
     * Snap an enabled Minis level onto a GLM effort ladder whose
     * tiers are [low] / "high" / "max" ([low] is the family's lowest
     * enabled tier: "low" on GLM-5.3, "high" on GLM-5.2). OFF never
     * reaches here — [buildThinkingFields] substitutes the family
     * default (MAX) for it first.
     */
    private fun effortTier(level: ThinkingLevel, low: String): String = when (level) {
        ThinkingLevel.LOW -> low
        ThinkingLevel.MEDIUM, ThinkingLevel.HIGH -> "high"
        ThinkingLevel.XHIGH, ThinkingLevel.MAX, ThinkingLevel.ULTRA -> "max"
        ThinkingLevel.OFF -> low // unreached: OFF is substituted in buildThinkingFields
    }
}
