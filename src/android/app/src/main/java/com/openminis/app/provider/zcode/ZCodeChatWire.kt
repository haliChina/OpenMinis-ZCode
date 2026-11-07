package com.openminis.app.provider.zcode

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
}
