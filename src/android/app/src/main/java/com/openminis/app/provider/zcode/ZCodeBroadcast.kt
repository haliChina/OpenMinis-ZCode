package com.openminis.app.provider.zcode

import com.openminis.app.auth.ZCodeConstants
import com.openminis.app.data.model.ThinkingLevel
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * [T-zcode-broadcast] Pure wire logic for the in-app ZCode broadcast:
 * a local HTTP endpoint (see [ZCodeBroadcastServer]) that exposes the
 * signed-in ZCode instance, Anthropic format, to other apps on this
 * device. The behaviour benchmark is the verified standalone proxy
 * (`tools/zcode-lan-proxy/zcode_proxy.py` on the feat/zcode-lan-proxy
 * branch): same routes, same key check, same request transforms, same
 * pass-through of upstream status/body. The differences are the ones
 * running inside the app buys: the JWT and device id come from
 * [com.openminis.app.auth.ZCodeOAuthManager] (no second login), the
 * identity headers are this phone's real ones (the script generated
 * its host machine's), thinking goes through [ZCodeChatWire] like the
 * chat path, and the default bind is loopback only.
 *
 * No Android imports — JVM-unit-testable, like [ZCodeChatWire].
 */
object ZCodeBroadcast {

    /** Default listen port (same as the standalone proxy). */
    const val DEFAULT_PORT = 8799

    const val LOOPBACK_HOST = "127.0.0.1"
    const val ANY_HOST = "0.0.0.0"

    /** Request-body cap, same 32 MB abuse guard as the proxy script. */
    const val MAX_BODY_BYTES = 32 * 1024 * 1024

    /**
     * The not-logged-in message, identical to the one the chat path
     * throws as `LLMError.InvalidApiKey` (see ZCodeProvider): a
     * broadcast caller whose instance has no usable JWT gets this
     * text in an Anthropic-shaped 401, never a fake success.
     */
    const val NOT_LOGGED_IN_MESSAGE = "未登录 ZCode，登录已过期请重新登录。"

    // ── Access key ─────────────────────────────────────────────────────

    /**
     * A fresh access key: 32 random bytes, base64url without padding
     * (43 chars). The standalone proxy used `secrets.token_urlsafe(32)`
     * — the same shape.
     */
    fun generateAccessKey(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * The key a request presented: `Authorization: Bearer <key>` wins;
     * `x-api-key` is the fallback (the proxy script's order).
     */
    fun presentedAccessKey(authorizationHeader: String?, xApiKeyHeader: String?): String? {
        val auth = authorizationHeader?.trim().orEmpty()
        if (auth.startsWith("Bearer ")) {
            return auth.removePrefix("Bearer ").trim().ifEmpty { null }
        }
        return xApiKeyHeader?.trim()?.ifEmpty { null }
    }

    /**
     * Constant-time key comparison (the proxy used
     * `hmac.compare_digest`; [MessageDigest.isEqual] is the Java
     * equivalent — it does not short-circuit on the first mismatch).
     * A missing/blank key on either side never validates.
     */
    fun isAccessKeyValid(presented: String?, expected: String?): Boolean {
        if (presented.isNullOrEmpty() || expected.isNullOrEmpty()) return false
        return MessageDigest.isEqual(
            presented.toByteArray(Charsets.UTF_8),
            expected.toByteArray(Charsets.UTF_8),
        )
    }

    // ── /v1/messages transform ─────────────────────────────────────────

    /**
     * Flatten an Anthropic `system` field (a plain string, or a list
     * of text blocks) into the single string [ZCodeSystemPrompt.build]
     * appends to its identity block — the proxy script's
     * `client_system_text`. Anything else (or nothing) becomes null.
     */
    fun clientSystemText(system: Any?): String? = when (system) {
        null, JSONObject.NULL -> null
        is String -> system
        is JSONArray -> {
            val parts = mutableListOf<String>()
            for (i in 0 until system.length()) {
                when (val block = system.opt(i)) {
                    is String -> parts.add(block)
                    is JSONObject -> if (block.optString("type") == "text") {
                        block.optString("text").takeIf { it.isNotEmpty() }?.let { parts.add(it) }
                    }
                }
            }
            if (parts.isEmpty()) null else parts.joinToString("\n\n")
        }
        else -> null
    }

    /**
     * The thinking level a broadcast request resolves to. The only
     * client signal translated is `output_config.effort` (the
     * Anthropic tier names map 1:1 onto Minis levels); everything
     * else — no thinking field, a `budget_tokens` thinking object, an
     * explicit `disabled` — resolves to OFF, which
     * [ZCodeChatWire.buildThinkingFields] reads as the family default,
     * exactly like a Minis chat turn where the user never picked a
     * level. The client's own `thinking`/`output_config` never reach
     * the wire: the gateway contract has no `budget_tokens`, and the
     * chat path's shapes are the only verified ones.
     */
    fun thinkingLevelForRequest(body: JSONObject): ThinkingLevel {
        val effort = body.optJSONObject("output_config")
            ?.optString("effort", "")?.trim()?.lowercase().orEmpty()
        return when (effort) {
            "low" -> ThinkingLevel.LOW
            "medium" -> ThinkingLevel.MEDIUM
            "high" -> ThinkingLevel.HIGH
            "max" -> ThinkingLevel.MAX
            else -> ThinkingLevel.OFF
        }
    }

    /**
     * Apply the broadcast transforms to a parsed client body, in the
     * proxy script's order:
     *  (a) model id → the lowercase wire id ([ZCodeConstants.wireModelId]);
     *  (b) `system` → the official 3 identity blocks with the client's
     *      own system text appended ([ZCodeSystemPrompt.build]);
     *  (c) thinking fields rebuilt by [ZCodeChatWire.buildThinkingFields];
     *  (d) `metadata.user_id` filled from the JWT when known (the
     *      client's other metadata keys are kept).
     * Everything else (messages, max_tokens, stream, tools…) passes
     * through untouched, like the script. Mutates and returns [body].
     */
    fun transformMessagesBody(body: JSONObject, userId: String?): JSONObject {
        val modelRaw = body.optString("model", "")
        if (modelRaw.isNotEmpty()) {
            body.put("model", ZCodeConstants.wireModelId(modelRaw))
        }
        // Read the client's effort BEFORE stripping the fields.
        val level = thinkingLevelForRequest(body)
        body.remove("thinking")
        body.remove("output_config")
        val thinkingFields = ZCodeChatWire.buildThinkingFields(modelRaw, level)
        for (key in thinkingFields.keys()) body.put(key, thinkingFields.get(key))
        body.put(
            "system",
            ZCodeSystemPrompt.build(clientSystemText(body.opt("system")), modelRaw, null),
        )
        if (!userId.isNullOrBlank()) {
            val metadata = body.optJSONObject("metadata") ?: JSONObject()
            metadata.put("user_id", userId)
            body.put("metadata", metadata)
        }
        return body
    }

    // ── /v1/models + error shapes ──────────────────────────────────────

    /**
     * The Anthropic model-list payload for [modelIds] (canonical
     * spellings): wire (lowercase) ids on the wire, canonical names
     * for display — the proxy script's `models_payload` shape.
     */
    fun modelsPayload(modelIds: List<String>): JSONObject {
        val data = JSONArray()
        for (id in modelIds) {
            data.put(
                JSONObject()
                    .put("type", "model")
                    .put("id", ZCodeConstants.wireModelId(id))
                    .put("display_name", ZCodeConstants.normalizeModelId(id) ?: id)
                    .put("created_at", "2025-01-01T00:00:00Z"),
            )
        }
        val result = JSONObject()
            .put("data", data)
            .put("has_more", false)
        if (modelIds.isNotEmpty()) {
            result.put("first_id", ZCodeConstants.wireModelId(modelIds.first()))
            result.put("last_id", ZCodeConstants.wireModelId(modelIds.last()))
        }
        return result
    }

    /** Anthropic-shaped error body: `{"type":"error","error":{…}}`. */
    fun errorBody(type: String, message: String): JSONObject =
        JSONObject()
            .put("type", "error")
            .put("error", JSONObject().put("type", type).put("message", message))
}
