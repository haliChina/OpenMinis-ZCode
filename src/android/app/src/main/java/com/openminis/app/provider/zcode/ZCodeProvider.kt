package com.openminis.app.provider.zcode

import com.openminis.app.auth.ZCodeCaptchaGate
import com.openminis.app.auth.ZCodeConstants
import com.openminis.app.data.model.AgentContentPart
import com.openminis.app.data.model.AgentToolDefinition
import com.openminis.app.data.model.LLMError
import com.openminis.app.data.model.LLMMessage
import com.openminis.app.data.model.LLMModel
import com.openminis.app.data.model.LLMResponse
import com.openminis.app.data.model.LLMStreamChunk
import com.openminis.app.data.model.LLMUsage
import com.openminis.app.data.model.ThinkingLevel
import com.openminis.app.data.model.WireToolIdMap
import com.openminis.app.provider.ImageBudget
import com.openminis.app.provider.LLMProvider
import com.openminis.app.provider.failOnSilentEmptyCompletion
import com.openminis.app.provider.safeOptString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

/**
 * [T-zcode-provider] ZCode plan-channel chat provider (Android, v1).
 *
 * Talks DIRECTLY to the free Start Plan channel — no local gateway, no
 * Termux, no reverse proxy in the middle:
 *   POST https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages
 *   Authorization: Bearer <jwt>  +  x-api-key: <jwt>
 *   anthropic-version: 2023-06-01
 *
 * Deliberately minimal, per the v1 scope:
 * - Single account; the JWT comes from [jwtProvider] (ZCodeOAuthManager)
 *   and is never logged, never written to disk here, never cached beyond
 *   the one request.
 * - Concurrency is capped at 2 per instance (upstream's observed per-
 *   account limit), via a static [Semaphore] keyed by instance id — the
 *   cap survives provider rebuilds, which a per-object semaphore would not.
 * - No fingerprint simulation: no device_mid / install_id / platform SKU
 *   headers are sent. Only the client identity (ZCode/3.17.1) is claimed.
 * - No thinking fields are sent: the GLM thinking contract on this
 *   channel is unverified, and guessing `thinking`/`output_config` shapes
 *   is how working requests start 400ing. [thinkingLevel] is accepted and
 *   ignored.
 * - Captcha: on a 3007 challenge the provider asks [ZCodeCaptchaGate]
 *   once; if a manual-verification dialog is mounted the user completes
 *   it in a real WebView and the ORIGINAL request is retried once with
 *   `X-Aliyun-Captcha-Verify-Param`. Cancel (or no dialog mounted) throws
 *   the upstream error as-is. 3012 risk-control is NEVER retried.
 * - Errors are surfaced verbatim (upstream code + message); nothing here
 *   auto-switches models, auto-rewrites ids, or fails over to another
 *   channel. A Start Plan account asking for GLM-5.3 gets the upstream
 *   400, not a silent rewrite.
 */
class ZCodeProvider(
    private val jwtProvider: suspend () -> String?,
    override var model: LLMModel = LLMModel.zcodeFlash,
    private val instanceId: String,
    /** Supplies the captcha config for a manual retry; null when the
     *  caller cannot provide one (context-less construction). */
    private val captchaConfigProvider: (suspend () -> ZCodeCaptchaGate.Config)? = null,
    private val workingDirectory: String? = null,
) : LLMProvider, com.openminis.app.network.NetworkTagged {

    override val name = "ZCode"
    override val defaultMaxOutputTokens: Int get() = model.maxOutputTokens ?: 128_000

    override var netTag: String? = null

    private val baseClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.MINUTES)
        .writeTimeout(30, TimeUnit.SECONDS)
        .connectionPool(com.openminis.app.network.NetworkMonitor.sharedLLMConnectionPool)
        .build()

    private val client: OkHttpClient
        get() = com.openminis.app.network.NetworkHttp.client(netTag, baseClient)

    companion object {
        private val concurrencyByInstance =
            java.util.concurrent.ConcurrentHashMap<String, Semaphore>()

        /** The per-account in-flight cap (upstream-observed: 2). */
        private fun semaphoreFor(instanceId: String): Semaphore =
            concurrencyByInstance.getOrPut(instanceId) { Semaphore(2) }
    }

    // ── Non-streaming ──────────────────────────────────────────────────

    override suspend fun sendMessageClamped(
        messages: List<LLMMessage>,
        systemPrompt: String?,
        maxTokens: Int,
        temperature: Double?,
        imageParts: List<LLMMessage.ImagePart>,
        tools: List<AgentToolDefinition>,
        thinkingLevel: ThinkingLevel,
    ): LLMResponse = withContext(Dispatchers.IO) {
        semaphoreFor(instanceId).withPermit {
            val jwt = jwtProvider()
                ?: throw LLMError.InvalidApiKey("未登录 ZCode，登录已过期请重新登录。")
            val body = buildRequestBody(messages, systemPrompt, maxTokens, stream = false, temperature, imageParts, tools)
            val response = executeWithCaptchaRetry(jwt, body.toString())
            val responseBody = response.body?.string().orEmpty()
            response.close()
            if (!response.isSuccessful) throw mapHttpError(response.code, responseBody)
            parseResponse(JSONObject(responseBody))
        }
    }

    // ── Streaming ──────────────────────────────────────────────────────

    override fun streamMessageClamped(
        messages: List<LLMMessage>,
        systemPrompt: String?,
        maxTokens: Int,
        temperature: Double?,
        imageParts: List<LLMMessage.ImagePart>,
        tools: List<AgentToolDefinition>,
        thinkingLevel: ThinkingLevel,
    ): Flow<LLMStreamChunk> = rawStreamMessage(
        messages, systemPrompt, maxTokens, temperature, imageParts, tools,
    ).failOnSilentEmptyCompletion(name)

    private fun rawStreamMessage(
        messages: List<LLMMessage>,
        systemPrompt: String?,
        maxTokens: Int,
        temperature: Double?,
        imageParts: List<LLMMessage.ImagePart>,
        tools: List<AgentToolDefinition>,
    ): Flow<LLMStreamChunk> = callbackFlow {
        val semaphore = semaphoreFor(instanceId)
        semaphore.acquire()
        try {
            val jwt = jwtProvider()
                ?: throw LLMError.InvalidApiKey("未登录 ZCode，登录已过期请重新登录。")
            val body = buildRequestBody(messages, systemPrompt, maxTokens, stream = true, temperature, imageParts, tools)
            val response = executeWithCaptchaRetry(jwt, body.toString())
            if (!response.isSuccessful) {
                val errorBody = response.body?.string().orEmpty()
                response.close()
                throw mapHttpError(response.code, errorBody)
            }
            val reader = BufferedReader(InputStreamReader(response.body!!.byteStream()))
            var currentToolId: String? = null
            var currentToolName: String? = null
            val toolInputBuffer = StringBuilder()
            try {
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line ?: continue
                    if (!l.startsWith("data: ")) continue
                    val payload = l.removePrefix("data: ")
                    if (payload == "[DONE]") break
                    val event = try { JSONObject(payload) } catch (_: Exception) { continue }
                    when (event.safeOptString("type", "")) {
                        "message_start" -> {
                            send(LLMStreamChunk.Started)
                            event.optJSONObject("message")?.optJSONObject("usage")?.let {
                                send(LLMStreamChunk.Usage(parseUsage(it)))
                            }
                        }
                        "content_block_start" -> {
                            val block = event.optJSONObject("content_block")
                            if (block?.safeOptString("type", "") == "tool_use") {
                                currentToolId = block.safeOptString("id", "")
                                currentToolName = block.safeOptString("name", "")
                                toolInputBuffer.clear()
                                send(LLMStreamChunk.ToolUseStart(currentToolId!!, currentToolName!!))
                            }
                        }
                        "content_block_delta" -> {
                            val delta = event.optJSONObject("delta") ?: continue
                            when (delta.safeOptString("type", "")) {
                                "text_delta" -> {
                                    val text = delta.safeOptString("text", "")
                                    if (text.isNotEmpty()) send(LLMStreamChunk.Text(text))
                                }
                                "thinking_delta" -> {
                                    val text = delta.safeOptString("thinking", "")
                                    if (text.isNotEmpty()) send(LLMStreamChunk.ThinkingDelta(text))
                                }
                                "input_json_delta" -> {
                                    val partial = delta.safeOptString("partial_json", "")
                                    if (partial.isNotEmpty() && currentToolId != null) {
                                        toolInputBuffer.append(partial)
                                        send(LLMStreamChunk.ToolInputDelta(currentToolId!!, toolInputBuffer.toString()))
                                    }
                                }
                            }
                        }
                        "content_block_stop" -> {
                            if (currentToolId != null && currentToolName != null) {
                                val args = try { JSONObject(toolInputBuffer.toString()) } catch (_: Exception) { JSONObject() }
                                send(LLMStreamChunk.ToolCallComplete(currentToolId!!, currentToolName!!, args))
                                currentToolId = null
                                currentToolName = null
                                toolInputBuffer.clear()
                            }
                        }
                        "message_delta" -> {
                            event.optJSONObject("usage")?.let { send(LLMStreamChunk.Usage(parseUsage(it))) }
                            val stopReason = event.optJSONObject("delta")
                                ?.safeOptString("stop_reason", "")?.ifEmpty { null }
                            send(LLMStreamChunk.Finished(stopReason))
                        }
                        "error" -> {
                            val err = event.optJSONObject("error")
                            val errType = err?.safeOptString("type", "") ?: "error"
                            val errMessage = err?.safeOptString("message", "") ?: payload.take(500)
                            throw mapSseError(errType, errMessage)
                        }
                    }
                }
            } catch (e: Exception) {
                cancel("Stream error", mapError(e))
            } finally {
                reader.close()
                response.close()
            }
            channel.close()
        } catch (e: Exception) {
            // jwtProvider / request-build failures land here (not in the
            // stream try above): surface them instead of hanging the flow.
            if (e !is kotlinx.coroutines.CancellationException) {
                // Re-throw through the flow machinery: callbackFlow collects
                // a thrown exception as a flow failure.
                throw mapError(e)
            } else throw e
        } finally {
            semaphore.release()
        }
        awaitClose()
    }

    // ── Request execution + one manual-captcha retry ───────────────────

    /**
     * Execute the chat request once; on a captcha challenge, ask the user
     * once through the gate and retry the SAME request once with the param.
     * Returns the (possibly retried) response — the caller still checks
     * isSuccessful and maps errors. The caller owns closing the response.
     */
    private suspend fun executeWithCaptchaRetry(jwt: String, bodyStr: String): Response {
        val first = client.newCall(buildRequest(jwt, bodyStr, verifyParam = null, region = null)).execute()
        if (first.isSuccessful) return first
        val status = first.code
        val hasCaptchaHeader = first.header("x-aliyun-captcha-verify-param") != null
        // Peek the body to classify the failure WITHOUT consuming it for
        // the caller: buffer the bytes, then rebuild the response.
        val peeked = first.peekBody(1_048_576).string()
        val challenge = ZCodeCaptchaGate.isCaptchaChallenge(status, peeked, hasCaptchaHeader)
        if (!challenge) return first
        val configProvider = captchaConfigProvider
        if (configProvider == null) {
            // No way to ask the user from this construction — surface the
            // upstream 3007 as-is.
            return first
        }
        val config = runCatching { configProvider() }.getOrDefault(ZCodeCaptchaGate.Config.FALLBACK)
        val param = ZCodeCaptchaGate.requestVerification(config)
            ?: return first // user cancelled (or no dialog mounted): original error stands
        first.close()
        return client.newCall(
            buildRequest(jwt, bodyStr, verifyParam = param, region = config.region),
        ).execute()
    }

    private fun buildRequest(jwt: String, bodyStr: String, verifyParam: String?, region: String?): Request {
        val builder = Request.Builder()
            .url(ZCodeConstants.MESSAGES_URL)
            .post(bodyStr.toRequestBody("application/json".toMediaType()))
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer $jwt")
            .header("x-api-key", jwt)
            .header("User-Agent", "ZCode/${ZCodeConstants.CLIENT_APP_VERSION}")
            .header("X-ZCode-App-Version", ZCodeConstants.CLIENT_APP_VERSION)
            .header("X-ZCode-Agent", "glm")
        if (verifyParam != null) {
            builder.header("X-Aliyun-Captcha-Verify-Param", verifyParam)
            if (!region.isNullOrBlank()) builder.header("X-Aliyun-Captcha-Verify-Region", region)
        }
        return builder.build()
    }

    // ── Body ───────────────────────────────────────────────────────────

    private fun buildRequestBody(
        messages: List<LLMMessage>,
        systemPrompt: String?,
        maxTokens: Int,
        stream: Boolean,
        temperature: Double?,
        imageParts: List<LLMMessage.ImagePart>,
        tools: List<AgentToolDefinition>,
    ): JSONObject {
        val body = JSONObject()
        body.put("model", model.id)
        val ceiling = model.maxOutputTokens ?: 128_000
        body.put("max_tokens", maxTokens.coerceIn(1, ceiling))
        body.put("stream", stream)
        if (temperature != null) body.put("temperature", temperature)
        body.put("system", ZCodeSystemPrompt.build(systemPrompt, model.id, workingDirectory))
        if (tools.isNotEmpty()) {
            val toolsArray = JSONArray()
            for (tool in tools) toolsArray.put(tool.toAnthropicJson())
            body.put("tools", toolsArray)
            body.put("tool_choice", JSONObject().put("type", "auto"))
        }
        body.put("messages", buildMessages(messages, imageParts))
        return body
    }

    /**
     * Anthropic-format messages: text, tool_use and tool_result blocks,
     * with consecutive same-role turns merged (upstream 400s otherwise).
     * Assistant turns order thinking → text → tool_use; user turns put
     * tool_result blocks first. Orphan tool_results (no matching tool_use
     * in the most recent assistant turn) are dropped — upstream 400s those.
     */
    private fun buildMessages(
        rawMessages: List<LLMMessage>,
        imageParts: List<LLMMessage.ImagePart>,
    ): JSONArray {
        val wireIds = WireToolIdMap()
        val liveToolUseIds = rawMessages
            .filter { it.role == LLMMessage.Role.ASSISTANT }
            .flatMap { it.contentParts }
            .filterIsInstance<AgentContentPart.ToolUse>()
            .map { wireIds.idFor(it.id) }
            .toSet()
        val out = JSONArray()
        var currentRole: String? = null
        var currentBlocks = mutableListOf<JSONObject>()
        fun flush() {
            if (currentRole == null) return
            val blocks = JSONArray()
            val ordered = when (currentRole) {
                "assistant" -> {
                    val thinking = currentBlocks.filter { it.optString("type") == "thinking" }
                    val other = currentBlocks.filter { it.optString("type") != "thinking" && it.optString("type") != "tool_use" }
                    val toolUse = currentBlocks.filter { it.optString("type") == "tool_use" }
                    thinking + other + toolUse
                }
                "user" -> {
                    val results = currentBlocks.filter { it.optString("type") == "tool_result" }
                    val rest = currentBlocks.filter { it.optString("type") != "tool_result" }
                    results + rest
                }
                else -> currentBlocks
            }
            ordered.forEach { blocks.put(it) }
            out.put(JSONObject().apply {
                put("role", currentRole)
                put("content", blocks)
            })
            currentRole = null
            currentBlocks = mutableListOf()
        }
        for (msg in rawMessages) {
            val role = msg.role.value
            if (role != currentRole) flush()
            currentRole = role
            // Text content (contentParts win when present, else content).
            if (msg.contentParts.isNotEmpty()) {
                for (part in msg.contentParts) {
                    when (part) {
                        is AgentContentPart.Text -> currentBlocks.add(JSONObject().apply {
                            put("type", "text")
                            put("text", part.text)
                        })
                        is AgentContentPart.ToolUse -> currentBlocks.add(JSONObject().apply {
                            put("type", "tool_use")
                            put("id", wireIds.idFor(part.id))
                            put("name", part.name)
                            put("input", part.input)
                        })
                        is AgentContentPart.ToolResult -> {
                            // Drop orphans: no matching tool_use upstream.
                            // AgentContentPart.ToolResult carries `id` (not
                            // `toolUseId`); mirror AnthropicProvider exactly:
                            // content is an array of text (+image) blocks,
                            // is_error carried when set.
                            if (wireIds.idFor(part.id) !in liveToolUseIds) continue
                            val resultContent = JSONArray()
                            resultContent.put(JSONObject().apply {
                                put("type", "text")
                                put("text", part.content)
                            })
                            if (part.imageData != null && part.imageMimeType != null) {
                                resultContent.put(imageBlock(part.imageData, part.imageMimeType))
                            }
                            currentBlocks.add(JSONObject().apply {
                                put("type", "tool_result")
                                put("tool_use_id", wireIds.idFor(part.id))
                                put("content", resultContent)
                                if (part.isError) put("is_error", true)
                            })
                        }
                        // [T-zcode-provider] History image bytes (restored
                        // sessions, retry-after-edit, agent-emitted
                        // ImageData) — same image block as AnthropicProvider.
                        is AgentContentPart.ImageData -> currentBlocks.add(imageBlock(part.data, part.mimeType))
                    }
                }
            } else if (msg.content.isNotEmpty()) {
                currentBlocks.add(JSONObject().apply {
                    put("type", "text")
                    put("text", msg.content)
                })
            }
        }
        // Attach this turn's images to the last user turn (Anthropic image
        // blocks, base64). Images arriving without a user turn are dropped.
        if (imageParts.isNotEmpty()) {
            // Find the last user message object and append image blocks.
            for (i in out.length() - 1 downTo 0) {
                val obj = out.getJSONObject(i)
                if (obj.optString("role") == "user") {
                    val content = obj.getJSONArray("content")
                    for (img in imageParts) {
                        content.put(JSONObject().apply {
                            put("type", "image")
                            put("source", JSONObject().apply {
                                put("type", "base64")
                                put("media_type", img.mimeType)
                                put("data", android.util.Base64.encodeToString(img.data, android.util.Base64.NO_WRAP))
                            })
                        })
                    }
                    break
                }
            }
        }
        flush()
        return out
    }

    /**
     * [T-zcode-provider] One inline image as an Anthropic content block —
     * mirrors AnthropicProvider.imageBlock: format, byte budget and
     * `media_type` come from [ImageBudget.prepareForUpload], so an image
     * that cannot be made sendable becomes a text block instead of a
     * request the API rejects on every retry.
     */
    private fun imageBlock(data: ByteArray, declaredMime: String?): JSONObject {
        val upload = ImageBudget.prepareForUpload(data, declaredMime)
            ?: return JSONObject().apply {
                put("type", "text")
                put("text", ImageBudget.UNSENDABLE_IMAGE_PLACEHOLDER)
            }
        return JSONObject().apply {
            put("type", "image")
            put("source", JSONObject().apply {
                put("type", "base64")
                put("media_type", upload.mimeType)
                put("data", upload.base64())
            })
        }
    }

    // ── Response parsing / errors ──────────────────────────────────────

    private fun parseResponse(json: JSONObject): LLMResponse {
        val text = buildString {
            json.optJSONArray("content")?.let { content ->
                for (i in 0 until content.length()) {
                    val block = content.getJSONObject(i)
                    if (block.safeOptString("type", "") == "text") {
                        append(block.safeOptString("text", ""))
                    }
                }
            }
        }
        val stopReason = json.safeOptString("stop_reason", "").ifEmpty { null }
        val usage = json.optJSONObject("usage")?.let { parseUsage(it) }
        return LLMResponse(text, stopReason, usage)
    }

    private fun parseUsage(json: JSONObject): LLMUsage =
        com.openminis.app.usage.ProviderUsageParser.anthropic(json).toLLMUsage()

    /** Upstream business code from an error body, if any. */
    private fun errorCode(body: String): Int? {
        val json = runCatching { JSONObject(body) }.getOrNull() ?: return null
        val err = json.optJSONObject("error")
        if (err != null && err.has("code")) return err.optInt("code")
        if (json.has("code")) return json.optInt("code")
        return null
    }

    private fun errorMessage(status: Int, body: String): String {
        val json = runCatching { JSONObject(body) }.getOrNull()
        val err = json?.optJSONObject("error")
        val msg = err?.safeOptString("message", "")
            ?.ifEmpty { json?.safeOptString("message", "") }
            ?.ifEmpty { json?.safeOptString("msg", "") }
            .orEmpty()
        val code = errorCode(body)
        val prefix = if (code != null) "code=$code " else ""
        return if (msg.isNotEmpty()) "[$prefix$msg]".trim() else "HTTP $status: ${body.take(300)}"
    }

    private fun mapHttpError(statusCode: Int, body: String): LLMError {
        val code = errorCode(body)
        val message = errorMessage(statusCode, body)
        // Expired/invalid login: the fix is re-login, not a retry.
        if (statusCode == 401 || statusCode == 403) {
            return LLMError.InvalidApiKey("登录已过期，请重新登录。($message)")
        }
        if (statusCode == 429) return LLMError.RateLimited()
        // Quota exhausted on this plan.
        if (statusCode == 402 || code == 1005 || code == 1113) {
            return LLMError.ProviderError("ZCode 额度已用完。($message)", httpStatus = statusCode)
        }
        // Risk-control: surface verbatim, never retried.
        if (code == 3012) {
            return LLMError.ProviderError("ZCode 风控拦截 (3012)。($message)", httpStatus = statusCode)
        }
        if (statusCode in setOf(500, 502, 503, 504, 529)) {
            return LLMError.TransientError(message, httpStatus = statusCode)
        }
        return LLMError.ProviderError(message, httpStatus = statusCode)
    }

    private fun mapSseError(errType: String, errMessage: String): LLMError = when (errType) {
        "overloaded_error" -> LLMError.TransientError("[$errType] $errMessage", httpStatus = 529)
        "rate_limit_error" -> LLMError.RateLimited()
        "authentication_error", "permission_error" ->
            LLMError.InvalidApiKey("登录已过期，请重新登录。([$errType] $errMessage)")
        else -> LLMError.ProviderError("[$errType] $errMessage")
    }

    private fun mapError(error: Throwable): LLMError {
        if (error is LLMError) return error
        if (error is java.io.IOException) return LLMError.NetworkError(error)
        return LLMError.Unknown(error)
    }
}
