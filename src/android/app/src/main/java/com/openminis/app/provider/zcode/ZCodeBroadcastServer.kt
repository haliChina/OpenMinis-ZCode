package com.openminis.app.provider.zcode

import com.openminis.app.auth.ZCodeConstants
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * [T-zcode-broadcast] The broadcast HTTP service: a minimal HTTP/1.1
 * server on [java.net.ServerSocket] + coroutines — no new dependency
 * (the repo has no embedded-server library; [com.openminis.app.auth.OAuthCallbackServer]
 * is the existing raw-socket precedent). One request per connection
 * (`Connection: close` on every response): Anthropic clients handle
 * that fine, and it keeps the relay bookkeeping trivially correct for
 * streamed (SSE) responses, which are re-framed as chunked and
 * flushed per chunk, never buffered whole.
 *
 * Behaviour mirrors the standalone proxy script route for route:
 * `GET /health` is the only unauthenticated route; everything else
 * needs the access key; upstream status and body pass through
 * verbatim (a 3007 captcha challenge included — the broadcast cannot
 * solve captchas and never retries); an upstream connection failure
 * is a 502. The one deliberate addition over the script: when the
 * bound instance has no usable JWT, `/v1/messages` answers the app's
 * own not-logged-in message as a 401 instead of forwarding a bare
 * request.
 *
 * All Android-shaped inputs are injected: the caller supplies the
 * access key, the per-request session (JWT + identity headers) and
 * the upstream transport, so this class stays JVM-testable with real
 * sockets. The [semaphore] is the ZCode account's shared in-flight
 * budget (see ZCodeProvider.sharedSemaphoreFor): chat and broadcast
 * together never exceed 2 upstream requests.
 *
 * Logs (via [log]) carry only method, path, model, status and
 * latency — never the key, the JWT, or body content.
 */
class ZCodeBroadcastServer(
    private val accessKeyProvider: () -> String?,
    private val sessionProvider: suspend () -> Session?,
    private val modelsProvider: () -> List<String>,
    private val upstream: Upstream,
    private val semaphore: Semaphore,
    private val maxBodyBytes: Int = ZCodeBroadcast.MAX_BODY_BYTES,
    private val log: (String) -> Unit = {},
) {

    /** One signed-in instance's upstream identity for a request. */
    class Session(
        val jwt: String,
        val userId: String?,
        /** Static + client-identity headers (everything except the
         *  Authorization pair, the Anthropic version headers and the
         *  per-request trace headers, which the server adds). */
        val baseHeaders: Map<String, String>,
    )

    /** Blocking upstream transport, injected so tests can fake it. */
    interface Upstream {
        /** POST [body] to [url] with [headers]; blocks until the
         *  response headers arrive. Throws [IOException] on a
         *  connection failure (mapped to 502). */
        fun post(url: String, body: ByteArray, headers: Map<String, String>): Response

        class Response(
            val status: Int,
            val contentType: String?,
            /** Headers worth relaying, keyed by LOWERCASE name. */
            val headers: Map<String, String>,
            val body: InputStream,
            private val closer: () -> Unit = {},
        ) : java.io.Closeable {
            override fun close() {
                runCatching { body.close() }
                runCatching { closer() }
            }
        }
    }

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var runScope: CoroutineScope? = null

    /** The address actually bound (after [start]); null before. */
    @Volatile
    var boundAddress: InetSocketAddress? = null
        private set

    val isRunning: Boolean get() = serverSocket != null

    /**
     * Bind synchronously (so a taken port fails the CALLER with the
     * [java.net.BindException], never silently) and start accepting.
     * Single-use per start; call [stop] before starting again.
     */
    fun start(host: String, port: Int) {
        check(serverSocket == null) { "broadcast server already started" }
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(InetAddress.getByName(host), port))
        serverSocket = ss
        boundAddress = ss.localSocketAddress as InetSocketAddress
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        runScope = scope
        scope.launch { acceptLoop(ss, scope) }
    }

    fun stop() {
        runCatching { serverSocket?.close() }
        serverSocket = null
        boundAddress = null
        runScope?.cancel()
        runScope = null
    }

    private suspend fun acceptLoop(ss: ServerSocket, scope: CoroutineScope) {
        while (!ss.isClosed) {
            val socket = try {
                ss.accept()
            } catch (e: IOException) {
                break // closed by stop(), or a fatal accept error
            }
            scope.launch { handleConnection(socket) }
        }
    }

    // ── Connection handling ────────────────────────────────────────────

    private suspend fun handleConnection(socket: Socket) {
        try {
            socket.soTimeout = REQUEST_READ_TIMEOUT_MS
            handleStreams(
                BufferedInputStream(socket.getInputStream()),
                BufferedOutputStream(socket.getOutputStream()),
            )
        } finally {
            runCatching { socket.close() }
        }
    }

    /**
     * One request/response exchange over a stream pair — everything
     * [handleConnection] does except the socket itself. Internal (not
     * private) so unit tests can drive the real routing/transform/
     * relay code over in-memory pipes: this sandbox intercepts
     * loopback TCP (even a same-JVM ServerSocket/Socket pair never
     * connects), so a live-socket test cannot run here.
     */
    internal suspend fun handleStreams(input: InputStream, output: OutputStream) {
        val startedAt = System.nanoTime()
        var method = "-"
        var path = "-"
        var model = "-"
        var status = 500
        try {
            val requestLine = readAsciiLine(input, MAX_LINE_BYTES)
            if (requestLine == null) return // connection opened and closed silently
            val parts = requestLine.split(" ")
            if (parts.size < 2) {
                sendError(output, 400, "invalid_request_error", "malformed request line")
                status = 400
                return
            }
            method = parts[0].uppercase()
            path = parts[1].substringBefore('?')
            val headers = readHeaders(input)
            if (headers == null) {
                sendError(output, 400, "invalid_request_error", "malformed headers")
                status = 400
                return
            }
            val result = dispatch(method, path, headers, input, output)
            status = result.first
            model = result.second
        } catch (e: IOException) {
            status = 499 // client went away, or a socket timeout
        } catch (e: Exception) {
            status = 500
            runCatching {
                sendError(output, 500, "api_error", "internal broadcast error")
            }
        } finally {
            val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000
            runCatching { log("$method $path model=$model status=$status ${elapsedMs}ms") }
        }
    }

    /** Route table, in the proxy script's order. Returns (status, modelForLog). */
    private suspend fun dispatch(
        method: String,
        path: String,
        headers: Map<String, String>,
        input: InputStream,
        output: OutputStream,
    ): Pair<Int, String> {
        if (path == "/health") {
            if (method != "GET") {
                sendError(output, 405, "invalid_request_error", "method not allowed")
                return 405 to "-"
            }
            sendJson(output, 200, JSONObject().put("ok", true))
            return 200 to "-"
        }
        val presented = ZCodeBroadcast.presentedAccessKey(
            headers["authorization"], headers["x-api-key"],
        )
        if (!ZCodeBroadcast.isAccessKeyValid(presented, accessKeyProvider())) {
            sendError(output, 401, "authentication_error", "missing or invalid access key")
            return 401 to "-"
        }
        if (path == "/v1/models" && method == "GET") {
            sendJson(output, 200, ZCodeBroadcast.modelsPayload(modelsProvider()))
            return 200 to "-"
        }
        if (path == "/v1/messages" && method == "POST") {
            return handleMessages(headers, input, output)
        }
        if (path == "/v1/models" || path == "/v1/messages") {
            sendError(output, 405, "invalid_request_error", "method not allowed")
            return 405 to "-"
        }
        sendError(output, 404, "not_found_error", "unknown path: $path")
        return 404 to "-"
    }

    private suspend fun handleMessages(
        headers: Map<String, String>,
        input: InputStream,
        output: OutputStream,
    ): Pair<Int, String> {
        if (headers.containsKey("transfer-encoding")) {
            sendError(output, 400, "invalid_request_error", "chunked request bodies are not supported")
            return 400 to "-"
        }
        val length = headers["content-length"]?.trim()?.toIntOrNull()
        if (length == null || length < 0) {
            sendError(output, 400, "invalid_request_error", "missing or invalid Content-Length")
            return 400 to "-"
        }
        if (length > maxBodyBytes) {
            sendError(output, 413, "invalid_request_error", "request body exceeds the size limit")
            return 413 to "-"
        }
        val raw = readBody(input, length)
        if (raw == null) {
            sendError(output, 400, "invalid_request_error", "truncated request body")
            return 400 to "-"
        }
        val body = try {
            JSONObject(String(raw, Charsets.UTF_8))
        } catch (e: Exception) {
            sendError(output, 400, "invalid_request_error", "request body is not valid JSON")
            return 400 to "-"
        }
        val session = sessionProvider()
        if (session == null) {
            // The bound instance is not signed in (or its token died):
            // say so in the app's own words, never forward a bare call.
            sendError(output, 401, "authentication_error", ZCodeBroadcast.NOT_LOGGED_IN_MESSAGE)
            return 401 to "-"
        }
        val transformed = ZCodeBroadcast.transformMessagesBody(body, session.userId)
        val model = transformed.optString("model", "").ifEmpty { "-" }
        val outBytes = transformed.toString().toByteArray(Charsets.UTF_8)
        val upstreamHeaders = linkedMapOf<String, String>()
        upstreamHeaders["anthropic-version"] = "2023-06-01"
        upstreamHeaders["content-type"] = "application/json"
        upstreamHeaders["Authorization"] = "Bearer ${session.jwt}"
        upstreamHeaders["x-api-key"] = session.jwt
        upstreamHeaders.putAll(session.baseHeaders)
        upstreamHeaders.putAll(ZCodeChatWire.buildTraceHeaders())

        // The account-wide in-flight budget: the permit is held for
        // the whole relay, exactly like the provider's streaming path.
        return semaphore.withPermit {
            val response = try {
                upstream.post(ZCodeConstants.MESSAGES_URL, outBytes, upstreamHeaders)
            } catch (e: IOException) {
                sendError(output, 502, "api_error", "upstream connection failed")
                return@withPermit 502 to model
            }
            try {
                relay(response, output) to model
            } finally {
                response.close()
            }
        }
    }

    /**
     * Relay the upstream response: status and the meaningful headers
     * verbatim, body re-framed as chunked and flushed per chunk so an
     * SSE stream reaches the client as it arrives.
     */
    private fun relay(response: Upstream.Response, output: OutputStream): Int {
        val head = StringBuilder()
        head.append("HTTP/1.1 ").append(response.status).append(' ')
            .append(reasonPhrase(response.status)).append("\r\n")
        response.contentType?.let { head.append("Content-Type: ").append(it).append("\r\n") }
        for (name in RELAYED_RESPONSE_HEADERS) {
            response.headers[name]?.let { head.append(name).append(": ").append(it).append("\r\n") }
        }
        head.append("Transfer-Encoding: chunked\r\n")
        head.append("Connection: close\r\n\r\n")
        output.write(head.toString().toByteArray(Charsets.ISO_8859_1))
        output.flush()
        val buffer = ByteArray(RELAY_CHUNK_BYTES)
        while (true) {
            val read = response.body.read(buffer)
            if (read < 0) break
            if (read == 0) continue
            output.write((Integer.toHexString(read) + "\r\n").toByteArray(Charsets.ISO_8859_1))
            output.write(buffer, 0, read)
            output.write("\r\n".toByteArray(Charsets.ISO_8859_1))
            output.flush()
        }
        output.write("0\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
        output.flush()
        return response.status
    }

    // ── HTTP plumbing ──────────────────────────────────────────────────

    private fun sendJson(output: OutputStream, status: Int, json: JSONObject) {
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        val head = "HTTP/1.1 $status ${reasonPhrase(status)}\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: ${bytes.size}\r\n" +
            "Connection: close\r\n\r\n"
        output.write(head.toByteArray(Charsets.ISO_8859_1))
        output.write(bytes)
        output.flush()
    }

    private fun sendError(output: OutputStream, status: Int, type: String, message: String) {
        sendJson(output, status, ZCodeBroadcast.errorBody(type, message))
    }

    /** One CRLF-terminated line as ASCII; null on immediate EOF. */
    private fun readAsciiLine(input: InputStream, cap: Int): String? {
        val buffer = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b < 0) return if (buffer.size() == 0) null else buffer.toString(Charsets.ISO_8859_1.name())
            if (b == '\n'.code) break
            buffer.write(b)
            if (buffer.size() > cap) throw IOException("line too long")
        }
        val line = buffer.toByteArray()
        val end = if (line.isNotEmpty() && line[line.size - 1] == '\r'.code.toByte()) line.size - 1 else line.size
        return String(line, 0, end, Charsets.ISO_8859_1)
    }

    /** Headers into a lowercase-keyed map; null when malformed/oversized. */
    private fun readHeaders(input: InputStream): Map<String, String>? {
        val headers = LinkedHashMap<String, String>()
        var total = 0
        while (true) {
            val line = readAsciiLine(input, MAX_LINE_BYTES) ?: return null
            if (line.isEmpty()) return headers
            total += line.length
            if (total > MAX_HEADER_BYTES || headers.size > MAX_HEADER_COUNT) return null
            val colon = line.indexOf(':')
            if (colon <= 0) return null
            headers[line.substring(0, colon).trim().lowercase()] =
                line.substring(colon + 1).trim()
        }
    }

    /** Read exactly [length] body bytes; null when the stream ends early. */
    private fun readBody(input: InputStream, length: Int): ByteArray? {
        val out = ByteArrayOutputStream(length.coerceAtMost(RELAY_CHUNK_BYTES))
        val buffer = ByteArray(RELAY_CHUNK_BYTES)
        var remaining = length
        while (remaining > 0) {
            val read = input.read(buffer, 0, minOf(buffer.size, remaining))
            if (read < 0) return null
            out.write(buffer, 0, read)
            remaining -= read
        }
        return out.toByteArray()
    }

    private fun reasonPhrase(status: Int): String = when (status) {
        200 -> "OK"
        201 -> "Created"
        204 -> "No Content"
        400 -> "Bad Request"
        401 -> "Unauthorized"
        402 -> "Payment Required"
        403 -> "Forbidden"
        404 -> "Not Found"
        405 -> "Method Not Allowed"
        413 -> "Payload Too Large"
        429 -> "Too Many Requests"
        500 -> "Internal Server Error"
        502 -> "Bad Gateway"
        503 -> "Service Unavailable"
        504 -> "Gateway Timeout"
        529 -> "Overloaded"
        else -> ""
    }

    companion object {
        /** Read timeout for the request phase of a connection. The
         *  relay phase is bounded by the upstream read timeout. */
        private const val REQUEST_READ_TIMEOUT_MS = 120_000
        private const val MAX_LINE_BYTES = 8 * 1024
        private const val MAX_HEADER_BYTES = 64 * 1024
        private const val MAX_HEADER_COUNT = 100
        private const val RELAY_CHUNK_BYTES = 16 * 1024

        /** Response headers relayed from upstream (lowercase keys),
         *  the proxy script's whitelist. */
        private val RELAYED_RESPONSE_HEADERS =
            listOf("cache-control", "retry-after", "x-aliyun-captcha-verify-param")
    }
}
