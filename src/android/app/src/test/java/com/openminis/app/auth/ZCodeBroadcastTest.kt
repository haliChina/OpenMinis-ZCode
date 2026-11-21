package com.openminis.app.auth

import com.openminis.app.data.model.ThinkingLevel
import com.openminis.app.provider.zcode.ZCodeBroadcast
import com.openminis.app.provider.zcode.ZCodeBroadcastServer
import com.openminis.app.provider.zcode.ZCodeProvider
import com.openminis.app.provider.zcode.ZCodeSystemPrompt
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Semaphore
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * [T-zcode-broadcast] JVM coverage for the in-app broadcast: the pure
 * wire logic ([ZCodeBroadcast]) plus a smoke test of the server's
 * request/response handling ([ZCodeBroadcastServer.handleStreams])
 * with a fake upstream — routing, key gate, the not-logged-in path,
 * the request transform as the upstream receives it, and
 * chunk-by-chunk streaming relay.
 *
 * The smoke test drives streams, not sockets: this sandbox
 * intercepts loopback TCP (verified with a minimal same-JVM
 * ServerSocket/Socket repro — the client times out and accept()
 * never returns), so a live-socket test cannot run here. The stream
 * path is every line of the server except the accept loop itself.
 */
class ZCodeBroadcastTest {

    // ── Access key ─────────────────────────────────────────────────────

    @Test
    fun `generated access keys are long url-safe and unique`() {
        val a = ZCodeBroadcast.generateAccessKey()
        val b = ZCodeBroadcast.generateAccessKey()
        assertTrue(a.length >= 32)
        assertTrue(a.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        assertNotEquals(a, b)
    }

    @Test
    fun `presented key prefers bearer then x-api-key`() {
        assertEquals("k1", ZCodeBroadcast.presentedAccessKey("Bearer k1", "k2"))
        assertEquals("k2", ZCodeBroadcast.presentedAccessKey(null, "k2"))
        assertEquals("k2", ZCodeBroadcast.presentedAccessKey("Basic zz", "k2"))
        assertEquals(null, ZCodeBroadcast.presentedAccessKey("Bearer ", null))
        assertEquals(null, ZCodeBroadcast.presentedAccessKey(null, "  "))
    }

    @Test
    fun `key validation accepts only the exact key`() {
        assertTrue(ZCodeBroadcast.isAccessKeyValid("s3cret-key", "s3cret-key"))
        assertFalse(ZCodeBroadcast.isAccessKeyValid("s3cret-keX", "s3cret-key"))
        assertFalse(ZCodeBroadcast.isAccessKeyValid("s3cret", "s3cret-key"))
        assertFalse(ZCodeBroadcast.isAccessKeyValid(null, "s3cret-key"))
        assertFalse(ZCodeBroadcast.isAccessKeyValid("", "s3cret-key"))
        assertFalse(ZCodeBroadcast.isAccessKeyValid("s3cret-key", null))
        assertFalse(ZCodeBroadcast.isAccessKeyValid("s3cret-key", ""))
    }

    // ── Request transform ──────────────────────────────────────────────

    @Test
    fun `transform lowercases the model and injects the official system blocks`() {
        val body = JSONObject()
            .put("model", "GLM-5.3-Flash")
            .put("system", "Be terse.")
            .put("messages", JSONArray())
        val out = ZCodeBroadcast.transformMessagesBody(body, userId = null)
        assertEquals("glm-5.3-flash", out.getString("model"))
        // Byte-identical to what the chat path builds for the same input.
        val expected = ZCodeSystemPrompt.build("Be terse.", "GLM-5.3-Flash", null)
        assertEquals(expected.toString(), out.getJSONArray("system").toString())
        val blocks = out.getJSONArray("system")
        assertEquals(3, blocks.length())
        assertEquals(ZCodeSystemPrompt.CLI_PREFIX, blocks.getJSONObject(0).getString("text"))
        assertFalse(blocks.getJSONObject(0).has("cache_control"))
        assertTrue(blocks.getJSONObject(1).getString("text").endsWith("Be terse."))
    }

    @Test
    fun `transform flattens a client system block list`() {
        val system = JSONArray()
            .put(JSONObject().put("type", "text").put("text", "First."))
            .put(JSONObject().put("type", "image").put("source", JSONObject()))
            .put(JSONObject().put("type", "text").put("text", "Second."))
        val body = JSONObject().put("model", "GLM-5.2").put("system", system)
        val out = ZCodeBroadcast.transformMessagesBody(body, userId = null)
        val expected = ZCodeSystemPrompt.build("First.\n\nSecond.", "GLM-5.2", null)
        assertEquals(expected.toString(), out.getJSONArray("system").toString())
    }

    @Test
    fun `transform fills metadata user_id and keeps other metadata`() {
        val body = JSONObject()
            .put("model", "GLM-5.2")
            .put("metadata", JSONObject().put("trace", "abc"))
        val out = ZCodeBroadcast.transformMessagesBody(body, userId = "user-42")
        val metadata = out.getJSONObject("metadata")
        assertEquals("user-42", metadata.getString("user_id"))
        assertEquals("abc", metadata.getString("trace"))
        // No user id known: metadata is left exactly as the client sent it.
        val body2 = JSONObject()
            .put("model", "GLM-5.2")
            .put("metadata", JSONObject().put("trace", "abc"))
        val out2 = ZCodeBroadcast.transformMessagesBody(body2, userId = null)
        assertFalse(out2.getJSONObject("metadata").has("user_id"))
    }

    @Test
    fun `transform applies the official thinking default when the client sent none`() {
        val flash = ZCodeBroadcast.transformMessagesBody(
            JSONObject().put("model", "GLM-5.3-Flash"), userId = null,
        )
        assertEquals("enabled", flash.getJSONObject("thinking").getString("type"))
        assertEquals("max", flash.getJSONObject("output_config").getString("effort"))

        val turbo = ZCodeBroadcast.transformMessagesBody(
            JSONObject().put("model", "GLM-5-Turbo"), userId = null,
        )
        assertEquals("enabled", turbo.getJSONObject("thinking").getString("type"))
        assertFalse(turbo.has("output_config"))
    }

    @Test
    fun `transform maps a client effort and strips budget_tokens`() {
        val body = JSONObject()
            .put("model", "GLM-5.3-Flash")
            .put("thinking", JSONObject().put("type", "enabled").put("budget_tokens", 4096))
            .put("output_config", JSONObject().put("effort", "low"))
        val out = ZCodeBroadcast.transformMessagesBody(body, userId = null)
        assertEquals("low", out.getJSONObject("output_config").getString("effort"))
        assertFalse(out.getJSONObject("thinking").has("budget_tokens"))
        // The level derivation itself.
        assertEquals(ThinkingLevel.LOW, ZCodeBroadcast.thinkingLevelForRequest(body))
        assertEquals(
            ThinkingLevel.OFF,
            ZCodeBroadcast.thinkingLevelForRequest(JSONObject().put("model", "GLM-5.2")),
        )
    }

    @Test
    fun `models payload uses wire ids and canonical display names`() {
        val payload = ZCodeBroadcast.modelsPayload(
            listOf("GLM-5.3-Flash", "GLM-5.2", "GLM-5-Turbo"),
        )
        val data = payload.getJSONArray("data")
        assertEquals(3, data.length())
        assertEquals("glm-5.3-flash", data.getJSONObject(0).getString("id"))
        assertEquals("GLM-5.3-Flash", data.getJSONObject(0).getString("display_name"))
        assertEquals("glm-5.3-flash", payload.getString("first_id"))
        assertEquals("glm-5-turbo", payload.getString("last_id"))
        assertFalse(payload.getBoolean("has_more"))
    }

    // ── Shared semaphore ───────────────────────────────────────────────

    @Test
    fun `broadcast shares the provider per-instance semaphore`() {
        val a1 = ZCodeProvider.sharedSemaphoreFor("instance-a")
        val a2 = ZCodeProvider.sharedSemaphoreFor("instance-a")
        val b = ZCodeProvider.sharedSemaphoreFor("instance-b")
        assertTrue(a1 === a2)
        assertTrue(a1 !== b)
        assertEquals(2, a1.availablePermits)
    }

    // ── Server handling over in-memory streams ─────────────────────────

    private class FakeUpstream(
        private val responder: (ByteArray) -> ZCodeBroadcastServer.Upstream.Response,
    ) : ZCodeBroadcastServer.Upstream {
        @Volatile var lastBody: ByteArray? = null
        @Volatile var lastHeaders: Map<String, String>? = null
        override fun post(
            url: String,
            body: ByteArray,
            headers: Map<String, String>,
        ): ZCodeBroadcastServer.Upstream.Response {
            lastBody = body
            lastHeaders = headers
            return responder(body)
        }
    }

    private fun jsonResponse(status: Int, text: String): ZCodeBroadcastServer.Upstream.Response =
        ZCodeBroadcastServer.Upstream.Response(
            status = status,
            contentType = "application/json",
            headers = emptyMap(),
            body = ByteArrayInputStream(text.toByteArray(Charsets.UTF_8)),
        )

    private fun newServer(
        upstream: ZCodeBroadcastServer.Upstream,
        session: ZCodeBroadcastServer.Session?,
        maxBodyBytes: Int = ZCodeBroadcast.MAX_BODY_BYTES,
        logs: MutableList<String>? = null,
    ): ZCodeBroadcastServer = ZCodeBroadcastServer(
        accessKeyProvider = { TEST_KEY },
        sessionProvider = { session },
        modelsProvider = { listOf("GLM-5.3-Flash", "GLM-5.2", "GLM-5-Turbo") },
        upstream = upstream,
        semaphore = Semaphore(2),
        maxBodyBytes = maxBodyBytes,
        log = { line -> logs?.add(line) },
    )

    private fun rawRequest(
        method: String,
        path: String,
        key: String?,
        body: String?,
    ): ByteArray {
        val head = StringBuilder()
        head.append("$method $path HTTP/1.1\r\n")
        head.append("Host: 127.0.0.1\r\n")
        if (key != null) head.append("x-api-key: $key\r\n")
        val bodyBytes = body?.toByteArray(Charsets.UTF_8)
        if (bodyBytes != null) {
            head.append("Content-Type: application/json\r\n")
            head.append("Content-Length: ${bodyBytes.size}\r\n")
        }
        head.append("\r\n")
        val headBytes = head.toString().toByteArray(Charsets.ISO_8859_1)
        return if (bodyBytes != null) headBytes + bodyBytes else headBytes
    }

    private class RawResponse(
        val status: Int,
        val headers: Map<String, String>,
        val body: ByteArray,
    ) {
        fun bodyText(): String = body.toString(Charsets.UTF_8)
    }

    /** Parse one response: status line + headers + chunked/Content-Length body. */
    private fun parseResponse(bytes: ByteArray): RawResponse {
        // ISO-8859-1 is byte-preserving, so string offsets are byte offsets.
        val text = bytes.toString(Charsets.ISO_8859_1)
        val headEnd = text.indexOf("\r\n\r\n")
        assertTrue("response has a complete head", headEnd >= 0)
        val lines = text.substring(0, headEnd).split("\r\n")
        val status = lines[0].split(" ")[1].toInt()
        val headers = lines.drop(1).mapNotNull { line ->
            val i = line.indexOf(':')
            if (i <= 0) null
            else line.substring(0, i).trim().lowercase() to line.substring(i + 1).trim()
        }.toMap()
        val rest = bytes.copyOfRange(headEnd + 4, bytes.size)
        val body = if (headers["transfer-encoding"] == "chunked") {
            val out = ByteArrayOutputStream()
            var pos = 0
            while (true) {
                var eol = pos
                while (!(rest[eol] == '\r'.code.toByte() && rest[eol + 1] == '\n'.code.toByte())) eol++
                val size = String(rest, pos, eol - pos, Charsets.ISO_8859_1).trim().toInt(16)
                if (size == 0) break
                out.write(rest, eol + 2, size)
                pos = eol + 2 + size + 2
            }
            out.toByteArray()
        } else {
            rest
        }
        return RawResponse(status, headers, body)
    }

    /** Run one full request/response exchange through the real handler. */
    private fun exchange(server: ZCodeBroadcastServer, requestBytes: ByteArray): RawResponse {
        val output = ByteArrayOutputStream()
        runBlocking { server.handleStreams(ByteArrayInputStream(requestBytes), output) }
        return parseResponse(output.toByteArray())
    }

    @Test
    fun `health is open and everything else needs the key`() {
        val server = newServer(FakeUpstream { jsonResponse(200, "{}") }, session = null)
        val health = exchange(server, rawRequest("GET", "/health", key = null, body = null))
        assertEquals(200, health.status)
        assertTrue(JSONObject(health.bodyText()).getBoolean("ok"))

        val noKey = exchange(
            server, rawRequest("POST", "/v1/messages", key = null, body = "{}"),
        )
        assertEquals(401, noKey.status)
        val wrongKey = exchange(
            server, rawRequest("POST", "/v1/messages", key = "nope", body = "{}"),
        )
        assertEquals(401, wrongKey.status)
        val unknown = exchange(server, rawRequest("GET", "/nope", key = TEST_KEY, body = null))
        assertEquals(404, unknown.status)
    }

    @Test
    fun `messages without a signed-in instance answer the app not-logged-in error`() {
        val server = newServer(FakeUpstream { jsonResponse(200, "{}") }, session = null)
        val response = exchange(
            server,
            rawRequest(
                "POST", "/v1/messages", key = TEST_KEY,
                body = """{"model":"GLM-5.2","messages":[]}""",
            ),
        )
        assertEquals(401, response.status)
        val error = JSONObject(response.bodyText()).getJSONObject("error")
        assertEquals("authentication_error", error.getString("type"))
        assertEquals(ZCodeBroadcast.NOT_LOGGED_IN_MESSAGE, error.getString("message"))
    }

    @Test
    fun `messages are transformed and the upstream response relayed`() {
        val upstream = FakeUpstream {
            jsonResponse(200, """{"id":"msg_1","type":"message"}""")
        }
        val logs = mutableListOf<String>()
        val session = ZCodeBroadcastServer.Session(
            jwt = TEST_JWT,
            userId = "user-42",
            baseHeaders = mapOf("X-Device-Mid" to "mid-1"),
        )
        val server = newServer(upstream, session, logs = logs)
        val response = exchange(
            server,
            rawRequest(
                "POST", "/v1/messages", key = TEST_KEY,
                body = """{"model":"GLM-5.3-Flash","system":"Be terse.","messages":[]}""",
            ),
        )
        assertEquals(200, response.status)
        assertEquals("msg_1", JSONObject(response.bodyText()).getString("id"))

        // What the upstream received: transformed body + full headers.
        val sent = JSONObject(upstream.lastBody!!.toString(Charsets.UTF_8))
        assertEquals("glm-5.3-flash", sent.getString("model"))
        assertEquals(3, sent.getJSONArray("system").length())
        assertEquals("user-42", sent.getJSONObject("metadata").getString("user_id"))
        assertEquals("max", sent.getJSONObject("output_config").getString("effort"))
        val headers = upstream.lastHeaders!!
        assertEquals("Bearer $TEST_JWT", headers["Authorization"])
        assertEquals(TEST_JWT, headers["x-api-key"])
        assertEquals("mid-1", headers["X-Device-Mid"])
        assertTrue(headers.containsKey("x-request-id"))

        // Logs never carry the key or the JWT.
        assertTrue(logs.isNotEmpty())
        assertFalse(logs.joinToString("\n").contains(TEST_KEY))
        assertFalse(logs.joinToString("\n").contains(TEST_JWT))
    }

    @Test
    fun `models endpoint answers with the key`() {
        val server = newServer(FakeUpstream { jsonResponse(200, "{}") }, session = null)
        val response = exchange(server, rawRequest("GET", "/v1/models", key = TEST_KEY, body = null))
        assertEquals(200, response.status)
        assertEquals("glm-5.3-flash", JSONObject(response.bodyText()).getString("first_id"))
    }

    @Test
    fun `oversized bodies are rejected with 413`() {
        val server = newServer(
            FakeUpstream { jsonResponse(200, "{}") },
            session = ZCodeBroadcastServer.Session(TEST_JWT, null, emptyMap()),
            maxBodyBytes = 16,
        )
        val response = exchange(
            server,
            rawRequest(
                "POST", "/v1/messages", key = TEST_KEY,
                body = """{"model":"GLM-5.2","messages":[],"padding":"0123456789abcdef"}""",
            ),
        )
        assertEquals(413, response.status)
    }

    @Test
    fun `streamed responses are relayed chunk by chunk`() {
        // The upstream body yields its first chunk, then blocks until
        // the test has SEEN that chunk arrive at the client — proving
        // the relay flushes per chunk instead of buffering the stream.
        val secondChunkGate = CountDownLatch(1)
        val streamingBody = object : InputStream() {
            private var stage = 0

            override fun read(): Int {
                val bytes = readChunk()
                return if (bytes.isEmpty()) -1 else bytes[0].toInt() and 0xFF
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                val bytes = readChunk()
                if (bytes.isEmpty()) return -1
                val n = minOf(len, bytes.size)
                System.arraycopy(bytes, 0, b, off, n)
                return n
            }

            private fun readChunk(): ByteArray = when (stage) {
                0 -> {
                    stage = 1
                    "data: one\n\n".toByteArray(Charsets.UTF_8)
                }
                1 -> {
                    stage = 2
                    if (!secondChunkGate.await(10, TimeUnit.SECONDS)) {
                        fail("client never saw the first chunk")
                    }
                    "data: two\n\n".toByteArray(Charsets.UTF_8)
                }
                else -> ByteArray(0)
            }
        }
        val upstream = FakeUpstream {
            ZCodeBroadcastServer.Upstream.Response(
                status = 200,
                contentType = "text/event-stream",
                headers = mapOf("cache-control" to "no-cache"),
                body = streamingBody,
            )
        }
        val session = ZCodeBroadcastServer.Session(TEST_JWT, null, emptyMap())
        val server = newServer(upstream, session)

        val requestIn = PipedInputStream()
        val requestOut = PipedOutputStream(requestIn)
        val responseOut = PipedOutputStream()
        val responseIn = PipedInputStream(responseOut)
        val handler = Thread {
            runBlocking { server.handleStreams(requestIn, responseOut) }
        }
        handler.isDaemon = true
        handler.start()
        try {
            requestOut.write(
                rawRequest(
                    "POST", "/v1/messages", key = TEST_KEY,
                    body = """{"model":"GLM-5.2","stream":true,"messages":[]}""",
                ),
            )
            requestOut.flush()
            val received = ByteArrayOutputStream()
            var sawFirstChunk = false
            val deadline = System.currentTimeMillis() + 10_000
            while (System.currentTimeMillis() < deadline) {
                if (responseIn.available() > 0) {
                    val b = responseIn.read()
                    if (b < 0) break
                    received.write(b)
                    val soFar = received.toString(Charsets.UTF_8)
                    if (!sawFirstChunk && soFar.contains("data: one")) {
                        sawFirstChunk = true
                        secondChunkGate.countDown()
                    }
                    if (soFar.contains("data: two")) break
                } else {
                    Thread.sleep(5)
                }
            }
            assertTrue("first chunk never arrived", sawFirstChunk)
            assertTrue(received.toString(Charsets.UTF_8).contains("data: two"))
        } finally {
            handler.join(5_000)
        }
        assertFalse("handler thread leaked", handler.isAlive)
    }

    @Test
    fun `upstream failure maps to 502`() {
        val upstream = FakeUpstream { throw java.io.IOException("connection refused") }
        val session = ZCodeBroadcastServer.Session(TEST_JWT, null, emptyMap())
        val server = newServer(upstream, session)
        val response = exchange(
            server,
            rawRequest(
                "POST", "/v1/messages", key = TEST_KEY,
                body = """{"model":"GLM-5.2","messages":[]}""",
            ),
        )
        assertEquals(502, response.status)
        assertEquals(
            "api_error",
            JSONObject(response.bodyText()).getJSONObject("error").getString("type"),
        )
    }

    private companion object {
        const val TEST_KEY = "test-access-key-0123456789"
        const val TEST_JWT = "test.jwt.token"
    }
}
