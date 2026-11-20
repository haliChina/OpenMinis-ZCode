#!/usr/bin/env python3
"""Self-test for zcode_proxy.py (standard library only).

Spins up a fake upstream server and the proxy itself (with a test
config) on ephemeral localhost ports, then checks:

  1. /health answers without a key
  2. /v1/messages without / with a wrong key -> 401
  3. with the key, the fake upstream receives the full identity header
     set, the official system blocks (block 1 verbatim, no
     cache_control on it), a lowercased model id and metadata.user_id
     from the JWT
  4. x-api-key header authentication also works
  5. /v1/models lists the three Start Plan models
  6. streaming responses arrive chunk by chunk, not buffered whole
  7. a third concurrent request is queued (upstream never sees >2)
  8. an upstream 3007 is passed through untouched and noted in the log

Run: python3 test_zcode_proxy.py -- exits 0 only if every check passes.
"""

import base64
import http.client
import io
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zcode_proxy

ACCESS_KEY = "test-access-key"
DEVICE_MID = "test-device-mid-0001"
USER_ID = "u-test-123"


def make_jwt(payload):
    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return b64({"alg": "HS256", "typ": "JWT"}) + "." + b64(payload) + ".fakesig"


JWT = make_jwt({"user_id": USER_ID, "exp": 4102444800})


# ---------------------------------------------------------------------------
# Fake upstream
# ---------------------------------------------------------------------------


class FakeUpstreamState:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []  # {path, headers (lowercased dict), body (parsed json)}
        self.current = 0
        self.max_concurrent = 0

    def reset_concurrency(self):
        with self.lock:
            self.current = 0
            self.max_concurrent = 0


STATE = FakeUpstreamState()


class FakeUpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        with STATE.lock:
            STATE.current += 1
            STATE.max_concurrent = max(STATE.max_concurrent, STATE.current)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw.decode("utf-8"))
            except ValueError:
                body = {}
            headers = {k.lower(): v for k, v in self.headers.items()}
            with STATE.lock:
                STATE.requests.append(
                    {"path": self.path, "headers": headers, "body": body}
                )
            marker = (body.get("metadata") or {}).get("test_marker")
            if marker == "slow":
                time.sleep(1.2)
                self._send_json(200, {"type": "message", "content": [{"type": "text", "text": "slow-ok"}]})
                return
            if marker == "captcha":
                self._send_json(403, {"code": 3007, "msg": "captcha required"})
                return
            if body.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for n in (1, 2, 3):
                    event = ('data: {"n":%d}\n\n' % n).encode("utf-8")
                    self.wfile.write(b"%x\r\n" % len(event))
                    self.wfile.write(event)
                    self.wfile.write(b"\r\n")
                    self.wfile.flush()
                    if n < 3:
                        time.sleep(0.5)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
                return
            self._send_json(
                200,
                {
                    "id": "msg_test",
                    "type": "message",
                    "role": "assistant",
                    "model": body.get("model"),
                    "content": [{"type": "text", "text": "ok"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            )
        finally:
            with STATE.lock:
                STATE.current -= 1


# ---------------------------------------------------------------------------
# Test plumbing
# ---------------------------------------------------------------------------


FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print("PASS: %s" % name)
    else:
        print("FAIL: %s%s" % (name, (" -- " + detail) if detail else ""))
        FAILURES.append(name)


def request(port, method, path, body=None, headers=None, timeout=15):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    raw = None
    hdrs = dict(headers or {})
    if body is not None:
        raw = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=raw, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    status = resp.status
    conn.close()
    return status, data


def last_upstream_request():
    with STATE.lock:
        return STATE.requests[-1]


def main():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstreamHandler)
    upstream_port = upstream.server_address[1]
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    messages_url = "http://127.0.0.1:%d/api/v1/zcode-plan/anthropic/v1/messages" % upstream_port

    config = {
        "jwt": JWT,
        "device_mid": DEVICE_MID,
        "user_id": USER_ID,
        "access_key": ACCESS_KEY,
    }
    proxy = zcode_proxy.ProxyServer(("127.0.0.1", 0), config, messages_url=messages_url)
    proxy_port = proxy.server_address[1]
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    bearer = {"Authorization": "Bearer " + ACCESS_KEY}
    msg_body = {
        "model": "GLM-5.3-Flash",
        "max_tokens": 16,
        "system": "You are a test client.",
        "messages": [{"role": "user", "content": "hi"}],
    }

    # 1. /health without a key.
    status, data = request(proxy_port, "GET", "/health")
    check("health without key -> 200 {\"ok\": true}",
          status == 200 and json.loads(data) == {"ok": True}, "status=%d body=%r" % (status, data))

    # 2. No key / wrong key -> 401.
    status, _ = request(proxy_port, "POST", "/v1/messages", body=msg_body)
    check("messages without key -> 401", status == 401, "status=%d" % status)
    status, _ = request(proxy_port, "POST", "/v1/messages", body=msg_body,
                        headers={"Authorization": "Bearer wrong-key"})
    check("messages with wrong key -> 401", status == 401, "status=%d" % status)

    # 3. Happy path + everything the upstream must see.
    status, data = request(proxy_port, "POST", "/v1/messages", body=msg_body, headers=bearer)
    check("messages with key -> 200", status == 200, "status=%d body=%r" % (status, data[:200]))
    check("upstream response passed through",
          json.loads(data).get("content", [{}])[0].get("text") == "ok")
    seen = last_upstream_request()
    h = seen["headers"]
    check("upstream path is the plan messages endpoint",
          seen["path"] == "/api/v1/zcode-plan/anthropic/v1/messages", seen["path"])
    check("Authorization is Bearer <jwt>", h.get("authorization") == "Bearer " + JWT)
    check("x-api-key is the jwt", h.get("x-api-key") == JWT)
    check("X-Device-Mid from config", h.get("x-device-mid") == DEVICE_MID)
    check("User-Agent ZCode/3.17.2", h.get("user-agent") == "ZCode/3.17.2", h.get("user-agent", ""))
    check("X-ZCode-App-Version 3.17.2", h.get("x-zcode-app-version") == "3.17.2")
    check("X-ZCode-Agent glm", h.get("x-zcode-agent") == "glm")
    check("HTTP-Referer", h.get("http-referer") == "https://zcode.z.ai")
    check("X-Title", h.get("x-title") == "Z Code@electron")
    check("X-Release-Channel production", h.get("x-release-channel") == "production")
    check("anthropic-version", h.get("anthropic-version") == "2023-06-01")
    check("X-Platform present", bool(h.get("x-platform")), h.get("x-platform", ""))
    check("X-Os-Category present", bool(h.get("x-os-category")))
    check("X-Client-Timezone present", bool(h.get("x-client-timezone")))
    check("trace headers present",
          all(h.get(k) for k in ("x-request-id", "x-zcode-trace-id", "x-query-id", "x-session-id"))
          and h.get("x-zcode-session-type") == "main"
          and h.get("x-zcode-query-source") == "main_turn")
    ubody = seen["body"]
    check("model lowercased on the wire", ubody.get("model") == "glm-5.3-flash", ubody.get("model", ""))
    system = ubody.get("system")
    check("system has exactly 3 blocks", isinstance(system, list) and len(system) == 3)
    if isinstance(system, list) and len(system) == 3:
        check("block 1 is the verbatim CLI prefix",
              system[0].get("text") == "You are ZCode, an interactive agent")
        check("block 1 has no cache_control", "cache_control" not in system[0])
        check("block 2 cache_control ephemeral",
              system[1].get("cache_control") == {"type": "ephemeral"})
        check("block 3 cache_control ephemeral",
              system[2].get("cache_control") == {"type": "ephemeral"})
        check("block 2 starts with the identity section",
              system[1].get("text", "").startswith("\nYou are an agent working with the user"))
        check("client system preserved at end of block 2",
              system[1].get("text", "").endswith("You are a test client."))
        expected = zcode_proxy.build_system_blocks("You are a test client.")
        check("system blocks equal build_system_blocks output", system == expected)
    check("metadata.user_id from JWT",
          (ubody.get("metadata") or {}).get("user_id") == USER_ID,
          json.dumps(ubody.get("metadata")))

    # 4. x-api-key header authentication.
    status, _ = request(proxy_port, "POST", "/v1/messages", body=msg_body,
                        headers={"x-api-key": ACCESS_KEY})
    check("messages with x-api-key header -> 200", status == 200, "status=%d" % status)

    # 5. /v1/models.
    status, data = request(proxy_port, "GET", "/v1/models", headers=bearer)
    ids = [m["id"] for m in json.loads(data).get("data", [])] if status == 200 else []
    check("models lists the Start Plan three",
          status == 200 and ids == ["glm-5.3-flash", "glm-5.2", "glm-5-turbo"],
          "status=%d ids=%r" % (status, ids))
    status, _ = request(proxy_port, "GET", "/v1/models")
    check("models without key -> 401", status == 401, "status=%d" % status)

    # 6. Streaming arrives chunk by chunk.
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=15)
    stream_body = dict(msg_body)
    stream_body["stream"] = True
    conn.request("POST", "/v1/messages", body=json.dumps(stream_body).encode("utf-8"),
                 headers=dict(bearer, **{"Content-Type": "application/json"}))
    resp = conn.getresponse()
    t0 = time.monotonic()
    first_at = None
    chunks = []
    while True:
        line = resp.readline()
        if not line:
            break
        if first_at is None:
            first_at = time.monotonic() - t0
        chunks.append(line)
    total = time.monotonic() - t0
    conn.close()
    payload = b"".join(chunks)
    check("stream status 200", resp.status == 200, "status=%d" % resp.status)
    check("stream delivered all 3 events",
          b'"n":1' in payload and b'"n":2' in payload and b'"n":3' in payload)
    check("stream is incremental (first chunk well before the end)",
          first_at is not None and first_at < 0.45 and total >= 0.9,
          "first_at=%s total=%.2f" % (first_at, total))

    # 7. Concurrency: the third request queues behind the semaphore.
    STATE.reset_concurrency()
    results = {}

    def slow_call(i):
        body = dict(msg_body)
        body["metadata"] = {"test_marker": "slow"}
        results[i] = request(proxy_port, "POST", "/v1/messages", body=body,
                             headers=bearer, timeout=30)[0]

    threads = [threading.Thread(target=slow_call, args=(i,)) for i in range(3)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0
    check("all 3 slow requests succeed", all(v == 200 for v in results.values()), repr(results))
    check("upstream never saw more than 2 concurrent",
          STATE.max_concurrent == 2, "max_concurrent=%d" % STATE.max_concurrent)
    check("third request was queued (elapsed >= 2s)", elapsed >= 2.0, "elapsed=%.2f" % elapsed)

    # 8. Upstream 3007 passes through and is noted in the proxy log.
    captured = io.StringIO()
    old_stderr = sys.stderr
    sys.stderr = captured
    try:
        body = dict(msg_body)
        body["metadata"] = {"test_marker": "captcha"}
        status, data = request(proxy_port, "POST", "/v1/messages", body=body, headers=bearer)
    finally:
        sys.stderr = old_stderr
    check("upstream 3007 status passed through", status == 403, "status=%d" % status)
    check("upstream 3007 body passed through", b"3007" in data)
    check("3007 noted in proxy log", "3007" in captured.getvalue(), captured.getvalue()[-300:])

    # 9. Unknown path.
    status, _ = request(proxy_port, "GET", "/nope", headers=bearer)
    check("unknown path -> 404", status == 404, "status=%d" % status)

    proxy.shutdown()
    upstream.shutdown()
    print()
    if FAILURES:
        print("FAILED: %d check(s): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
