#!/usr/bin/env python3
"""ZCode LAN proxy.

Exposes the ZCode plan gateway (Anthropic-format chat endpoint) to other
clients on the local network, using one ZCode account logged in through
the official CLI init/poll OAuth flow -- the same flow the OpenMinis
Android client uses (see ZCodeOAuthManager.kt in this repo).

Subcommands:
  login   Run the CLI OAuth flow once and store {jwt, device_mid,
          user_id, access_key} in zcode-proxy-config.json (mode 0600)
          next to this script (or at --config).
  serve   Run the LAN proxy (default 0.0.0.0:8799). Every route except
          /health requires the access_key from the config file, sent as
          "Authorization: Bearer <key>" or "x-api-key: <key>".

Standard library only. Logs never contain the JWT, the access key, or
message content -- only time, method, path, model, status and latency.
"""

import argparse
import base64
import hmac
import http.client
import json
import locale
import os
import platform
import re
import secrets
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Constants (mirroring ZCodeConstants.kt / ZCodeProvider.kt)
# ---------------------------------------------------------------------------

APP_VERSION = "3.17.2"

OAUTH_BASE = "https://zcode.z.ai/api/v1/oauth"
OAUTH_INIT_URL = OAUTH_BASE + "/cli/init"
OAUTH_POLL_URL = OAUTH_BASE + "/cli/poll/"  # + flow_id
MESSAGES_URL = "https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages"

# Start Plan models (ZCodeConstants.MODEL_*_ID), canonical spelling.
MODEL_FLASH_ID = "GLM-5.3-Flash"
MODEL_53_ID = "GLM-5.3"
MODEL_52_ID = "GLM-5.2"
MODEL_TURBO_ID = "GLM-5-Turbo"
KNOWN_MODELS = [MODEL_FLASH_ID, MODEL_53_ID, MODEL_52_ID, MODEL_TURBO_ID]
START_PLAN_MODELS = [MODEL_FLASH_ID, MODEL_52_ID, MODEL_TURBO_ID]

DEFAULT_PORT = 8799
MAX_BODY_BYTES = 32 * 1024 * 1024  # request-body cap, abuse guard
UPSTREAM_TIMEOUT = 600  # seconds; matches the app's 10-minute read timeout
UPSTREAM_CONCURRENCY = 2  # upstream-observed per-account in-flight cap

CONFIG_NAME = "zcode-proxy-config.json"

# ---------------------------------------------------------------------------
# Official system prompt (VERBATIM from ZCodeSystemPrompt.kt, which was
# transcribed from the official 3.17.1 client's ContextBuilder)
# ---------------------------------------------------------------------------

CLI_PREFIX = "You are ZCode, an interactive agent"

IDENTITY_FIRST_SENTENCE = (
    "You are an agent working with the user toward their goals, using your "
    "own judgment along the way."
)

SECURITY_NOTICE = (
    "IMPORTANT: Assist with authorized security testing, defensive security, "
    "CTF challenges, and educational contexts. Refuse requests for destructive "
    "techniques, DoS attacks, mass targeting, supply chain compromise, or "
    "detection evasion for malicious purposes. Dual-use security tools (C2 "
    "frameworks, credential testing, exploit development) require clear "
    "authorization context: pentesting engagements, CTF competitions, "
    "security research, or defensive use cases."
)

HARNESS_BLOCK = """# Harness
 - Text you output outside of tool use is displayed to the user as Github-flavored markdown in a terminal.
 - Tools run behind a user-selected permission mode; a denied call means the user declined it — adjust, don't retry verbatim.
 - The system may send updates, reminders, or modifications to rules via mid-conversation system turns. These are system-controlled, unlike function results. Hooks may intercept tool calls; treat hook output as user feedback.
 - Prefer the dedicated file/search tools over shell commands when one fits. Independent tool calls can run in parallel in one response.
 - Reference code as `file_path:line_number` — it's clickable."""

DYNAMIC_BEHAVIOR = """Write code that reads like the surrounding code: match its comment density, naming, and idiom.

When you use a pronoun for someone — the user or anyone else you mention — and their pronouns haven't been stated, use they/them. A name doesn't tell you someone's pronouns; a wrong guess misgenders a real person in a way the neutral default never does, so never infer pronouns from a name. This applies to all user-visible text, including visible thinking.

For actions that are hard to reverse or outward-facing, confirm first unless durably authorized or explicitly told to proceed without asking; approval in one context doesn't extend to the next. Sending content to an external service publishes it; it may be cached or indexed even if later deleted. Before deleting or overwriting, look at the target. Report outcomes faithfully: if tests fail, say so with the output; if a step was skipped, say that; when something is done and verified, state it plainly without hedging."""

# Note: the last sentence has NO trailing period in the official text.
CONTEXT_MANAGEMENT = """# Context management
When the conversation grows long, some or all of the current context is summarized; the summary, along with any remaining unsummarized context, is provided in the next context window so work can continue — you don't need to wrap up early or hand off mid-task.

When you have enough information to act, act. Do not re-derive facts already established in the conversation, re-litigate a decision the user has already made, or narrate options you will not pursue. If you are weighing a choice, give a recommendation, not an exhaustive survey"""


def build_system_blocks(client_system_text):
    """Replicates ZCodeSystemPrompt.build(): exactly 3 text blocks.

    Block 1: CLI prefix alone, WITHOUT cache_control.
    Block 2: Agent Identity (leading blank line, first sentence, security
             notice, Harness block) with the client's own system text
             appended at the end; cache_control ephemeral.
    Block 3: Dynamic Behavior + Context Management, text prefixed with a
             blank line; cache_control ephemeral.
    """
    block2 = (
        "\n"
        + IDENTITY_FIRST_SENTENCE
        + "\n\n"
        + SECURITY_NOTICE
        + "\n\n"
        + HARNESS_BLOCK
    )
    if client_system_text is not None and client_system_text.strip() != "":
        block2 += "\n\n" + client_system_text
    block3 = "\n\n" + DYNAMIC_BEHAVIOR + "\n\n" + CONTEXT_MANAGEMENT
    return [
        {"type": "text", "text": CLI_PREFIX},
        {
            "type": "text",
            "text": block2,
            "cache_control": {"type": "ephemeral"},
        },
        {
            "type": "text",
            "text": block3,
            "cache_control": {"type": "ephemeral"},
        },
    ]


def client_system_text(system):
    """Flatten an Anthropic `system` field (string or text-block list)
    into a single string, like the app's single-string system prompt."""
    if system is None:
        return None
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        parts = []
        for block in system:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n\n".join(parts) if parts else None
    return None


# ---------------------------------------------------------------------------
# Small helpers mirroring the Kotlin wire logic
# ---------------------------------------------------------------------------


def clean_header_value(value):
    """Mirror of ZCodeOAuthManager.cleanHeaderValue: a header value is
    sent only when it is non-empty after trimming and consists entirely
    of printable ASCII (0x20-0x7E); anything else drops the header."""
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    if any(ord(c) < 0x20 or ord(c) > 0x7E for c in v):
        return None
    return v


def normalize_model_id(raw):
    """Mirror of ZCodeConstants.normalizeModelId: strip [1m]/[200k]
    context suffixes, case-insensitively match a known ZCode model.
    Returns the canonical spelling or None."""
    if raw is None:
        return None
    cleaned = str(raw).strip()
    for suffix in ("[1m]", "[200k]"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)].strip()
    if not cleaned:
        return None
    lower = cleaned.lower()
    for known in KNOWN_MODELS:
        if known.lower() == lower:
            return known
    return None


def wire_model_id(model_id):
    """Mirror of ZCodeConstants.wireModelId: upstream receives the model
    id lowercase; unknown ids are lowercased as-is rather than dropped."""
    canonical = normalize_model_id(model_id)
    if canonical is not None:
        return canonical.lower()
    return str(model_id).strip().lower()


def parse_jwt_payload(jwt):
    """Decode a JWT payload without verifying the signature (same as
    ZCodeOAuthManager.parseJwtPayload). Returns a dict or None."""
    if not jwt:
        return None
    parts = jwt.split(".")
    if len(parts) != 3:
        return None
    try:
        segment = parts[1]
        segment += "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(segment.encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def jwt_user_id(jwt):
    """Mirror of ZCodeOAuthManager.jwtUserId: user_id, else sub."""
    payload = parse_jwt_payload(jwt)
    if not payload:
        return None
    uid = payload.get("user_id") or payload.get("sub")
    if isinstance(uid, str) and uid.strip():
        return uid
    return None


def build_trace_headers():
    """Mirror of ZCodeChatWire.buildTraceHeaders: fresh UUIDs per call."""
    return {
        "x-request-id": str(uuid.uuid4()),
        "x-zcode-session-type": "main",
        "x-zcode-trace-id": str(uuid.uuid4()),
        "x-query-id": str(uuid.uuid4()),
        "x-zcode-query-source": "main_turn",
        "x-session-id": str(uuid.uuid4()),
    }


# ---------------------------------------------------------------------------
# Client identity headers (mirror of buildIdentityHeaders /
# currentIdentityHeaders, but with THIS machine's real values -- the app
# sends the phone's; the proxy must not spoof Android, so platform, OS,
# language and timezone are derived from the host via the stdlib)
# ---------------------------------------------------------------------------


def _platform_os_token():
    system = platform.system()
    return {"Windows": "win32", "Darwin": "darwin", "Linux": "linux"}.get(
        system, system.lower() or "unknown"
    )


def _platform_arch_token():
    machine = platform.machine()
    return {
        "AMD64": "x64",
        "x86_64": "x64",
        "ARM64": "arm64",
        "aarch64": "arm64",
        "armv7l": "arm",
        "armv8l": "arm",
        "i386": "x86",
        "i686": "x86",
    }.get(machine, clean_header_value(machine.lower()) or "unknown")


def _os_category():
    return {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(
        platform.system(), platform.system().lower() or "unknown"
    )


def _os_version():
    if platform.system() == "Darwin":
        mac = platform.mac_ver()[0]
        if mac:
            return mac
    return platform.release() or platform.version() or ""


def _client_language():
    """Best-effort BCP-47-ish tag for this machine (e.g. "zh-CN")."""
    candidates = []
    try:
        loc = locale.getlocale()[0]
        if loc:
            candidates.append(loc)
    except Exception:
        pass
    for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        value = os.environ.get(var)
        if value:
            candidates.append(value.split(":")[0])
    for cand in candidates:
        tag = cand.split(".")[0].split("@")[0].replace("_", "-")
        if tag and tag not in ("C", "POSIX"):
            cleaned = clean_header_value(tag)
            if cleaned:
                return cleaned
    return "en-US"


def _client_timezone():
    """Best-effort IANA timezone id for this machine (e.g. "Asia/Shanghai"),
    mirroring TimeZone.getDefault().id on the phone."""
    tz_env = os.environ.get("TZ")
    if tz_env:
        cleaned = clean_header_value(tz_env.lstrip(":"))
        if cleaned:
            return cleaned
    try:
        if os.path.islink("/etc/localtime"):
            target = os.readlink("/etc/localtime")
            marker = "zoneinfo/"
            idx = target.find(marker)
            if idx >= 0:
                cleaned = clean_header_value(target[idx + len(marker):])
                if cleaned:
                    return cleaned
    except OSError:
        pass
    try:
        with open("/etc/timezone", "r", encoding="utf-8") as fh:
            cleaned = clean_header_value(fh.read())
            if cleaned:
                return cleaned
    except OSError:
        pass
    names = time.tzname
    if names and names[0]:
        cleaned = clean_header_value(names[0])
        if cleaned:
            return cleaned
    return "UTC"


def build_identity_headers(device_mid):
    """Mirror of ZCodeOAuthManager.buildIdentityHeaders with host values.
    Every value passes the printable-ASCII gate; empty fields are omitted,
    never sent blank."""
    out = {}

    def put(name, value):
        cleaned = clean_header_value(value)
        if cleaned is not None:
            out[name] = cleaned

    put("X-Device-Mid", device_mid)
    put("X-Platform", "%s-%s" % (_platform_os_token(), _platform_arch_token()))
    put("X-Os-Category", _os_category())
    put("X-Os-Version", _os_version())
    put("X-Client-Language", _client_language())
    put("X-Client-Timezone", _client_timezone())
    return out


# ---------------------------------------------------------------------------
# Config file
# ---------------------------------------------------------------------------


def default_config_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_NAME)


def load_config(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def save_config(path, config):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass  # Windows: chmod is best-effort only
    os.replace(tmp_path, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Login (CLI init/poll flow, mirroring ZCodeOAuthManager)
# ---------------------------------------------------------------------------


def _https_json(method, url, body_obj, bearer=None, timeout=30):
    """One JSON-over-HTTPS round trip via http.client."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    body = None
    if body_obj is not None:
        body = json.dumps(body_obj).encode("utf-8")
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        status = resp.status
    finally:
        conn.close()
    text = raw.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text) if text else {}
    except ValueError:
        parsed = {}
    return status, parsed, text


def build_bigmodel_relay_url():
    """Mirror of ZCodeOAuthManager.buildBigModelRelayUrl."""
    return (
        "https://zcode.z.ai/app/oauth/login"
        "?redirect=zcode://oauth/callback"
        "&app_version=" + APP_VERSION
    )


def rewrite_authorize_url_for_bigmodel(authorize_url):
    """Mirror of ZCodeOAuthManager.rewriteAuthorizeUrlForProvider for the
    bigmodel provider: set the `redirect` query parameter to the official
    relay URL (replacing an existing one), leaving every other parameter
    and the fragment byte-for-byte. Raises ValueError on a non-HTTPS URL."""
    parts = urllib.parse.urlsplit(authorize_url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValueError("ZCode authorize URL is not a valid HTTPS URL")
    # Java's URLEncoder and quote_plus agree on every character that
    # occurs in the relay URL (letters, digits, '.', and %XX for the rest).
    encoded_relay = urllib.parse.quote_plus(build_bigmodel_relay_url())
    before_fragment, _, fragment = authorize_url.partition("#")
    base, _, raw_query = before_fragment.partition("?")
    pairs = [p for p in raw_query.split("&") if p] if raw_query else []
    redirect_param = "redirect=" + encoded_relay
    for i, pair in enumerate(pairs):
        if pair.split("=", 1)[0] == "redirect":
            pairs[i] = redirect_param
            break
    else:
        pairs.append(redirect_param)
    out = base + "?" + "&".join(pairs)
    if fragment:
        out += "#" + fragment
    return out


def _parse_deadline_seconds(data):
    """Mirror of ZCodeOAuthManager.parseExpiresAtMs: expires_at may be
    epoch seconds or millis; expires_in is relative seconds; the default
    window is 300 seconds."""
    now = time.time()
    raw = data.get("expires_at")
    num = None
    if isinstance(raw, (int, float)):
        num = int(raw)
    elif isinstance(raw, str):
        try:
            num = int(raw)
        except ValueError:
            num = None
    if num is not None and num > 0:
        return num / 1000.0 if num > 1_000_000_000_000 else float(num)
    expires_in = data.get("expires_in")
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        return now + float(expires_in)
    return now + 300.0



def cmd_login(args):
    provider = args.provider  # "zai" or "bigmodel"
    config_path = args.config or default_config_path()
    config = load_config(config_path)

    device_mid = config.get("device_mid")
    if not (isinstance(device_mid, str) and device_mid.strip()):
        device_mid = str(uuid.uuid4())
    access_key = config.get("access_key")
    access_key_is_new = not (isinstance(access_key, str) and access_key.strip())
    if access_key_is_new:
        access_key = secrets.token_urlsafe(32)

    # Step 1: init. The poll token is a self-generated 32-byte hex secret
    # sent as Bearer; the server may replace it with its own poll_token.
    poll_token = secrets.token_hex(32)
    status, payload, raw_text = _https_json(
        "POST", OAUTH_INIT_URL, {"provider": provider}, bearer=poll_token
    )
    if not (200 <= status <= 299):
        raise SystemExit("ZCode login init failed (HTTP %d): %s" % (status, raw_text[:200]))
    if payload.get("code", 0) != 0:
        raise SystemExit(
            "ZCode login init rejected (code=%s): %s" % (payload.get("code"), raw_text[:200])
        )
    data = payload.get("data")
    if not isinstance(data, dict):
        raise SystemExit("ZCode login init response is incomplete (no data)")
    flow_id = data.get("flow_id")
    authorize_url = data.get("authorize_url")
    if not flow_id or not authorize_url:
        raise SystemExit("ZCode login init response is incomplete (no flow_id/authorize_url)")
    if provider == "bigmodel":
        authorize_url = rewrite_authorize_url_for_bigmodel(authorize_url)
    effective_poll_token = data.get("poll_token") or poll_token
    interval = data.get("poll_interval_sec", 2)
    try:
        interval = float(interval)
    except (TypeError, ValueError):
        interval = 2.0
    interval = min(max(interval, 1.0), 10.0)
    deadline = _parse_deadline_seconds(data)

    print("Open this URL in a browser and finish the authorization:")
    print(authorize_url)
    print("Waiting for authorization (up to 300 seconds)...", flush=True)

    # Step 2: poll until data.token arrives or the deadline passes.
    jwt = None
    user_id = None
    while time.time() < deadline:
        time.sleep(interval)
        p_status, p_payload, _ = _https_json(
            "GET", OAUTH_POLL_URL + urllib.parse.quote(str(flow_id), safe=""),
            None, bearer=effective_poll_token,
        )
        if not (200 <= p_status <= 299):
            raise SystemExit("ZCode login poll failed (HTTP %d)" % p_status)
        p_data = p_payload.get("data")
        if not isinstance(p_data, dict):
            p_data = p_payload
        token = p_data.get("token")
        if token:
            jwt = token
            user_obj = p_data.get("user")
            if isinstance(user_obj, dict):
                uid = user_obj.get("user_id")
                if isinstance(uid, str) and uid.strip():
                    user_id = uid
            if user_id is None:
                user_id = jwt_user_id(jwt)
            break
        status_field = str(p_data.get("status", "")).lower()
        if status_field == "ready":
            raise SystemExit("ZCode login returned ready without a token")
        if status_field in ("expired", "denied", "cancelled", "canceled"):
            raise SystemExit("ZCode login was %s" % status_field)
        code = p_payload.get("code", 0)
        if code != 0:
            msg = p_payload.get("msg") or p_payload.get("message") or ""
            raise SystemExit("ZCode login failed (code=%s)%s" % (code, (": " + msg) if msg else ""))
        # Otherwise still pending: keep polling.
    if jwt is None:
        raise SystemExit("Login timed out (no authorization within 300 seconds); try again.")

    config = {
        "jwt": jwt,
        "device_mid": device_mid,
        "user_id": user_id,
        "access_key": access_key,
    }
    save_config(config_path, config)
    print("Login OK. Config saved to %s (mode 0600)." % config_path)
    if access_key_is_new:
        print("Proxy access key (shown once, keep it secret): %s" % access_key)
    return 0


# ---------------------------------------------------------------------------
# Serve
# ---------------------------------------------------------------------------


def log_line(message):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())
    sys.stderr.write("%s %s\n" % (stamp, message))
    sys.stderr.flush()


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, config, messages_url=MESSAGES_URL):
        self.config = config
        self.messages_url = messages_url
        self.semaphore = threading.Semaphore(UPSTREAM_CONCURRENCY)
        self.identity_headers = build_identity_headers(config.get("device_mid", ""))
        jwt = config.get("jwt", "")
        self.user_id = jwt_user_id(jwt) or config.get("user_id")
        super().__init__(server_address, ProxyHandler)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "zcode-lan-proxy"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, format, *args):  # silence the default logger
        pass

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status, error_type, message):
        self._send_json(
            status, {"type": "error", "error": {"type": error_type, "message": message}}
        )

    def _authorized(self):
        expected = self.server.config.get("access_key", "")
        auth = self.headers.get("Authorization", "")
        presented = None
        if auth.startswith("Bearer "):
            presented = auth[len("Bearer "):].strip()
        if presented is None:
            presented = self.headers.get("x-api-key")
        if presented is None or not expected:
            return False
        return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))

    # -- routing ----------------------------------------------------------

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def _dispatch(self):
        started = time.monotonic()
        path = urllib.parse.urlsplit(self.path).path
        model = "-"
        status = 500
        note = ""
        try:
            if path == "/health":
                if self.command != "GET":
                    status = 405
                    self._send_error_json(405, "invalid_request_error", "method not allowed")
                else:
                    status = 200
                    self._send_json(200, {"ok": True})
                return
            if not self._authorized():
                status = 401
                self._send_error_json(
                    401, "authentication_error", "missing or invalid access key"
                )
                return
            if path == "/v1/models" and self.command == "GET":
                status = 200
                self._send_json(200, models_payload())
                return
            if path == "/v1/messages" and self.command == "POST":
                status, model, note = self._handle_messages()
                return
            if path in ("/v1/models", "/v1/messages"):
                status = 405
                self._send_error_json(405, "invalid_request_error", "method not allowed")
                return
            status = 404
            self._send_error_json(404, "not_found_error", "unknown path: " + path)
        except (BrokenPipeError, ConnectionResetError):
            status = 499  # client went away mid-response
        except Exception:
            try:
                self._send_error_json(500, "api_error", "internal proxy error")
            except Exception:
                pass  # response already (partially) sent; nothing more to do
            status = 500
        finally:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            log_line(
                "%s %s model=%s status=%d %dms%s"
                % (self.command, path, model, status, elapsed_ms, note)
            )

    # -- /v1/messages ------------------------------------------------------

    def _read_request_body(self):
        """Returns the raw body bytes, or None after sending an error."""
        if self.headers.get("Transfer-Encoding"):
            self._send_error_json(
                400, "invalid_request_error", "chunked request bodies are not supported"
            )
            return None
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self._send_error_json(400, "invalid_request_error", "missing Content-Length")
            return None
        try:
            length = int(length_header)
        except ValueError:
            self._send_error_json(400, "invalid_request_error", "invalid Content-Length")
            return None
        if length < 0:
            self._send_error_json(400, "invalid_request_error", "invalid Content-Length")
            return None
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            self._send_error_json(
                413, "invalid_request_error", "request body exceeds the 32MB limit"
            )
            return None
        body = self.rfile.read(length)
        if len(body) != length:
            self._send_error_json(400, "invalid_request_error", "truncated request body")
            return None
        return body

    def _handle_messages(self):
        """Returns (status, model_for_log, log_note)."""
        raw = self._read_request_body()
        if raw is None:
            return 400, "-", ""
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_error_json(400, "invalid_request_error", "request body is not valid JSON")
            return 400, "-", ""
        if not isinstance(body, dict):
            self._send_error_json(400, "invalid_request_error", "request body must be a JSON object")
            return 400, "-", ""

        # (a) model id lowercase on the wire.
        model_for_log = "-"
        if isinstance(body.get("model"), str):
            body["model"] = wire_model_id(body["model"])
            model_for_log = body["model"]
        # (b) official identity system blocks in front; the client's own
        # system text is preserved, appended at the end of block 2.
        body["system"] = build_system_blocks(client_system_text(body.get("system")))
        # (c) metadata.user_id from the JWT payload.
        if self.server.user_id:
            metadata = body.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
            metadata["user_id"] = self.server.user_id
            body["metadata"] = metadata

        out_body = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        # (d) the full identity header set.
        jwt = self.server.config.get("jwt", "")
        headers = {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "Authorization": "Bearer " + jwt,
            "x-api-key": jwt,
            "User-Agent": "ZCode/" + APP_VERSION,
            "X-ZCode-App-Version": APP_VERSION,
            "X-ZCode-Agent": "glm",
            "HTTP-Referer": "https://zcode.z.ai",
            "X-Title": "Z Code@electron",
            "X-Release-Channel": "production",
        }
        headers.update(self.server.identity_headers)
        headers.update(build_trace_headers())

        parts = urllib.parse.urlsplit(self.server.messages_url)
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(
                parts.hostname, parts.port or 443, timeout=UPSTREAM_TIMEOUT
            )
        else:
            conn = http.client.HTTPConnection(
                parts.hostname, parts.port or 80, timeout=UPSTREAM_TIMEOUT
            )
        upstream_path = parts.path or "/"
        if parts.query:
            upstream_path += "?" + parts.query

        # Global concurrency cap: at most 2 in flight upstream; further
        # requests wait here instead of being rejected.
        self.server.semaphore.acquire()
        try:
            try:
                conn.request("POST", upstream_path, body=out_body, headers=headers)
                resp = conn.getresponse()
            except (OSError, http.client.HTTPException):
                self._send_error_json(502, "api_error", "upstream connection failed")
                return 502, model_for_log, ""
            captcha_header = resp.getheader("x-aliyun-captcha-verify-param")
            try:
                status, prefix = self._relay_response(resp)
            finally:
                resp.close()
            note = ""
            if captcha_header or _CAPTCHA_CODE_RE.search(prefix):
                note = (
                    " note=upstream-3007-captcha-challenge;"
                    " proxy cannot solve captchas, returned as-is without retry"
                )
            return status, model_for_log, note
        finally:
            self.server.semaphore.release()
            conn.close()

    def _relay_response(self, resp):
        """Stream the upstream response back chunk by chunk (flushed per
        chunk, never buffered whole). Returns (status, first-bytes) where
        first-bytes is a small prefix kept only for 3007 detection."""
        status = resp.status
        self.send_response(status)
        content_type = resp.getheader("Content-Type")
        if content_type:
            self.send_header("Content-Type", content_type)
        for name in ("Cache-Control", "Retry-After", "x-aliyun-captcha-verify-param"):
            value = resp.getheader(name)
            if value:
                self.send_header(name, value)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        prefix = bytearray()
        while True:
            # read1, not read: read(n) keeps reading until n bytes or
            # EOF, which would buffer a whole stream before relaying.
            chunk = resp.read1(16384)
            if not chunk:
                break
            if len(prefix) < 4096:
                prefix += chunk[: 4096 - len(prefix)]
            self.wfile.write(b"%x\r\n" % len(chunk))
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        return status, bytes(prefix)


_CAPTCHA_CODE_RE = re.compile(rb'"code"\s*:\s*3007')
# A 3007 is the captcha challenge (same signal ZCodeCaptchaGate uses in
# the app: a 3007 code in the body or the x-aliyun-captcha-verify-param
# response header, which _handle_messages checks separately).


def models_payload():
    data = [
        {
            "type": "model",
            "id": wire_model_id(model_id),
            "display_name": model_id,
            "created_at": "2025-01-01T00:00:00Z",
        }
        for model_id in START_PLAN_MODELS
    ]
    return {
        "data": data,
        "has_more": False,
        "first_id": data[0]["id"],
        "last_id": data[-1]["id"],
    }


def cmd_serve(args):
    config_path = args.config or default_config_path()
    if not os.path.exists(config_path):
        raise SystemExit(
            "Config not found: %s -- run `zcode_proxy.py login` first." % config_path
        )
    config = load_config(config_path)
    if not (isinstance(config.get("access_key"), str) and config["access_key"].strip()):
        raise SystemExit("Config has no access_key; refusing to start. Run login again.")
    if not (isinstance(config.get("jwt"), str) and config["jwt"].strip()):
        raise SystemExit("Config has no jwt; refusing to start. Run login first.")
    messages_url = os.environ.get("ZCODE_PROXY_MESSAGES_URL", MESSAGES_URL)
    server = ProxyServer(("0.0.0.0", args.port), config, messages_url=messages_url)
    log_line(
        "zcode-lan-proxy listening on http://0.0.0.0:%d "
        "(LAN clients: http://<this-machine-LAN-IP>:%d, access key required)"
        % (args.port, args.port)
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log_line("shutting down")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="zcode_proxy.py", description="ZCode LAN proxy (standard library only)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_login = sub.add_parser("login", help="run the ZCode CLI OAuth login once")
    p_login.add_argument(
        "--provider",
        choices=["zai", "bigmodel"],
        default="zai",
        help="login provider (default: zai)",
    )
    p_login.add_argument("--config", default=None, help="config file path")

    p_serve = sub.add_parser("serve", help="run the LAN proxy")
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT, help="port (default: 8799)")
    p_serve.add_argument("--config", default=None, help="config file path")

    args = parser.parse_args(argv)
    if args.command == "login":
        return cmd_login(args)
    return cmd_serve(args)


if __name__ == "__main__":
    sys.exit(main())
