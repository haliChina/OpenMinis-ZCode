package com.openminis.app.provider.zcode

import org.json.JSONArray
import org.json.JSONObject
import java.time.LocalDate
import java.time.format.DateTimeFormatter

/**
 * [T-zcode-provider] The 3-block `system` shape the ZCode plan gateway
 * enforces (verified in dengyie `body_transform.py` and kilim
 * `system-prompt.ts` / `body-transformer.ts`):
 *
 *   Block 1 — cliPrefix, alone, NO cache_control. The gateway checks the
 *   first block's identity; appending a 4th block or folding the prefix
 *   into another block has been observed to trigger 405 / 3012.
 *   Block 2 — stable behaviour, `cache_control: ephemeral`; the caller's
 *   system prompt is appended to the END of this block (never as its own
 *   block).
 *   Block 3 — dynamic behaviour, `cache_control: ephemeral`, text starting
 *   with "\n\n": date, environment, and the trailing powered-by line.
 *
 * The TEXT is our own wording, not a copy of any gateway's captured
 * official prompt (see ZCodeConstants). If upstream tightens the
 * fingerprint check to byte-compare the official text, requests will
 * start failing with 3012 and this file is the first place to revisit —
 * that is a known, documented limitation of this v1, not a bug to
 * silently paper over by shipping a captured prompt.
 */
object ZCodeSystemPrompt {

    const val CLI_PREFIX = "You are ZCode, an interactive coding agent"

    /** Block 2 — stable behaviour. Kept short and generic on purpose. */
    private const val STABLE = """You are a coding agent running inside the user's editor session.
Follow the user's instructions directly. When you need to change files, say what you are changing and why before you change it.
Prefer minimal, targeted edits over rewrites. Do not invent APIs, files, or tool results you have not observed.
If a request is ambiguous, ask one short clarifying question instead of guessing.
Keep answers concise; use code blocks for code and plain language for explanations."""

    fun build(clientSystem: String?, modelId: String, workingDirectory: String?): JSONArray {
        val arr = JSONArray()
        // Block 1: cliPrefix alone, no cache_control.
        arr.put(JSONObject().apply {
            put("type", "text")
            put("text", CLI_PREFIX)
        })
        // Block 2: stable + client system appended at the end.
        val block2 = buildString {
            append(STABLE)
            if (!clientSystem.isNullOrBlank()) {
                append("\n\n")
                append(clientSystem)
            }
        }
        arr.put(JSONObject().apply {
            put("type", "text")
            put("text", block2)
            put("cache_control", JSONObject().put("type", "ephemeral"))
        })
        // Block 3: dynamic, text starts with "\n\n".
        val today = LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE)
        val block3 = buildString {
            append("\n\n# Dynamic Behavior\n")
            append("- Today's date is $today.\n")
            append("- Answer in the user's language unless asked otherwise.\n")
            append("\n## Environment Info\n")
            append("- Platform: Android (OpenMinis)\n")
            append("- Working directory: ${workingDirectory ?: "(not set)"}\n")
            append("\n## Context Management\n")
            append("- If the conversation grows long, summarize what matters and keep working from the summary.\n")
            append("- You are powered by the model named zai-api/$modelId.")
        }
        arr.put(JSONObject().apply {
            put("type", "text")
            put("text", block3)
            put("cache_control", JSONObject().put("type", "ephemeral"))
        })
        return arr
    }
}
