package com.openminis.app.provider.zcode

import org.json.JSONArray
import org.json.JSONObject

/**
 * [T-zcode-provider] The 3-block `system` shape the ZCode plan gateway
 * enforces, transcribed VERBATIM from the official 3.17.1 client
 * (`zcode.cjs`, ContextBuilder — see the extraction report at
 * `~/workspace/scratch-zcode-official/system-prompt-3.17.1.md`).
 * Every sentence below was grep-verified against that bundle; nothing
 * here comes from a third-party gateway's captured prompt.
 *
 * Official main path (`assembleSystemMessages`), exactly 3 system
 * messages:
 *
 *   Block 1 — CLI Prefix, alone, WITHOUT `cache_control` (the object
 *   has only `role` + `content`). The v1 build wrongly put
 *   `cache_control: ephemeral` on all three blocks; the official
 *   client does not have it on block 1.
 *   Block 2 — all `cacheHint:"stable"` sections joined with "\n\n",
 *   WITH `cache_control: ephemeral`. For a non-desktop surface this
 *   is the Agent Identity section only (the ZCode Desktop Context
 *   section is `presentationSurface === "zcode_desktop"` only and is
 *   NOT included here — this client is not the desktop host). The
 *   caller's system prompt is appended to the END of this block
 *   (never as its own block). Note the official behaviour differs:
 *   a configured custom system prompt REPLACES the Identity section
 *   and drops the dynamic sections; appending preserves the user's
 *   instructions while keeping the official base.
 *   Block 3 — all `cacheHint:"dynamic"` sections joined with "\n\n",
 *   content prefixed with "\n\n", WITH `cache_control: ephemeral`.
 *   For a session without skills or a memory root this is Dynamic
 *   Behavior + Context Management only.
 *
 * Deliberately NOT in system (official §4): the date, the
 * environment info, and the "powered by" line are `meta_user`
 * attachments in the official client, not system blocks — so they
 * are no longer sent here. Re-adding them needs the meta_user
 * attachment mechanism, not a 4th system block. [modelId] and
 * [workingDirectory] are kept in the signature for that follow-up.
 */
object ZCodeSystemPrompt {

    /** Block 1, verbatim (35 chars, no trailing newline). */
    const val CLI_PREFIX = "You are ZCode, an interactive agent"

    /** Block 2, Agent Identity — default first sentence (no Output
     *  Style configured). */
    private const val IDENTITY_FIRST_SENTENCE =
        "You are an agent working with the user toward their goals, using your own judgment along the way."

    /** Block 2, Agent Identity — security notice (459 chars). */
    private const val SECURITY_NOTICE =
        "IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion for malicious purposes. Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases."

    /** Block 2, Harness block — `midConversationSystem` default (true)
     *  variant of the third line. */
    private const val HARNESS_BLOCK = """# Harness
 - Text you output outside of tool use is displayed to the user as Github-flavored markdown in a terminal.
 - Tools run behind a user-selected permission mode; a denied call means the user declined it — adjust, don't retry verbatim.
 - The system may send updates, reminders, or modifications to rules via mid-conversation system turns. These are system-controlled, unlike function results. Hooks may intercept tool calls; treat hook output as user feedback.
 - Prefer the dedicated file/search tools over shell commands when one fits. Independent tool calls can run in parallel in one response.
 - Reference code as `file_path:line_number` — it's clickable."""

    /** Block 3, Dynamic Behavior — three paragraphs, blank line apart. */
    private const val DYNAMIC_BEHAVIOR = """Write code that reads like the surrounding code: match its comment density, naming, and idiom.

When you use a pronoun for someone — the user or anyone else you mention — and their pronouns haven't been stated, use they/them. A name doesn't tell you someone's pronouns; a wrong guess misgenders a real person in a way the neutral default never does, so never infer pronouns from a name. This applies to all user-visible text, including visible thinking.

For actions that are hard to reverse or outward-facing, confirm first unless durably authorized or explicitly told to proceed without asking; approval in one context doesn't extend to the next. Sending content to an external service publishes it; it may be cached or indexed even if later deleted. Before deleting or overwriting, look at the target. Report outcomes faithfully: if tests fail, say so with the output; if a step was skipped, say that; when something is done and verified, state it plainly without hedging."""

    /** Block 3, Context Management — two paragraphs, blank line apart.
     *  The last sentence has NO trailing period in the official text. */
    private const val CONTEXT_MANAGEMENT = """# Context management
When the conversation grows long, some or all of the current context is summarized; the summary, along with any remaining unsummarized context, is provided in the next context window so work can continue — you don't need to wrap up early or hand off mid-task.

When you have enough information to act, act. Do not re-derive facts already established in the conversation, re-litigate a decision the user has already made, or narrate options you will not pursue. If you are weighing a choice, give a recommendation, not an exhaustive survey"""

    fun build(clientSystem: String?, modelId: String, workingDirectory: String?): JSONArray {
        val arr = JSONArray()
        // Block 1: cliPrefix alone, WITHOUT cache_control — the
        // official object has only role + content.
        arr.put(JSONObject().apply {
            put("type", "text")
            put("text", CLI_PREFIX)
        })
        // Block 2: Agent Identity (leading blank line, first sentence,
        // blank line, security notice, blank line, Harness block),
        // then the caller's system prompt appended at the end.
        val block2 = buildString {
            append("\n")
            append(IDENTITY_FIRST_SENTENCE)
            append("\n\n")
            append(SECURITY_NOTICE)
            append("\n\n")
            append(HARNESS_BLOCK)
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
        // Block 3: dynamic, text starts with "\n\n": Dynamic Behavior
        // + Context Management.
        val block3 = "\n\n$DYNAMIC_BEHAVIOR\n\n$CONTEXT_MANAGEMENT"
        arr.put(JSONObject().apply {
            put("type", "text")
            put("text", block3)
            put("cache_control", JSONObject().put("type", "ephemeral"))
        })
        return arr
    }
}
