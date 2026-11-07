package com.openminis.app.ui.settings

import android.annotation.SuppressLint
import android.os.Handler
import android.os.Looper
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.openminis.app.auth.ZCodeCaptchaGate
import com.openminis.app.auth.ZCodeConstants
import com.openminis.app.auth.ZCodeOAuthManager
import com.openminis.app.data.model.ProviderInstance
import com.openminis.app.data.repository.ProviderRepository
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * [T-zcode-provider] Manual ZCode console, shown on the ZCode provider
 * detail screen. Everything here is a manual button — no timers, no
 * background jobs, no auto-claim, no polling:
 *
 *   查额度   GET billing/balance + billing/current (raw values shown)
 *   查可领   GET billing/preview (claimable plans listed to pick from)
 *   领取     POST billing/claim {"plan_id": <the id the user picked>}
 *
 * One claim = one id, once. The upstream business code is shown with its
 * meaning (0=领到、1003=已领过、1001=不存在、1005=名额用完…); nothing
 * here auto-selects the "best" plan or loops over candidates.
 *
 * This section also mounts [ZCodeCaptchaDialog], the single host for the
 * manual captcha flow. Chat requests that hit a 3007 while this screen is
 * open can use the same dialog through [ZCodeCaptchaGate]; when the
 * console is not open the gate returns null and the chat path surfaces
 * the upstream error as-is.
 */

// ── Captcha dialog (shared by console + chat) ───────────────────────────

private class ZCodeCaptchaBridge(
    private val onParam: (String) -> Unit,
    private val onError: (String) -> Unit,
) {
    // JS-interface callbacks arrive off the main thread; hop to it before
    // touching Compose state or completing the gate.
    private val mainHandler = Handler(Looper.getMainLooper())

    @JavascriptInterface
    fun onVerifyParam(param: String) {
        mainHandler.post { onParam(param) }
    }

    @JavascriptInterface
    fun onError(message: String) {
        mainHandler.post { onError(message) }
    }
}

/**
 * Hosts the manual Aliyun verification. Shows a real WebView running the
 * official Aliyun SDK from the local asset page — NOT a headless browser,
 * NOT jsdom/happy-dom, NOT a solver. Traceless verification passes on its
 * own; if Aliyun wants a slider/puzzle it appears in the WebView for the
 * user to complete. The VERIFY_PARAM is handed back through the JS bridge
 * and used once, immediately, by the request that triggered it.
 */
@Composable
fun ZCodeCaptchaDialog() {
    DisposableEffect(Unit) {
        ZCodeCaptchaGate.registerListener()
        onDispose { ZCodeCaptchaGate.unregisterListener() }
    }
    val pending by ZCodeCaptchaGate.pending.collectAsState()
    val request = pending ?: return
    var errorMessage by remember(request) { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = { ZCodeCaptchaGate.complete(null) },
        title = { Text("完成验证后继续") },
        text = {
            androidx.compose.foundation.layout.Column {
                Text(
                    "ZCode 要求完成一次验证（无痕验证通常自动通过，需要时请在下方完成滑块 / 拼图）。验证只用于本次请求，不会被保存或复用。",
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (errorMessage != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(errorMessage!!, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                }
                Spacer(Modifier.height(8.dp))
                AndroidView(
                    modifier = Modifier.fillMaxWidth().height(360.dp),
                    factory = { ctx ->
                        @SuppressLint("SetJavaScriptEnabled")
                        WebView(ctx).apply {
                            settings.javaScriptEnabled = true
                            settings.domStorageEnabled = true
                            addJavascriptInterface(
                                ZCodeCaptchaBridge(
                                    onParam = { param -> ZCodeCaptchaGate.complete(param) },
                                    onError = { msg -> errorMessage = msg },
                                ),
                                "ZCodeCaptcha",
                            )
                            webViewClient = object : WebViewClient() {
                                override fun onPageFinished(view: WebView, url: String) {
                                    val cfg = JSONObject().apply {
                                        put("sceneId", request.config.sceneId)
                                        put("region", request.config.region)
                                        put("prefix", request.config.prefix)
                                    }
                                    view.evaluateJavascript(
                                        "window.startZCodeCaptcha && window.startZCodeCaptcha($cfg)",
                                        null,
                                    )
                                }
                            }
                            loadUrl("file:///android_asset/zcode_captcha.html")
                        }
                    },
                    onRelease = { it.destroy() },
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { ZCodeCaptchaGate.complete(null) }) {
                Text("取消")
            }
        },
    )
}

// ── Console section ────────────────────────────────────────────────────

private data class PlanOption(val id: String, val label: String)

private fun parsePreviewPlans(body: String): List<PlanOption> {
    val out = mutableListOf<PlanOption>()
    val data = runCatching { JSONObject(body).optJSONObject("data") }.getOrNull() ?: return out
    val plans = data.optJSONArray("plans") ?: data.optJSONArray("claimable") ?: return out
    for (i in 0 until plans.length()) {
        val p = plans.optJSONObject(i) ?: continue
        val id = p.optString("plan_id", "").ifEmpty { p.optString("id", "") }
        if (id.isEmpty()) continue
        val label = p.optString("show_name", "")
            .ifEmpty { p.optString("name", "") }
            .ifEmpty { p.optString("title", "") }
            .ifEmpty { id }
        out.add(PlanOption(id, label))
    }
    return out
}

private fun parseBalanceSummary(body: String): List<String> {
    val lines = mutableListOf<String>()
    val data = runCatching { JSONObject(body).optJSONObject("data") }.getOrNull() ?: return lines
    val balances = data.optJSONArray("balances") ?: return lines
    for (i in 0 until balances.length()) {
        val b = balances.optJSONObject(i) ?: continue
        val name = b.optString("show_name", "").ifEmpty { b.optString("model", "") }
        val total = b.optLong("total_units", -1)
        val used = b.optLong("used_units", -1)
        val remaining = b.optLong("remaining_units", -1)
        val expires = b.optString("expires_at", "")
        lines.add(
            listOfNotNull(
                name.ifEmpty { null },
                if (remaining >= 0) "剩余 $remaining" else null,
                if (total >= 0) "/ 共 $total" else null,
                if (used >= 0) "(已用 $used)" else null,
                if (expires.isNotEmpty()) "到期 $expires" else null,
            ).joinToString(" ").ifEmpty { "（空）" },
        )
    }
    return lines
}

private fun parsePlanNames(body: String): List<String> {
    val names = mutableListOf<String>()
    val data = runCatching { JSONObject(body).optJSONObject("data") }.getOrNull() ?: return names
    data.optJSONArray("plans")?.let { plans ->
        for (i in 0 until plans.length()) {
            val p = plans.optJSONObject(i) ?: continue
            p.optString("show_name", "").ifEmpty { p.optString("name", "") }
                .takeIf { it.isNotEmpty() }?.let { names.add(it) }
        }
    }
    return names
}

@Composable
fun ColumnScope.ZCodeConsoleSection(
    instance: ProviderInstance,
    @Suppress("UNUSED_PARAMETER") providerRepository: ProviderRepository,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val manager = remember(instance.id) { ZCodeOAuthManager(context, instance.id) }

    // The captcha dialog host for this screen (shared with chat).
    ZCodeCaptchaDialog()

    var planMode by remember(instance.id) { mutableStateOf(manager.planMode()) }
    var busy by remember { mutableStateOf<String?>(null) }
    var statusLine by remember { mutableStateOf<String?>(null) }
    var balanceResult by remember { mutableStateOf<ZCodeOAuthManager.ApiResult?>(null) }
    var currentResult by remember { mutableStateOf<ZCodeOAuthManager.ApiResult?>(null) }
    var previewResult by remember { mutableStateOf<ZCodeOAuthManager.ApiResult?>(null) }
    var claimResult by remember { mutableStateOf<ZCodeOAuthManager.ApiResult?>(null) }
    var selectedPlanId by remember { mutableStateOf<String?>(null) }

    val previewPlans = previewResult?.let { parsePreviewPlans(it.body) }.orEmpty()

    fun runAction(label: String, block: suspend () -> Unit) {
        if (busy != null) return
        busy = label
        statusLine = null
        scope.launch {
            try {
                block()
            } catch (e: Exception) {
                statusLine = "$label 失败：${e.message}"
            } finally {
                busy = null
            }
        }
    }

    SettingsSection(
        header = "ZCode 控制台",
        footer = "全部手动操作，无自动领取、无定时刷新。领取只领你在下方选中的一个计划，领一次。",
    ) {
        SettingsCardBlock {
            androidx.compose.foundation.layout.Column(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            ) {
                Text(
                    "套餐：${when (planMode) {
                        ZCodeConstants.PlanMode.START -> "Start Plan（免费体验）"
                        ZCodeConstants.PlanMode.CODING -> "Coding Plan（付费）"
                        ZCodeConstants.PlanMode.UNKNOWN -> "未知（查一次额度后确定）"
                    }}",
                    style = MaterialTheme.typography.bodyLarge,
                )
                if (planMode == ZCodeConstants.PlanMode.START) {
                    Text(
                        "Start Plan 可用模型：GLM-5.3-Flash、GLM-5.2、GLM-5-Turbo（无 GLM-5.3）。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.height(8.dp))
                MinisButton(
                    onClick = {
                        runAction("查额度") {
                            balanceResult = manager.fetchBillingBalance()
                            currentResult = manager.fetchBillingCurrent()
                            planMode = manager.refreshPlanMode()
                            val r = balanceResult!!
                            statusLine = if (r.captchaCancelled) "已取消验证，未扣额度。"
                            else "额度已读取（HTTP ${r.httpStatus}）。"
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = busy == null,
                ) { Text(if (busy == "查额度") "查询中…" else "查额度") }
                Spacer(Modifier.height(8.dp))
                MinisButton(
                    onClick = {
                        runAction("查可领") {
                            previewResult = manager.fetchBillingPreview()
                            selectedPlanId = null
                            val r = previewResult!!
                            statusLine = if (r.captchaCancelled) "已取消验证，未扣额度。"
                            else "可领计划已读取（HTTP ${r.httpStatus}）。"
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = busy == null,
                ) { Text(if (busy == "查可领") "查询中…" else "查可领") }
                Spacer(Modifier.height(8.dp))
                MinisButton(
                    onClick = {
                        val planId = selectedPlanId ?: return@MinisButton
                        runAction("领取") {
                            claimResult = manager.claimPlan(planId)
                            val r = claimResult!!
                            statusLine = when {
                                r.captchaCancelled -> "已取消验证，未扣额度。"
                                r.code != null -> "领取结果：${ZCodeConstants.claimCodeMeaning(r.code)}（code=${r.code}）"
                                else -> "领取返回 HTTP ${r.httpStatus}。"
                            }
                            if (r.code == 0) {
                                balanceResult = manager.fetchBillingBalance()
                                planMode = manager.refreshPlanMode()
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = busy == null && selectedPlanId != null,
                ) { Text(if (busy == "领取") "领取中…" else "领取选中计划") }

                if (statusLine != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(statusLine!!, style = MaterialTheme.typography.bodyMedium)
                }

                val balanceLines = balanceResult?.let { parseBalanceSummary(it.body) }.orEmpty()
                if (balanceLines.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text("额度", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    balanceLines.forEach { line ->
                        Text(line, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                val planNames = currentResult?.let { parsePlanNames(it.body) }.orEmpty()
                if (planNames.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text("当前套餐", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    planNames.forEach { name ->
                        Text(name, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                if (previewPlans.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text("可领计划（点选一个，再按“领取选中计划”）", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    previewPlans.forEach { plan ->
                        SettingsRow(
                            title = plan.label,
                            subtitle = plan.id,
                            onClick = { selectedPlanId = plan.id },
                            showDivider = false,
                        )
                        if (selectedPlanId == plan.id) {
                            Text("已选中", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                        }
                    }
                } else if (previewResult != null) {
                    Spacer(Modifier.height(8.dp))
                    Text("当前没有可领的计划。", style = MaterialTheme.typography.bodyMedium)
                }
                if (claimResult != null) {
                    Spacer(Modifier.height(8.dp))
                    Text("领取返回", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(
                        claimResult!!.body.take(2000),
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (balanceResult != null) {
                    Spacer(Modifier.height(8.dp))
                    Text("额度原始返回", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    androidx.compose.foundation.layout.Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(160.dp)
                            .verticalScroll(rememberScrollState()),
                    ) {
                        Text(
                            balanceResult!!.body.take(4000),
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}
