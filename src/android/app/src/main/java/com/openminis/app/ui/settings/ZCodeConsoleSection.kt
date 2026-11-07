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
import com.openminis.app.auth.ZCodeActivation
import com.openminis.app.auth.ZCodeCaptchaGate
import com.openminis.app.auth.ZCodeConstants
import com.openminis.app.auth.ZCodeOAuthManager
import com.openminis.app.data.model.ProviderInstance
import com.openminis.app.data.repository.ProviderRepository
import com.openminis.app.ui.components.MinisButton
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * [T-zcode-provider] Manual ZCode console, shown on the ZCode provider
 * detail screen. Everything here is a manual button — no timers, no
 * background jobs, no auto-claim, no polling:
 *
 *   查额度   GET billing/balance + billing/current (raw values shown)
 *   查可领   激活上报（app_launch + app_daily_active + app_login_success）→ GET
 *            marketing/touch（seq 递增）→ touch 为空时再 GET billing/preview
 *            （带 app_version/platform）；touch 优先，preview 只作备用；
 *            两路都空时列出日期编码兑底 id（可选手册领取，待实测）；
 *            仍无可领时用 balance + current 交叉验证账号到底有无套餐。
 *            上报失败不阻断继续。
 *   领取     POST billing/claim {"plan_id": <the id the user picked>}；
 *            当天已领过的不再重复领，连续 3 次 1005 的计划 30 分钟内
 *            不再试；成功后发 touch confirm 回执（失败不影响结果）。
 *   预取验证 手动预取一次验证码参数并缓存 45 秒，下次验证不再弹窗。
 *
 * One claim = one id, once, chosen by the user. The upstream business
 * code is shown with its meaning (0=领到、1003=已领过、1001=不存在、
 * 1005=名额用完…); nothing here auto-selects the "best" plan or loops
 * over candidates. The version manifest is checked at most once per 5
 * days when this screen opens (no timer); only upgrades are adopted.
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
        title = { Text(if (request.isPrefetch) "预取验证" else "完成验证后继续") },
        text = {
            androidx.compose.foundation.layout.Column {
                Text(
                    if (request.isPrefetch) {
                        "正在为下一次请求预取验证（无痕验证通常自动通过，需要时请在下方完成滑块 / 拼图）。预取到的参数只缓存 45 秒、只用一次。"
                    } else {
                        "ZCode 要求完成一次验证（无痕验证通常自动通过，需要时请在下方完成滑块 / 拼图）。验证只用于本次请求，不会被保存或复用。"
                    },
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

private fun parseBalanceSummary(body: String): List<String> {
    val detail = ZCodeActivation.parseBalanceDetail(body)
    val lines = mutableListOf<String>()
    for (b in detail.buckets) {
        lines.add(
            listOfNotNull(
                b.name.ifEmpty { null },
                if (b.remaining >= 0) "剩余 ${b.remaining}" else null,
                if (b.total >= 0) "/ 共 ${b.total}" else null,
                if (b.used >= 0) "(已用 ${b.used})" else null,
                b.periodLabel.ifEmpty { null },
                if (b.capabilities.isNotEmpty()) "能力 ${b.capabilities.joinToString(",")}" else null,
                if (b.expiresAt.isNotEmpty()) "到期 ${b.expiresAt}" else null,
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

    // #19: version manifest check, at most once per 5 days, only when
    // this screen opens. Silent — no timer, no status line.
    androidx.compose.runtime.LaunchedEffect(instance.id) {
        runCatching { manager.checkClientVersionIfDue() }
    }

    var planMode by remember(instance.id) { mutableStateOf(manager.planMode()) }
    var busy by remember { mutableStateOf<String?>(null) }
    var statusLine by remember { mutableStateOf<String?>(null) }
    var balanceResult by remember { mutableStateOf<ZCodeOAuthManager.ApiResult?>(null) }
    var currentResult by remember { mutableStateOf<ZCodeOAuthManager.ApiResult?>(null) }
    var previewResult by remember { mutableStateOf<ZCodeOAuthManager.ApiResult?>(null) }
    var touchResult by remember { mutableStateOf<ZCodeOAuthManager.ApiResult?>(null) }
    var activationResult by remember { mutableStateOf<ZCodeActivation.ActivationResult?>(null) }
    var claimResult by remember { mutableStateOf<ZCodeOAuthManager.ApiResult?>(null) }
    var selectedPlan by remember { mutableStateOf<ZCodeActivation.ClaimablePlan?>(null) }
    var fallbackPlans by remember { mutableStateOf<List<ZCodeActivation.ClaimablePlan>>(emptyList()) }
    var crossCheck by remember { mutableStateOf<ZCodeActivation.CrossCheck?>(null) }
    var prefetchStatus by remember { mutableStateOf<String?>(null) }

    // Claimable plans: touch first, preview as backup, deduped by
    // plan_id, priority desc then plan_id asc — plus date-coded
    // fallback entries when both channels are empty. Parsing is tiny,
    // so it is recomputed from the raw results on every recomposition.
    val claimablePlans = ZCodeActivation.mergePlans(
        previewResult?.let { ZCodeActivation.parsePreviewPlans(it.body) }.orEmpty(),
        touchResult?.let { ZCodeActivation.parseTouchDeliveries(it.body) }.orEmpty(),
    ) + fallbackPlans

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
        footer = "全部手动操作，无自动领取、无定时刷新。查可领前先上报一次当日活跃（官方客户端同款，用于发现活动套餐）；领取只领你在下方选中的一个计划，领一次。",
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
                            // Activation first (manual tap only, no timer,
                            // no daily gate — upstream dedupes by device
                            // + date). A failed report is recorded, not
                            // fatal: preview and touch still run.
                            activationResult = manager.reportActivation()
                            // #5: touch first; preview only as a backup
                            // when touch yields nothing.
                            touchResult = manager.fetchMarketingTouch()
                            val touchPlans = touchResult?.let {
                                ZCodeActivation.parseTouchDeliveries(it.body)
                            }.orEmpty()
                            previewResult = if (touchPlans.isEmpty()) {
                                manager.fetchBillingPreview()
                            } else null
                            val previewPlans = previewResult?.let {
                                ZCodeActivation.parsePreviewPlans(it.body)
                            }.orEmpty()
                            val merged = ZCodeActivation.mergePlans(previewPlans, touchPlans)
                            // #20: both channels empty — offer date-coded
                            // fallback ids as selectable entries (manual
                            // claim only, never auto-claimed).
                            fallbackPlans = if (merged.isEmpty()) {
                                ZCodeActivation.buildDateCodedFallbackIds(
                                    java.time.LocalDate.now(
                                        java.time.ZoneId.of("Asia/Shanghai"),
                                    ),
                                ).map { id ->
                                    ZCodeActivation.ClaimablePlan(
                                        id = id,
                                        name = id,
                                        description = "兑底（待实测）",
                                        source = ZCodeActivation.ClaimablePlan.Source.FALLBACK,
                                    )
                                }
                            } else emptyList()
                            // #13: still nothing claimable — cross-check
                            // with balance + current instead of calling
                            // it an interface failure.
                            crossCheck = if (merged.isEmpty()) {
                                balanceResult = manager.fetchBillingBalance()
                                currentResult = manager.fetchBillingCurrent()
                                ZCodeActivation.crossCheckPlan(
                                    balanceResult!!.body,
                                    currentResult!!.body,
                                )
                            } else null
                            selectedPlan = null
                            val act = activationResult!!
                            statusLine = "激活上报${act.message}；可领计划已读取" +
                                if (merged.isEmpty()) "（两路都空，已列出兑底 id）。" else "。"
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = busy == null,
                ) { Text(if (busy == "查可领") "查询中…" else "查可领") }
                Spacer(Modifier.height(8.dp))
                MinisButton(
                    onClick = {
                        val plan = selectedPlan ?: return@MinisButton
                        runAction("领取") {
                            val uid = manager.userId().orEmpty()
                            // #11: already claimed today — do not repeat.
                            if (uid.isNotEmpty() && manager.isClaimedToday(uid, plan.id)) {
                                statusLine = "今天已领过 ${plan.id}，不再重复领取。"
                                return@runAction
                            }
                            // #9: 3 consecutive 1005s block the plan for
                            // 30 minutes.
                            if (manager.isClaimBlocked(plan.id)) {
                                statusLine = "该计划因连续 3 次名额用完，30 分钟内不再尝试。"
                                return@runAction
                            }
                            claimResult = manager.claimPlan(plan.id)
                            val r = claimResult!!
                            statusLine = when {
                                r.captchaCancelled -> "已取消验证，未扣额度。"
                                r.code == 1005 -> {
                                    manager.recordClaim1005(plan.id)
                                    val next = ZCodeActivation.parseClaimNextAvailableAt(r.body)
                                    // #9 self-heal: refresh the balance
                                    // and re-check instead of trusting
                                    // the stale read.
                                    balanceResult = manager.fetchBillingBalance()
                                    val cc = ZCodeActivation.crossCheckPlan(
                                        balanceResult!!.body,
                                        currentResult?.body.orEmpty(),
                                    )
                                    "领取结果：名额已用完（code=1005）" +
                                        (if (next != null) "，下次可领时间：$next" else "") +
                                        "；${cc.summary}。"
                                }
                                r.code == 1003 -> {
                                    manager.resetClaimCircuit(plan.id)
                                    if (uid.isNotEmpty()) manager.recordClaimedToday(uid, plan.id)
                                    "领取结果：已领取过（code=1003）。"
                                }
                                ZCodeActivation.claimSucceeded(r.code, r.body) -> {
                                    manager.resetClaimCircuit(plan.id)
                                    if (uid.isNotEmpty()) manager.recordClaimedToday(uid, plan.id)
                                    // #7: touch confirm receipt —
                                    // best-effort, never blocks the result.
                                    if (plan.campaignId.isNotEmpty()) {
                                        manager.confirmTouchAction(plan.campaignId)
                                    }
                                    balanceResult = manager.fetchBillingBalance()
                                    planMode = manager.refreshPlanMode()
                                    "领取成功：${plan.name}。"
                                }
                                r.code != null -> "领取结果：${ZCodeConstants.claimCodeMeaning(r.code)}（code=${r.code}）"
                                else -> "领取返回 HTTP ${r.httpStatus}。"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = busy == null && selectedPlan != null,
                ) { Text(if (busy == "领取") "领取中…" else "领取选中计划") }
                Spacer(Modifier.height(8.dp))
                MinisButton(
                    onClick = {
                        runAction("预取验证") {
                            val config = manager.fetchCaptchaConfig()
                            if (config.skipModelRequest) {
                                prefetchStatus = "当前配置跳过模型请求验证，无需预取。"
                                return@runAction
                            }
                            val param = ZCodeCaptchaGate.requestPrefetch(config)
                            if (param != null) {
                                ZCodeCaptchaGate.cachePrefetchedParam(param)
                                prefetchStatus = "已预取验证（45 秒内有效，下次验证不再弹窗）。"
                            } else {
                                prefetchStatus = "预取未完成（已取消或无验证弹窗）。"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = busy == null,
                ) { Text(if (busy == "预取验证") "预取中…" else "预取验证") }

                if (statusLine != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(statusLine!!, style = MaterialTheme.typography.bodyMedium)
                }
                if (prefetchStatus != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(prefetchStatus!!, style = MaterialTheme.typography.bodyMedium)
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
                if (claimablePlans.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text("可领计划（点选一个，再按“领取选中计划”）", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    claimablePlans.forEach { plan ->
                        val subtitle = buildString {
                            append(plan.id)
                            if (plan.description.isNotEmpty()) append(" · ${plan.description}")
                            if (plan.grants.isNotEmpty()) {
                                append(" · ")
                                append(plan.grants.joinToString(", ") { grant ->
                                    "${grant.name.ifEmpty { "额度" }} ${grant.units}"
                                })
                            }
                            if (plan.source == ZCodeActivation.ClaimablePlan.Source.FALLBACK) {
                                append(" · 兑底 id，未验证是否有效")
                            }
                        }
                        SettingsRow(
                            title = plan.name,
                            subtitle = subtitle,
                            onClick = { selectedPlan = plan },
                            showDivider = false,
                        )
                        if (selectedPlan?.id == plan.id) {
                            Text("已选中", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                        }
                    }
                    // #20: which categories look missing, from current.
                    val missing = currentResult?.let {
                        ZCodeActivation.classifyMissingCategories(it.body)
                    }.orEmpty()
                    if (missing.isNotEmpty()) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "提示：当前套餐疑似缺 " + missing.joinToString("、") {
                                if (it == "weekend") "周末包" else "每日包"
                            } + "（按 current 的计划 id 启发式判断，仅供参考）。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else if (previewResult != null || touchResult != null) {
                    Spacer(Modifier.height(8.dp))
                    Text("当前没有可领的计划。", style = MaterialTheme.typography.bodyMedium)
                }
                if (crossCheck != null) {
                    Spacer(Modifier.height(8.dp))
                    Text("交叉验证：${crossCheck!!.summary}", style = MaterialTheme.typography.bodyMedium)
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
                if (previewResult != null) {
                    Spacer(Modifier.height(8.dp))
                    Text("可领原始返回", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    androidx.compose.foundation.layout.Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(160.dp)
                            .verticalScroll(rememberScrollState()),
                    ) {
                        Text(
                            previewResult!!.body.take(4000),
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                if (touchResult != null) {
                    Spacer(Modifier.height(8.dp))
                    Text("活动发现原始返回", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    androidx.compose.foundation.layout.Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(160.dp)
                            .verticalScroll(rememberScrollState()),
                    ) {
                        Text(
                            touchResult!!.body.take(4000).ifEmpty { "（空）" },
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}
