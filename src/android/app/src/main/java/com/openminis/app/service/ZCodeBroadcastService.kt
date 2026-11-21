package com.openminis.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.openminis.app.R
import com.openminis.app.auth.ZCodeConstants
import com.openminis.app.auth.ZCodeOAuthManager
import com.openminis.app.logging.AppLogger
import com.openminis.app.provider.zcode.ZCodeBroadcast
import com.openminis.app.provider.zcode.ZCodeBroadcastServer
import com.openminis.app.provider.zcode.ZCodeProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayInputStream
import java.util.concurrent.TimeUnit

/**
 * [T-zcode-broadcast] Process-wide lifecycle for the in-app ZCode
 * broadcast (the local Anthropic endpoint for other apps on this
 * device, see [ZCodeBroadcastServer]).
 *
 * The controller owns the server and the state the console observes;
 * [ZCodeBroadcastService] is only the foreground-service shell Android
 * requires to keep the process alive while broadcasting — the same
 * split [BackupRunController] / [BackupForegroundService] use.
 *
 * State is deliberately NOT persisted: if the process dies the
 * broadcast is gone (Android gives a localhost server no resurrection
 * path short of boot receivers, which are out of scope), and the
 * console switch must say so rather than show a stale "on". The
 * access key and the LAN preference ARE persisted (per instance, in
 * the manager's encrypted store); the running state is not.
 */
object ZCodeBroadcastController {

    sealed interface State {
        object Stopped : State
        data class Starting(val instanceId: String, val allowLan: Boolean) : State
        data class Running(
            val instanceId: String,
            val host: String,
            val port: Int,
            val allowLan: Boolean,
        ) : State

        data class Failed(val instanceId: String, val message: String) : State
    }

    private const val TAG = "ZCodeBroadcast"

    private val _state = MutableStateFlow<State>(State.Stopped)
    val state: StateFlow<State> = _state.asStateFlow()

    @Volatile
    private var server: ZCodeBroadcastServer? = null

    /**
     * From the console switch — a user action, so the
     * foreground-service start restriction does not apply. Re-tapping
     * with different parameters (another instance, LAN on/off) rebinds.
     */
    fun requestStart(context: Context, instanceId: String, allowLan: Boolean) {
        when (val current = _state.value) {
            is State.Running ->
                if (current.instanceId == instanceId && current.allowLan == allowLan) return
            is State.Starting ->
                if (current.instanceId == instanceId && current.allowLan == allowLan) return
            else -> Unit
        }
        _state.value = State.Starting(instanceId, allowLan)
        if (!ZCodeBroadcastService.start(context, instanceId, allowLan)) {
            _state.value = State.Failed(instanceId, "广播启动失败：系统拒绝启动前台服务。")
        }
    }

    fun requestStop() {
        stopServer()
        _state.value = State.Stopped
    }

    /**
     * Called by the service once it is foreground: build the server
     * for [instanceId] and bind it. A bind failure lands in
     * [State.Failed] with a user-readable message — the console shows
     * it; nothing fails silently.
     */
    internal fun beginServer(context: Context, instanceId: String, allowLan: Boolean) {
        stopServer()
        val manager = ZCodeOAuthManager(context.applicationContext, instanceId)
        val host = if (allowLan) ZCodeBroadcast.ANY_HOST else ZCodeBroadcast.LOOPBACK_HOST
        val newServer = ZCodeBroadcastServer(
            accessKeyProvider = { manager.broadcastAccessKey() },
            sessionProvider = { buildSession(manager) },
            modelsProvider = {
                ZCodeConstants.modelsForPlan(manager.planMode()).map { it.id }
            },
            upstream = OkHttpBroadcastUpstream(),
            semaphore = ZCodeProvider.sharedSemaphoreFor(instanceId),
            log = { AppLogger.info(TAG, "[ZCodeBroadcast] $it") },
        )
        try {
            newServer.start(host, ZCodeBroadcast.DEFAULT_PORT)
        } catch (e: Exception) {
            AppLogger.error(TAG, "[ZCodeBroadcast] start failed: ${e.message}")
            _state.value = State.Failed(instanceId, startFailureMessage(e))
            return
        }
        // Publish only if this start is still the wanted one: the user
        // may have switched off (or rebound elsewhere) while we were
        // binding, and a late Running would resurrect a broadcast they
        // just cancelled — with its service already gone.
        val current = _state.value
        if (current is State.Starting && current.instanceId == instanceId) {
            server = newServer
            val port = newServer.boundAddress?.port ?: ZCodeBroadcast.DEFAULT_PORT
            AppLogger.info(TAG, "[ZCodeBroadcast] listening on $host:$port")
            _state.value = State.Running(instanceId, host, port, allowLan)
        } else {
            newServer.stop()
        }
    }

    /**
     * The per-request upstream identity for the bound instance: the
     * stored JWT (null → the server answers the not-logged-in error),
     * plus the same static + identity header set [ZCodeProvider]
     * sends — this phone's real values, via the manager.
     */
    private suspend fun buildSession(
        manager: ZCodeOAuthManager,
    ): ZCodeBroadcastServer.Session? {
        val jwt = manager.validAccessToken() ?: return null
        val headers = linkedMapOf(
            "User-Agent" to "ZCode/${ZCodeConstants.appVersion()}",
            "X-ZCode-App-Version" to ZCodeConstants.appVersion(),
            "X-ZCode-Agent" to "glm",
            "HTTP-Referer" to "https://zcode.z.ai",
            "X-Title" to "Z Code@electron",
            "X-Release-Channel" to "production",
        )
        headers.putAll(ZCodeOAuthManager.currentIdentityHeaders(manager.deviceMid()))
        return ZCodeBroadcastServer.Session(
            jwt = jwt,
            userId = ZCodeOAuthManager.jwtUserId(jwt),
            baseHeaders = headers,
        )
    }

    private fun startFailureMessage(e: Exception): String = when (e) {
        is java.net.BindException ->
            "端口 ${ZCodeBroadcast.DEFAULT_PORT} 已被占用，广播启动失败。"
        else -> "广播启动失败：${e.message ?: e.javaClass.simpleName}"
    }

    private fun stopServer() {
        server?.stop()
        server = null
    }

    /**
     * startForeground was refused (background-start restrictions):
     * the broadcast cannot run, and the console must say why rather
     * than silently flipping the switch back off.
     */
    internal fun onForegroundRefused() {
        stopServer()
        val instanceId = when (val current = _state.value) {
            is State.Starting -> current.instanceId
            is State.Running -> current.instanceId
            is State.Failed -> current.instanceId
            is State.Stopped -> null
        }
        _state.value = if (instanceId != null) {
            State.Failed(instanceId, "广播启动失败：系统拒绝前台服务。")
        } else {
            State.Stopped
        }
    }

    /**
     * The service went away without a stop request (system timeout,
     * process pressure): the server must not outlive the foreground
     * service that keeps this process schedulable. A [State.Failed]
     * is kept — it is the message the console is showing.
     */
    internal fun onServiceGone() {
        stopServer()
        if (_state.value !is State.Failed) {
            _state.value = State.Stopped
        }
    }
}

/**
 * The production upstream transport: one OkHttp POST with the
 * provider's timeouts (30 s connect, 10 min read — long streams are
 * the norm), the response body handed to the server as a stream.
 * Deliberately NOT routed through NetworkHttp's per-provider routes:
 * those are keyed by chat-provider instance tags, and the broadcast
 * is a device-local endpoint, not a chat provider.
 */
private class OkHttpBroadcastUpstream : ZCodeBroadcastServer.Upstream {

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.MINUTES)
        .writeTimeout(30, TimeUnit.SECONDS)
        .connectionPool(com.openminis.app.network.NetworkMonitor.sharedLLMConnectionPool)
        .build()

    override fun post(
        url: String,
        body: ByteArray,
        headers: Map<String, String>,
    ): ZCodeBroadcastServer.Upstream.Response {
        val builder = Request.Builder()
            .url(url)
            .post(body.toRequestBody("application/json".toMediaType()))
        for ((name, value) in headers) builder.header(name, value)
        val response = client.newCall(builder.build()).execute()
        val relayed = linkedMapOf<String, String>()
        for (name in listOf("Cache-Control", "Retry-After", "x-aliyun-captcha-verify-param")) {
            response.header(name)?.let { relayed[name.lowercase()] = it }
        }
        return ZCodeBroadcastServer.Upstream.Response(
            status = response.code,
            contentType = response.header("Content-Type"),
            headers = relayed,
            body = response.body?.byteStream() ?: ByteArrayInputStream(ByteArray(0)),
            closer = { response.close() },
        )
    }
}

/**
 * [T-zcode-broadcast] Foreground-service shell for the broadcast.
 *
 * Type `specialUse`, not the backup service's `dataSync`: dataSync
 * carries a cumulative time budget (6 h / 24 h on Android 15) after
 * which the system times the service out — right for a finite backup,
 * wrong for a user-toggled endpoint that stays on until switched off.
 * A local API endpoint for other apps on the device matches none of
 * the typed categories, which is exactly what specialUse exists for;
 * the manifest declares the required subtype property. There is no
 * boot receiver and no restart stickiness: process death ends the
 * broadcast, by design.
 */
class ZCodeBroadcastService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var observing = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            AppLogger.info(TAG, "[ZCodeBroadcast] stop requested from notification")
            ZCodeBroadcastController.requestStop()
            return START_NOT_STICKY
        }
        // startForegroundService() must be answered within ~5 s — do it
        // before anything else, with the best text known so far.
        goForeground(notificationText(ZCodeBroadcastController.state.value))
        val instanceId = intent?.getStringExtra(EXTRA_INSTANCE_ID)
        val allowLan = intent?.getBooleanExtra(EXTRA_ALLOW_LAN, false) ?: false
        if (instanceId != null) {
            // Binding is a blocking syscall on a literal address —
            // quick, but keep it off the main thread anyway.
            scope.launch {
                withContext(Dispatchers.IO) {
                    ZCodeBroadcastController.beginServer(applicationContext, instanceId, allowLan)
                }
            }
        }
        if (!observing) {
            observing = true
            observeState()
        }
        return START_NOT_STICKY
    }

    private fun observeState() {
        scope.launch {
            ZCodeBroadcastController.state.collect { state ->
                when (state) {
                    is ZCodeBroadcastController.State.Running ->
                        updateNotification(notificationText(state))
                    is ZCodeBroadcastController.State.Stopped,
                    is ZCodeBroadcastController.State.Failed,
                    -> {
                        stopForegroundCompat()
                        stopSelf()
                    }
                    is ZCodeBroadcastController.State.Starting -> Unit
                }
            }
        }
    }

    private fun notificationText(state: ZCodeBroadcastController.State): String =
        when (state) {
            is ZCodeBroadcastController.State.Running ->
                if (state.allowLan) {
                    "${state.host}:${state.port} · 局域网可访问"
                } else {
                    "${state.host}:${state.port}"
                }
            else -> "${ZCodeBroadcast.LOOPBACK_HOST}:${ZCodeBroadcast.DEFAULT_PORT}"
        }

    private fun goForeground(text: String) {
        ensureChannel(this)
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    buildNotification(text),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } else {
                startForeground(NOTIFICATION_ID, buildNotification(text))
            }
        }.onFailure {
            AppLogger.error(TAG, "[ZCodeBroadcast] startForeground refused: ${it.message}")
            ZCodeBroadcastController.onForegroundRefused()
            stopSelf()
        }
    }

    private fun updateNotification(text: String) {
        runCatching {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION_ID, buildNotification(text))
        }
    }

    private fun buildNotification(text: String): Notification {
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, ZCodeBroadcastService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle(getString(R.string.zcode_broadcast_notif_title))
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openAppIntent())
            .addAction(0, getString(R.string.zcode_broadcast_stop), stop)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun openAppIntent(): PendingIntent? {
        val launch = packageManager.getLaunchIntentForPackage(packageName) ?: return null
        return PendingIntent.getActivity(this, 0, launch, PendingIntent.FLAG_IMMUTABLE)
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    /**
     * If the system ever times this service out, stop the broadcast
     * with it — a server without its foreground service is a server
     * the freezer will kill mid-stream anyway.
     */
    override fun onTimeout(startId: Int, fgsType: Int) {
        AppLogger.warning(TAG, "[ZCodeBroadcast] foreground service timed out — stopping broadcast")
        ZCodeBroadcastController.requestStop()
        stopForegroundCompat()
        stopSelf()
    }

    @Deprecated("Replaced by onTimeout(Int, Int) on API 35")
    override fun onTimeout(startId: Int) = onTimeout(startId, 0)

    override fun onDestroy() {
        ZCodeBroadcastController.onServiceGone()
        scope.cancel()
        observing = false
        super.onDestroy()
    }

    companion object {
        private const val TAG = "ZCodeBroadcastService"
        const val CHANNEL_ID = "zcode_broadcast"
        private const val NOTIFICATION_ID = 4301
        private const val ACTION_STOP = "com.openminis.app.zcode.broadcast.STOP"
        private const val EXTRA_INSTANCE_ID = "instance_id"
        private const val EXTRA_ALLOW_LAN = "allow_lan"

        /** Called from the console switch (a user action). Returns
         *  false when the start was refused, so the controller can
         *  surface it instead of the switch hanging in Starting. */
        fun start(context: Context, instanceId: String, allowLan: Boolean): Boolean {
            return runCatching {
                val intent = Intent(context, ZCodeBroadcastService::class.java).apply {
                    putExtra(EXTRA_INSTANCE_ID, instanceId)
                    putExtra(EXTRA_ALLOW_LAN, allowLan)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
                true
            }.onFailure {
                AppLogger.error(TAG, "[ZCodeBroadcast] could not start: ${it.message}")
            }.getOrDefault(false)
        }

        fun ensureChannel(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
            val nm = context.getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL_ID) != null) return
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.zcode_broadcast_notif_channel),
                    // LOW: persistent but silent — a status, not an alert.
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
    }
}
