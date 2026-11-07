package com.openminis.app.auth

import android.content.Context
import android.content.SharedPreferences
import com.openminis.app.util.EncryptedPrefsFactory
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * [T-zcode-provider] The stable device id: generated once, persisted in
 * EncryptedPrefs, and the SAME value on every later call — billing
 * 400s with 3001 when X-Device-Mid is missing, so a fresh id per
 * request would not do. Mirrors the CodexAccountIdRefreshTest setup:
 * the OAuth store is a plain prefs file because AndroidKeyStore does
 * not exist on the JVM.
 */
@RunWith(RobolectricTestRunner::class)
class ZCodeDeviceMidTest {

    private val ctx: Context get() = RuntimeEnvironment.getApplication()
    private lateinit var prefs: SharedPreferences
    private val instanceId = "zcode-device-mid-test"

    private val uuid = Regex(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    )

    @Before
    fun setUp() {
        EncryptedPrefsFactory.resetCacheForTest()
        prefs = ctx.getSharedPreferences("oauth_prefs_test", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        EncryptedPrefsFactory.cached("oauth_prefs") { prefs }
    }

    @After
    fun tearDown() = EncryptedPrefsFactory.resetCacheForTest()

    @Test
    fun `device mid is generated once and reused`() {
        val manager = ZCodeOAuthManager(ctx, instanceId)
        val first = manager.deviceMid()
        assertTrue("a uuid", uuid.matches(first))
        assertEquals("persisted under the device-mid key", first, prefs.getString("oauth_${ZCodeOAuthManager.KEY_DEVICE_MID}_$instanceId", null))
        // Same manager, same value; a fresh manager on the same
        // instance reads the persisted one instead of generating.
        assertEquals(first, manager.deviceMid())
        assertEquals(first, ZCodeOAuthManager(ctx, instanceId).deviceMid())
    }

    @Test
    fun `a blank stored value regenerates instead of being reused`() {
        prefs.edit()
            .putString("oauth_${ZCodeOAuthManager.KEY_DEVICE_MID}_$instanceId", "   ")
            .commit()
        val fresh = ZCodeOAuthManager(ctx, instanceId).deviceMid()
        assertTrue("a uuid", uuid.matches(fresh))
        assertNotEquals("   ", fresh)
    }

    @Test
    fun `different instances get different device ids`() {
        val a = ZCodeOAuthManager(ctx, "zcode-instance-a").deviceMid()
        val b = ZCodeOAuthManager(ctx, "zcode-instance-b").deviceMid()
        assertNotEquals(a, b)
    }
}
