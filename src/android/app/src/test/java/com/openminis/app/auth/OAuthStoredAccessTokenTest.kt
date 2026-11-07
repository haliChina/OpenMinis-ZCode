package com.openminis.app.auth

import android.content.Context
import android.content.SharedPreferences
import com.openminis.app.util.EncryptedPrefsFactory
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * [T-zcode-list-mask] storedAccessToken(): the provider list row masks
 * whatever credential the instance has. ZCode's JWT lives only in the
 * OAuth blob, never in the api-key slot, so the row reads it from here —
 * manual bearer first, then the blob's access_token, null when neither
 * is present. Pure prefs reads: no refresh, no network.
 */
@RunWith(RobolectricTestRunner::class)
class OAuthStoredAccessTokenTest {

    private val ctx: Context get() = RuntimeEnvironment.getApplication()
    private lateinit var prefs: SharedPreferences

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
    fun `manual bearer wins over the stored blob`() {
        val manager = ZCodeOAuthManager(ctx, "stored-token-manual")
        manager.saveManualBearerToken("manual-aaa")
        manager.importStoredTokensJson("""{"access_token":"stored-bbb","expire_at":0}""")
        assertEquals("manual-aaa", manager.storedAccessToken())
    }

    @Test
    fun `stored token when no manual bearer is set`() {
        val manager = ZCodeOAuthManager(ctx, "stored-token-blob")
        manager.importStoredTokensJson("""{"access_token":"stored-ccc","expire_at":0}""")
        assertEquals("stored-ccc", manager.storedAccessToken())
    }

    @Test
    fun `nothing stored returns null`() {
        assertNull(ZCodeOAuthManager(ctx, "stored-token-none").storedAccessToken())
    }

    @Test
    fun `empty access_token in the blob returns null`() {
        val manager = ZCodeOAuthManager(ctx, "stored-token-empty")
        manager.importStoredTokensJson("""{"access_token":"","expire_at":0}""")
        assertNull(manager.storedAccessToken())
    }

    @Test
    fun `empty manual bearer falls through to the stored token`() {
        val manager = ZCodeOAuthManager(ctx, "stored-token-empty-manual")
        manager.saveManualBearerToken("")
        manager.importStoredTokensJson("""{"access_token":"stored-ddd","expire_at":0}""")
        assertEquals("stored-ddd", manager.storedAccessToken())
    }

    @Test
    fun `blob without an access_token key returns null`() {
        val manager = ZCodeOAuthManager(ctx, "stored-token-no-key")
        manager.importStoredTokensJson("""{"refresh_token":"rrr","expire_at":0}""")
        assertNull(manager.storedAccessToken())
    }
}
