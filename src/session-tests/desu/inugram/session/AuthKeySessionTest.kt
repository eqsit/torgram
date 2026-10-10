package desu.inugram.session

import desu.inugram.core.session.AuthKeyCodec
import desu.inugram.helpers.security.AuthKeySessionHelper
import desu.inugram.helpers.security.AuthKeySessionNative
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.telegram.messenger.ApplicationLoader
import org.telegram.messenger.UserConfig
import org.telegram.tgnet.TLRPC
import org.telegram.tgnet.ConnectionsManager
import androidx.test.platform.app.InstrumentationRegistry
import android.accounts.AccountManager
import android.content.ContentResolver
import android.content.Context
import android.widget.FrameLayout
import androidx.recyclerview.widget.RecyclerView
import org.telegram.messenger.LocaleController
import org.telegram.messenger.R
import org.telegram.ui.ActionBar.ActionBar
import org.telegram.ui.Cells.TextSettingsCell
import org.telegram.ui.LogoutActivity
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Uses synthetic keys in an unused debug-only account slot, with networking offline. */
class AuthKeySessionTest {
    private val account = UserConfig.MAX_ACCOUNT_COUNT - 1
    private val key = ByteArray(256) { it.toByte() }
    private var ownsTestSlot = false
    private var syntheticUserAdded = false

    @Before fun prepare_an_unused_offline_slot() {
        assertEquals("desu.inugram.debug", ApplicationLoader.applicationContext.packageName)
        assertFalse(UserConfig.getInstance(account).isClientActivated)
        ownsTestSlot = true
        ConnectionsManager.getInstance(account)
        ConnectionsManager.native_setNetworkAvailable(account, false, 0, false)
        ConnectionsManager.native_setUserId(account, 0)
        AuthKeySessionNative.discardImport(account)
        assertEquals(1, result { AuthKeySessionNative.exportSession(account, it) }.error)
    }

    @After fun discard_the_synthetic_key_without_a_server_logout() {
        if (!ownsTestSlot) return
        if (syntheticUserAdded) {
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                val config = UserConfig.getInstance(account)
                if (config.clientUserId == 1L) {
                    config.setCurrentUser(null)
                    config.saveConfig(true)
                }
            }
        }
        ConnectionsManager.native_setUserId(account, 0)
        AuthKeySessionNative.discardImport(account)
        assertEquals(1, result { AuthKeySessionNative.exportSession(account, it) }.error)
    }

    @Test fun imported_desktop_bytes_dc_and_fingerprint_survive_native_export() {
        assertEquals(0, result { AuthKeySessionNative.importSession(account, 2, false, key, it) }.error)
        ConnectionsManager.native_setUserId(account, 1)
        val exported = result { AuthKeySessionNative.exportSession(account, it) }
        assertEquals(0, exported.error)
        assertEquals(2, exported.dcId)
        assertFalse(exported.testBackend)
        assertArrayEquals(key, exported.key)
        assertEquals(AuthKeyCodec.keyId(key), ConnectionsManager.native_getCurrentAuthKeyId(account))
        exported.key?.fill(0)
    }

    @Test fun an_active_slot_cannot_have_its_key_replaced() {
        assertEquals(0, result { AuthKeySessionNative.importSession(account, 2, false, key, it) }.error)
        ConnectionsManager.native_setUserId(account, 1)
        assertEquals(3, result { AuthKeySessionNative.importSession(account, 3, false, ByteArray(256) { 1 }, it) }.error)
        val exported = result { AuthKeySessionNative.exportSession(account, it) }
        assertEquals(2, exported.dcId)
        assertArrayEquals(key, exported.key)
        exported.key?.fill(0)
    }

    @Test fun native_import_rejects_invalid_lengths_zero_keys_dc_and_backend() {
        for (invalid in listOf(ByteArray(16), ByteArray(255) { 1 }, ByteArray(257) { 1 }, ByteArray(256))) {
            assertEquals(2, result { AuthKeySessionNative.importSession(account, 2, false, invalid, it) }.error)
        }
        assertEquals(2, result { AuthKeySessionNative.importSession(account, 6, false, key, it) }.error)
        assertEquals(2, result { AuthKeySessionNative.importSession(account, 2, true, key, it) }.error)
    }

    @Test fun discarding_a_pending_import_removes_only_local_credentials() {
        assertEquals(0, result { AuthKeySessionNative.importSession(account, 2, false, key, it) }.error)
        AuthKeySessionNative.discardImport(account)
        assertEquals(1, result { AuthKeySessionNative.exportSession(account, it) }.error)
        assertEquals(0, ConnectionsManager.native_getCurrentAuthKeyId(account))
    }

    @Test fun local_logout_removes_the_account_and_keys_and_keeps_an_export_reimportable() {
        val selectedAccount = UserConfig.selectedAccount
        assertEquals(0, result { AuthKeySessionNative.importSession(account, 2, false, key, it) }.error)
        ConnectionsManager.native_setUserId(account, 1)
        val exported = result { AuthKeySessionNative.exportSession(account, it) }
        assertEquals(0, exported.error)
        // Stock clears global settings when the last account leaves. Keep a memory-only
        // sentinel if there are no real accounts, so the test preserves the user's settings.
        val sentinel = if ((0 until UserConfig.MAX_ACCOUNT_COUNT).none {
                UserConfig.getInstance(it).isClientActivated
            }) UserConfig.MAX_ACCOUNT_COUNT - 2 else null
        try {
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                sentinel?.let {
                    UserConfig.getInstance(it).setCurrentUser(TLRPC.TL_user().apply { id = 2; self = true })
                }
                UserConfig.getInstance(account).setCurrentUser(TLRPC.TL_user().apply {
                    id = 1
                    self = true
                    first_name = "Synthetic session"
                })
                syntheticUserAdded = true
                AuthKeySessionHelper.performLocalLogout(account)
            }
        } finally {
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                sentinel?.let { UserConfig.getInstance(it).setCurrentUser(null) }
            }
        }
        assertFalse(UserConfig.getInstance(account).isClientActivated)
        assertNull(UserConfig.getInstance(account).currentUser)
        assertEquals(selectedAccount, UserConfig.selectedAccount)
        assertEquals(1, result { AuthKeySessionNative.exportSession(account, it) }.error)
        // The normal server-logout branch retains the key while waiting for an RPC response;
        // this asserts that local-only cleanup actually ran with the offline native manager.
        assertEquals(0, ConnectionsManager.native_getCurrentAuthKeyId(account))
        assertArrayEquals(key, exported.key)
        assertEquals(0, result { AuthKeySessionNative.importSession(account, exported.dcId, exported.testBackend, exported.key!!, it) }.error)
        assertEquals(AuthKeyCodec.keyId(key), ConnectionsManager.native_getCurrentAuthKeyId(account))
        exported.key?.fill(0)
    }

    @Test fun the_debug_system_account_and_contact_sync_are_registered_under_their_own_type() {
        val context = ApplicationLoader.applicationContext
        val description = AccountManager.get(context).authenticatorTypes.single { it.type == context.packageName }
        assertEquals(context.packageName, description.packageName)
        assertTrue(ContentResolver.getSyncAdapterTypes().any {
            it.accountType == context.packageName && it.authority == "com.android.contacts"
        })
    }

    @Test fun the_logout_page_keeps_normal_logout_first_and_local_logout_immediately_after_it() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            val context = ApplicationLoader.applicationContext
            val fragment = DetachedLogoutActivity()
            fragment.setCurrentAccount(account)
            fragment.onFragmentCreate()
            fragment.attachActionBar(context)
            try {
                val root = fragment.createView(context) as FrameLayout
                val list = root.getChildAt(0) as RecyclerView
                @Suppress("UNCHECKED_CAST")
                val adapter = list.adapter as RecyclerView.Adapter<RecyclerView.ViewHolder>
                val labels = ArrayList<String>()
                for (position in 0 until adapter.itemCount) {
                    val holder = adapter.createViewHolder(root, adapter.getItemViewType(position))
                    adapter.bindViewHolder(holder, position)
                    (holder.itemView as? TextSettingsCell)?.let { labels.add(it.textView.text.toString()) }
                }
                assertEquals(listOf(LocaleController.getString(R.string.LogOutTitle),
                    LocaleController.getString(R.string.InuSessionLocalLogout)), labels)
            } finally { fragment.onFragmentDestroy() }
        }
    }

    private class DetachedLogoutActivity : LogoutActivity() {
        fun attachActionBar(context: Context) { actionBar = ActionBar(context) }
    }

    @Test fun a_session_file_restores_its_key_dc_and_backend() {
        val original = AuthKeySessionHelper.Credentials(key.clone(), 4, false)
        val bytes = AuthKeySessionHelper.encodeFile(original)
        val restored = AuthKeySessionHelper.parseInput(bytes.toString(Charsets.UTF_8), 0, false)
        assertEquals(4, restored.dcId)
        assertFalse(restored.testBackend)
        assertArrayEquals(key, restored.key)
        assertFalse(restored.toString().contains(AuthKeyCodec.encode(key)))
        original.clear()
        restored.clear()
        bytes.fill(0)
    }

    @Test fun file_metadata_must_use_supported_types_and_version() {
        val valid = AuthKeySessionHelper.encodeFile(AuthKeySessionHelper.Credentials(key, 2, false)).toString(Charsets.UTF_8)
        for ((from, to) in listOf("\"version\": 1" to "\"version\": 1.5",
                "\"version\": 1" to "\"version\": 2",
                "\"dc_id\": 2" to "\"dc_id\": 2.5",
                "\"test_backend\": false" to "\"test_backend\": \"false\"",
                "inugram.session" to "inugram.settings")) {
            assertThrows(Exception::class.java) { AuthKeySessionHelper.parseInput(valid.replace(from, to), 0, false) }
        }
    }

    @Test fun plain_hex_needs_a_dc_and_a_short_hash_is_rejected() {
        assertThrows(Exception::class.java) { AuthKeySessionHelper.parseInput(AuthKeyCodec.encode(key), 0, false) }
        assertThrows(Exception::class.java) { AuthKeySessionHelper.parseInput("0123456789abcdef", 2, false) }
        val restored = AuthKeySessionHelper.parseInput(AuthKeyCodec.encode(key), 5, false)
        assertEquals(5, restored.dcId)
        assertArrayEquals(key, restored.key)
        restored.clear()
    }

    private class Result(val dcId: Int, val testBackend: Boolean, val key: ByteArray?, val error: Int)
    private fun result(action: (AuthKeySessionNative.Callback) -> Unit): Result {
        val latch = CountDownLatch(1)
        var response: Result? = null
        action(AuthKeySessionNative.Callback { dc, test, bytes, error ->
            response = Result(dc, test, bytes, error)
            latch.countDown()
        })
        assertTrue("Native callback timed out", latch.await(10, TimeUnit.SECONDS))
        return response!!
    }
}
