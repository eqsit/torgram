package desu.inugram.helpers.security

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PersistableBundle
import android.view.View
import desu.inugram.InuConfig
import desu.inugram.core.session.AuthKeyCodec
import org.json.JSONObject
import org.telegram.messenger.AndroidUtilities
import org.telegram.messenger.LocaleController.getString
import org.telegram.messenger.MessagesController
import org.telegram.messenger.R
import org.telegram.messenger.UserConfig
import org.telegram.messenger.UserObject
import org.telegram.messenger.Utilities
import org.telegram.tgnet.ConnectionsManager
import org.telegram.ui.ActionBar.AlertDialog
import org.telegram.ui.ActionBar.ActionBarMenuItem
import org.telegram.ui.ActionBar.BaseFragment
import org.telegram.ui.Components.BulletinFactory
import org.telegram.ui.LoginActivity
import java.util.WeakHashMap

object AuthKeySessionHelper {
    const val LOCAL_LOGOUT_ACTION = 31033
    internal const val IMPORT_FILE = 31031
    private const val EXPORT_FILE = 31032
    private const val FORMAT = "inugram.session"
    private val imports = WeakHashMap<LoginActivity, AuthKeyImportDialog>()
    private val exports = WeakHashMap<BaseFragment, Credentials>()

    // Never store a key in InuConfig, saved fragment arguments, logs, or settings backups.
    class Credentials(val key: ByteArray, val dcId: Int, val testBackend: Boolean) {
        fun clear() = key.fill(0)
        override fun toString() = "Session credentials (redacted)"
    }

    fun openImport(fragment: BaseFragment) {
        if (!InuConfig.AUTH_KEY_SESSION_TRANSFER.value) return
        val account = (0 until UserConfig.MAX_ACCOUNT_COUNT).firstOrNull {
            !UserConfig.getInstance(it).isClientActivated
        }
        if (account == null) {
            error(fragment, getString(R.string.InuSessionNoFreeAccount))
            return
        }
        val login = LoginActivity(account)
        login.inu_importAuthKey = true
        fragment.presentFragment(login)
    }

    @JvmStatic fun showImport(login: LoginActivity, account: Int) {
        if (!InuConfig.AUTH_KEY_SESSION_TRANSFER.value || login.parentActivity == null) return
        if (UserConfig.getInstance(account).isClientActivated) {
            error(login, getString(R.string.InuSessionAccountOccupied))
            return
        }
        imports.remove(login)?.close()
        val state = AuthKeyImportDialog(login, account) { imports.remove(login) }
        imports[login] = state
        state.show()
    }

    @JvmStatic fun onLoginDestroyed(login: LoginActivity) {
        imports.remove(login)?.close()
    }

    @JvmStatic fun keepsDialogOnPause(login: LoginActivity, dialog: android.app.Dialog): Boolean =
        imports[login]?.keepsDialogOnPause(dialog) == true

    @JvmStatic fun showLocalLogout(fragment: BaseFragment) {
        if (!InuConfig.AUTH_KEY_SESSION_TRANSFER.value) return
        val context = fragment.parentActivity ?: return
        fragment.showDialog(createLocalLogoutDialog(context, fragment.currentAccount))
    }

    @JvmStatic fun addLocalLogoutMenu(menu: ActionBarMenuItem) {
        if (InuConfig.AUTH_KEY_SESSION_TRANSFER.value) {
            menu.addSubItem(LOCAL_LOGOUT_ACTION, R.drawable.msg_leave, getString(R.string.InuSessionLocalLogout))
        }
    }

    @JvmStatic fun handleLocalLogoutClick(fragment: BaseFragment, id: Int): Boolean {
        if (id != LOCAL_LOGOUT_ACTION || !InuConfig.AUTH_KEY_SESSION_TRANSFER.value) return false
        showLocalLogout(fragment)
        return true
    }

    @JvmStatic fun setLocalLogoutVisible(menu: ActionBarMenuItem, visible: Boolean) {
        if (!menu.hasSubItem(LOCAL_LOGOUT_ACTION)) return
        if (visible) menu.showSubItem(LOCAL_LOGOUT_ACTION) else menu.hideSubItem(LOCAL_LOGOUT_ACTION)
    }

    @JvmStatic fun createLocalLogoutDialog(context: Context, account: Int): AlertDialog {
        val expectedUserId = UserConfig.getInstance(account).clientUserId
        val dialog = AlertDialog.Builder(context)
            .setTitle(getString(R.string.InuSessionLocalLogout))
            .setMessage(getString(R.string.InuSessionLocalLogoutConfirm))
            .setPositiveButton(getString(R.string.InuSessionLocalLogout)) { _, _ ->
                BiometricHelper.gate(context, InuConfig.BIOMETRIC_CONFIRM_LOGOUT.value) {
                    if (expectedUserId != 0L && UserConfig.getInstance(account).clientUserId == expectedUserId) {
                        performLocalLogout(account)
                    }
                }
            }
            .setNegativeButton(getString(R.string.Cancel), null).create()
        (dialog.getButton(android.app.Dialog.BUTTON_POSITIVE) as? android.widget.TextView)
            ?.setTextColor(org.telegram.ui.ActionBar.Theme.getColor(org.telegram.ui.ActionBar.Theme.key_text_RedBold))
        return dialog
    }

    fun performLocalLogout(account: Int) {
        if (!InuConfig.AUTH_KEY_SESSION_TRANSFER.value || !UserConfig.getInstance(account).isClientActivated) return
        // Stock type 2 clears keys/storage and switches accounts locally, without auth.logOut.
        MessagesController.getInstance(account).performLogout(2)
    }

    fun showExport(fragment: BaseFragment) {
        if (!InuConfig.AUTH_KEY_SESSION_TRANSFER.value) return
        val accounts = (0 until UserConfig.MAX_ACCOUNT_COUNT).filter {
            UserConfig.getInstance(it).isClientActivated
        }
        if (accounts.isEmpty()) {
            error(fragment, getString(R.string.InuSessionNoAccount))
            return
        }
        if (accounts.size == 1) exportAccount(fragment, accounts[0])
        else {
            val names = accounts.map { UserObject.getUserName(UserConfig.getInstance(it).currentUser) }.toTypedArray()
            fragment.showDialog(AlertDialog.Builder(fragment.parentActivity, fragment.resourceProvider)
                .setTitle(getString(R.string.InuSessionChooseAccount))
                .setItems(names) { _, index -> exportAccount(fragment, accounts[index]) }
                .setNegativeButton(getString(R.string.Cancel), null).create())
        }
    }

    private fun exportAccount(fragment: BaseFragment, account: Int) {
        ConnectionsManager.getInstance(account) // ensure native account initialization
        AuthKeySessionNative.exportSession(account) { dcId, test, key, code ->
            AndroidUtilities.runOnUIThread {
                if (fragment.parentActivity == null) {
                    key?.fill(0)
                    return@runOnUIThread
                }
                if (code != 0 || key == null) {
                    key?.fill(0)
                    error(fragment, getString(R.string.InuSessionExportError))
                    return@runOnUIThread
                }
                val credentials = Credentials(key, dcId, test)
                var saving = false
                val name = UserObject.getUserName(UserConfig.getInstance(account).currentUser)
                val message = "$name · DC $dcId\n\n${getString(R.string.InuSessionExportInfo)}"
                val dialog = AlertDialog.Builder(fragment.parentActivity, fragment.resourceProvider)
                    .setTitle(getString(R.string.InuSessionExport))
                    .setMessage(message)
                    .setPositiveButton(getString(R.string.InuSessionCopyHex)) { _, _ ->
                        copyKey(fragment, credentials)
                    }
                    .setNeutralButton(getString(R.string.InuSessionSaveFile)) { _, _ ->
                        releaseExport(fragment)
                        exports[fragment] = credentials
                        saving = true
                        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                            addCategory(Intent.CATEGORY_OPENABLE)
                            type = "application/json"
                            putExtra(Intent.EXTRA_TITLE, "inugram-session-dc$dcId.json")
                        }
                        try {
                            fragment.startActivityForResult(intent, EXPORT_FILE)
                        } catch (_: Exception) {
                            releaseExport(fragment)
                            error(fragment, getString(R.string.InuSessionFileError))
                        }
                    }
                    .setNegativeButton(getString(R.string.Cancel), null).create()
                if (fragment.showDialog(dialog) { if (!saving) credentials.clear() } == null) credentials.clear()
            }
        }
    }

    private fun copyKey(fragment: BaseFragment, credentials: Credentials) {
        val context = fragment.parentActivity ?: return
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val hex = AuthKeyCodec.encode(credentials.key)
        val clip = ClipData.newPlainText("auth key hex · DC ${credentials.dcId}", hex)
        if (Build.VERSION.SDK_INT >= 24) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
        }
        clipboard.setPrimaryClip(clip)
        AndroidUtilities.runOnUIThread({
            try {
                if (clipboard.primaryClip?.getItemAt(0)?.text?.toString() == hex) {
                    if (Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip()
                    else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            } catch (_: Exception) { }
        }, 60_000)
        BulletinFactory.of(fragment).createSimpleBulletin(R.raw.copy, getString(R.string.InuSessionCopied)).show()
    }

    fun parseInput(text: String, dcId: Int, test: Boolean): Credentials {
        if (text.length > AuthKeyCodec.MAX_INPUT_SIZE) throw AuthKeyCodec.InvalidKey(AuthKeyCodec.Error.LENGTH)
        if (!text.trimStart().startsWith("{")) {
            AuthKeyCodec.validateDc(dcId, test)
            return Credentials(AuthKeyCodec.decode(text), dcId, test)
        }
        val root = JSONObject(text)
        require(root.getString("format") == FORMAT && root.get("version") == 1) { "Unsupported session format" }
        val rawDc = root.get("dc_id")
        require(rawDc is Int) { "Invalid data center" }
        val backend = root.get("test_backend")
        require(backend is Boolean) { "Invalid backend" }
        AuthKeyCodec.validateDc(rawDc, backend)
        return Credentials(AuthKeyCodec.decode(root.getString("auth_key_hex")), rawDc, backend)
    }

    fun encodeFile(credentials: Credentials): ByteArray = JSONObject().apply {
        put("format", FORMAT)
        put("version", 1)
        put("dc_id", credentials.dcId)
        put("test_backend", credentials.testBackend)
        put("auth_key_hex", AuthKeyCodec.encode(credentials.key))
    }.toString(2).toByteArray(Charsets.UTF_8)

    @JvmStatic fun onActivityResult(fragment: BaseFragment, request: Int, result: Int, data: Intent?): Boolean {
        if (request == IMPORT_FILE && fragment is LoginActivity) {
            imports[fragment]?.onFileResult(result, data)
            return true
        }
        if (request != EXPORT_FILE) return false
        val credentials = exports.remove(fragment) ?: return true
        val context = fragment.parentActivity
        val uri = data?.data
        if (result != Activity.RESULT_OK || context == null || uri == null) {
            credentials.clear()
            return true
        }
        Utilities.globalQueue.postRunnable {
            var bytes: ByteArray? = null
            val success = try {
                bytes = encodeFile(credentials)
                context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } != null
            } catch (_: Exception) { false }
            finally { bytes?.fill(0); credentials.clear() }
            AndroidUtilities.runOnUIThread {
                if (fragment.parentActivity != null) {
                    if (success) BulletinFactory.of(fragment).createSimpleBulletin(R.raw.contact_check, getString(R.string.InuSessionSaved)).show()
                    else error(fragment, getString(R.string.InuSessionFileError))
                }
            }
        }
        return true
    }

    fun releaseExport(fragment: BaseFragment) { exports.remove(fragment)?.clear() }

    internal fun error(fragment: BaseFragment, message: String) {
        if (fragment.parentActivity != null) BulletinFactory.of(fragment).createErrorBulletin(message).show()
    }
}
