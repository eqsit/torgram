package desu.inugram.helpers.security

import android.app.Activity
import android.app.Dialog
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.text.InputFilter
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import desu.inugram.core.session.AuthKeyCodec
import org.telegram.messenger.AndroidUtilities
import org.telegram.messenger.LocaleController.getString
import org.telegram.messenger.R
import org.telegram.messenger.UserConfig
import org.telegram.messenger.Utilities
import org.telegram.tgnet.ConnectionsManager
import org.telegram.tgnet.TLRPC
import org.telegram.tgnet.Vector
import org.telegram.ui.ActionBar.AlertDialog
import org.telegram.ui.ActionBar.Theme
import org.telegram.ui.Components.EditTextBoldCursor
import org.telegram.ui.Components.LayoutHelper
import org.telegram.ui.LaunchActivity
import org.telegram.ui.LoginActivity

internal class AuthKeyImportDialog(
    private val login: LoginActivity,
    private val account: Int,
    private val onClosed: () -> Unit,
) {
    private lateinit var dialog: AlertDialog
    private lateinit var keyField: EditTextBoldCursor
    private lateinit var dcButton: TextView
    private lateinit var fileButton: TextView
    private lateinit var visibilityButton: TextView
    private lateinit var status: TextView
    private var dcId = 0
    private var busy = false
    private var staged = false
    private var closed = false
    private var generation = 0
    private var requestId = 0
    private var pickingFile = false
    private var timeout: Runnable? = null
    private val manager get() = ConnectionsManager.getInstance(account)

    fun show() {
        val context = login.parentActivity ?: return
        val content = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(4), dp(24), dp(8))
        }
        content.addView(label(context, getString(R.string.InuSessionImportInfo), 14f))
        keyField = EditTextBoldCursor(context).apply {
            setTextSize(14f)
            typeface = Typeface.MONOSPACE
            setTextColor(Theme.getColor(Theme.key_dialogTextBlack, login.resourceProvider))
            setHintTextColor(Theme.getColor(Theme.key_dialogTextHint, login.resourceProvider))
            hint = getString(R.string.InuSessionKeyHint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI
            transformationMethod = PasswordTransformationMethod.getInstance()
            gravity = Gravity.TOP or Gravity.LEFT
            minLines = 3
            maxLines = 5
            filters = arrayOf(InputFilter.LengthFilter(AuthKeyCodec.MAX_INPUT_SIZE))
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            setBackgroundDrawable(Theme.createEditTextDrawable(context, true))
            setPadding(0, dp(10), 0, dp(10))
        }
        content.addView(keyField, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT, 0f, 12f, 0f, 0f))
        visibilityButton = action(context, getString(R.string.InuSessionShowKey)) {
            val show = keyField.transformationMethod != null
            keyField.transformationMethod = if (show) null else PasswordTransformationMethod.getInstance()
            visibilityButton.text = getString(if (show) R.string.InuSessionHideKey else R.string.InuSessionShowKey)
        }
        content.addView(visibilityButton)
        dcButton = action(context, getString(R.string.InuSessionChooseDc)) {
            val choices = (1..(if (manager.isTestBackend) 3 else 5)).map { "DC $it" }.toTypedArray()
            AlertDialog.Builder(context, login.resourceProvider)
                .setTitle(getString(R.string.InuSessionChooseDc))
                .setItems(choices) { _, index ->
                    dcId = index + 1
                    updateDcLabel()
                }.show()
        }
        content.addView(dcButton)
        fileButton = action(context, getString(R.string.InuSessionOpenFile)) {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
                putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("application/json", "text/plain"))
            }
            pickingFile = true
            try { login.startActivityForResult(intent, AuthKeySessionHelper.IMPORT_FILE) }
            catch (_: Exception) {
                pickingFile = false
                fail(getString(R.string.InuSessionFileError))
            }
        }
        content.addView(fileButton)
        status = label(context, "", 14f)
        status.setTextColor(Theme.getColor(Theme.key_text_RedRegular, login.resourceProvider))
        content.addView(status)
        val scroll = ScrollView(context).apply { addView(content) }
        dialog = AlertDialog.Builder(context, login.resourceProvider)
            .setTitle(getString(R.string.InuSessionLogin))
            .setView(scroll)
            .setPositiveButton(getString(R.string.InuSessionLogin), null)
            .setNegativeButton(getString(R.string.Cancel), null).create()
        if (login.showDialog(dialog) { close() } == null) {
            close()
            return
        }
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        dialog.getButton(Dialog.BUTTON_POSITIVE).setOnClickListener { startImport() }
        dialog.setCanceledOnTouchOutside(false)
    }

    private fun startImport() {
        if (busy || closed) return
        val credentials = try {
            AuthKeySessionHelper.parseInput(keyField.text.toString(), dcId, manager.isTestBackend)
        } catch (error: AuthKeyCodec.InvalidKey) {
            fail(getString(if (error.reason == AuthKeyCodec.Error.DC) R.string.InuSessionDcError else R.string.InuSessionKeyError))
            return
        } catch (_: Exception) {
            fail(getString(R.string.InuSessionFormatError))
            return
        }
        if (credentials.testBackend != manager.isTestBackend) {
            credentials.clear()
            fail(getString(R.string.InuSessionBackendError))
            return
        }
        val fingerprint = AuthKeyCodec.keyId(credentials.key)
        if ((0 until UserConfig.MAX_ACCOUNT_COUNT).any {
                UserConfig.getInstance(it).isClientActivated &&
                    ConnectionsManager.getInstance(it).isTestBackend == credentials.testBackend &&
                    ConnectionsManager.getInstance(it).currentAuthKeyId == fingerprint
            }) {
            credentials.clear()
            fail(getString(R.string.InuSessionAlreadyImported))
            return
        }
        setBusy(true)
        status.text = getString(R.string.InuSessionChecking)
        status.setTextColor(Theme.getColor(Theme.key_dialogTextGray, login.resourceProvider))
        AndroidUtilities.hideKeyboard(keyField)
        val attempt = ++generation
        staged = true
        timeout = Runnable {
            if (!closed && generation == attempt) fail(getString(R.string.InuSessionTimeout))
        }.also { AndroidUtilities.runOnUIThread(it, 45_000) }
        AuthKeySessionNative.importSession(account, credentials.dcId, credentials.testBackend, credentials.key) { _, _, _, error ->
            AndroidUtilities.runOnUIThread {
                if (closed || generation != attempt) return@runOnUIThread
                if (error != 0) {
                    fail(getString(if (error == 3) R.string.InuSessionAccountOccupied else R.string.InuSessionImportError))
                } else fetchSelf(attempt)
            }
        }
        credentials.clear()
    }

    private fun fetchSelf(attempt: Int) {
        val request = TLRPC.TL_users_getUsers().apply { id.add(TLRPC.TL_inputUserSelf()) }
        requestId = manager.sendRequest(request, { response, error ->
            val user = (response as? Vector<*>)?.objects?.firstOrNull() as? TLRPC.User
            AndroidUtilities.runOnUIThread {
                if (closed || generation != attempt) return@runOnUIThread
                requestId = 0
                if (error != null || user == null || user.id == 0L || !user.self) {
                    val message = when (error?.text) {
                        "AUTH_KEY_DUPLICATED" -> getString(R.string.InuSessionDuplicated)
                        "AUTH_KEY_UNREGISTERED", "AUTH_KEY_INVALID", "SESSION_REVOKED", "SESSION_EXPIRED" -> getString(R.string.InuSessionRevoked)
                        else -> getString(R.string.InuSessionImportError)
                    }
                    fail(message)
                    return@runOnUIThread
                }
                timeout?.let(AndroidUtilities::cancelRunOnUIThread)
                timeout = null
                val existing = (0 until UserConfig.MAX_ACCOUNT_COUNT).firstOrNull {
                    UserConfig.getInstance(it).isClientActivated &&
                        UserConfig.getInstance(it).clientUserId == user.id &&
                        ConnectionsManager.getInstance(it).isTestBackend == manager.isTestBackend
                }
                busy = false
                if (existing != null && login.parentActivity is LaunchActivity) {
                    AuthKeySessionNative.discardImport(account)
                    staged = false
                    dialog.dismiss()
                    (login.parentActivity as? LaunchActivity)?.switchToAccount(existing, true)
                    login.finishFragment()
                } else {
                    staged = false
                    dialog.dismiss()
                    login.onAuthSuccess(TLRPC.TL_auth_authorization().apply { this.user = user })
                }
            }
        }, ConnectionsManager.RequestFlagWithoutLogin or ConnectionsManager.RequestFlagFailOnServerErrors)
        manager.bindRequestToGuid(requestId, login.classGuid)
    }

    fun onFileResult(result: Int, data: Intent?) {
        pickingFile = false
        if (closed || busy || result != Activity.RESULT_OK) return
        val uri = data?.data ?: return
        val context = login.parentActivity ?: return
        val attempt = generation
        Utilities.globalQueue.postRunnable {
            val text = try {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    val bytes = ByteArray(AuthKeyCodec.MAX_INPUT_SIZE + 1)
                    var count = 0
                    while (count < bytes.size) {
                        val read = input.read(bytes, count, bytes.size - count)
                        if (read < 0) break
                        count += read
                    }
                    try {
                        if (count > AuthKeyCodec.MAX_INPUT_SIZE) null else String(bytes, 0, count, Charsets.UTF_8)
                    } finally { bytes.fill(0) }
                }
            } catch (_: Exception) { null }
            AndroidUtilities.runOnUIThread {
                if (closed || busy || generation != attempt) return@runOnUIThread
                if (text == null) {
                    fail(getString(R.string.InuSessionFileError))
                    return@runOnUIThread
                }
                if (text.trimStart().startsWith("{")) {
                    try {
                        val credentials = AuthKeySessionHelper.parseInput(text, dcId, manager.isTestBackend)
                        try {
                            if (credentials.testBackend != manager.isTestBackend) {
                                fail(getString(R.string.InuSessionBackendError))
                            } else {
                                dcId = credentials.dcId
                                updateDcLabel()
                                keyField.setText(AuthKeyCodec.encode(credentials.key))
                                status.text = getString(R.string.InuSessionFileLoaded)
                            }
                        } finally { credentials.clear() }
                    } catch (_: Exception) { fail(getString(R.string.InuSessionFormatError)) }
                } else {
                    keyField.setText(text)
                    status.text = getString(R.string.InuSessionFileLoaded)
                }
            }
        }
    }

    private fun setBusy(value: Boolean) {
        busy = value
        keyField.isEnabled = !value
        dcButton.isEnabled = !value
        fileButton.isEnabled = !value
        visibilityButton.isEnabled = !value
        dialog.getButton(Dialog.BUTTON_POSITIVE).isEnabled = !value
    }

    private fun fail(message: String) {
        ++generation
        timeout?.let(AndroidUtilities::cancelRunOnUIThread)
        timeout = null
        if (requestId != 0) manager.cancelRequest(requestId, false)
        requestId = 0
        if (staged) AuthKeySessionNative.discardImport(account)
        staged = false
        setBusy(false)
        status.setTextColor(Theme.getColor(Theme.key_text_RedRegular, login.resourceProvider))
        status.text = message
    }

    fun close() {
        if (closed) return
        closed = true
        ++generation
        timeout?.let(AndroidUtilities::cancelRunOnUIThread)
        timeout = null
        if (requestId != 0) manager.cancelRequest(requestId, false)
        requestId = 0
        if (staged) AuthKeySessionNative.discardImport(account)
        staged = false
        if (::keyField.isInitialized) keyField.text?.clear()
        if (::dialog.isInitialized && dialog.isShowing) dialog.dismiss()
        onClosed()
    }

    fun keepsDialogOnPause(candidate: Dialog) = pickingFile && ::dialog.isInitialized && candidate === dialog

    private fun updateDcLabel() { dcButton.text = "DC $dcId" }
    private fun dp(value: Int) = AndroidUtilities.dp(value.toFloat())
    private fun label(context: Context, text: String, size: Float) = TextView(context).apply {
        this.text = text
        textSize = size
        setTextColor(Theme.getColor(Theme.key_dialogTextBlack, login.resourceProvider))
    }
    private fun action(context: Context, text: String, action: () -> Unit) = label(context, text, 15f).apply {
        setTextColor(Theme.getColor(Theme.key_dialogTextBlue, login.resourceProvider))
        setPadding(0, dp(10), 0, dp(10))
        setOnClickListener { if (!busy) action() }
    }
}
