package desu.inugram.helpers.security

/** All key access runs on tgnet's account network thread. */
object AuthKeySessionNative {
    fun interface Callback {
        fun onResult(dcId: Int, testBackend: Boolean, key: ByteArray?, error: Int)
    }

    @JvmStatic external fun exportSession(account: Int, callback: Callback)
    @JvmStatic external fun importSession(account: Int, dcId: Int, testBackend: Boolean, key: ByteArray, callback: Callback)
    @JvmStatic external fun discardImport(account: Int)
}
