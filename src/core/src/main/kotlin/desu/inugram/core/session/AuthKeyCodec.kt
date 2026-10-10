package desu.inugram.core.session

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** Raw, permanent MTProto key bytes, in the same order used by Telegram Desktop. */
object AuthKeyCodec {
    const val KEY_SIZE = 256
    const val HEX_SIZE = KEY_SIZE * 2
    const val MAX_INPUT_SIZE = 8192

    enum class Error { LENGTH, HEX, ZERO_KEY, DC }
    class InvalidKey(val reason: Error) : IllegalArgumentException(reason.name)

    fun decode(text: String): ByteArray {
        if (text.length > MAX_INPUT_SIZE) throw InvalidKey(Error.LENGTH)
        val hex = text.filterNot { it.isWhitespace() }.removePrefix("0x").removePrefix("0X")
        if (hex.length != HEX_SIZE) throw InvalidKey(Error.LENGTH)
        val key = ByteArray(KEY_SIZE)
        for (i in key.indices) {
            val high = digit(hex[i * 2])
            val low = digit(hex[i * 2 + 1])
            if (high < 0 || low < 0) {
                key.fill(0)
                throw InvalidKey(Error.HEX)
            }
            key[i] = ((high shl 4) or low).toByte()
        }
        if (key.all { it == 0.toByte() }) throw InvalidKey(Error.ZERO_KEY)
        return key
    }

    fun encode(key: ByteArray): String {
        require(key.size == KEY_SIZE) { "Invalid auth key length" }
        val digits = "0123456789abcdef"
        return buildString(HEX_SIZE) {
            for (b in key) {
                val value = b.toInt() and 255
                append(digits[value ushr 4])
                append(digits[value and 15])
            }
        }
    }

    fun validateDc(dcId: Int, testBackend: Boolean = false) {
        if (dcId !in 1..(if (testBackend) 3 else 5)) throw InvalidKey(Error.DC)
    }

    fun keyId(key: ByteArray): Long {
        require(key.size == KEY_SIZE) { "Invalid auth key length" }
        val hash = MessageDigest.getInstance("SHA-1").digest(key)
        return ByteBuffer.wrap(hash, 12, 8).order(ByteOrder.LITTLE_ENDIAN).long
    }

    private fun digit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }
}
