package desu.inugram.core.session

import org.junit.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AuthKeyCodecTest {
    private val key = ByteArray(256) { it.toByte() }

    @Test fun desktop_bytes_survive_a_hex_round_trip_without_reordering() {
        val hex = AuthKeyCodec.encode(key)
        assertEquals(512, hex.length)
        assertEquals("0001020304050607", hex.take(16))
        assertContentEquals(key, AuthKeyCodec.decode(hex))
    }

    @Test fun uppercase_prefix_and_wrapped_lines_are_accepted() {
        val wrapped = AuthKeyCodec.encode(key).uppercase().chunked(32).joinToString(" \n")
        assertContentEquals(key, AuthKeyCodec.decode(" 0X$wrapped \n"))
    }

    @Test fun a_key_identifier_cannot_be_imported_as_a_full_key() {
        assertEquals(AuthKeyCodec.Error.LENGTH, assertFailsWith<AuthKeyCodec.InvalidKey> {
            AuthKeyCodec.decode("0123456789abcdef")
        }.reason)
    }

    @Test fun malformed_oversized_and_zero_keys_are_rejected() {
        for (bad in listOf("ab".repeat(255), "ab".repeat(257), "x".repeat(512), "０".repeat(512), "ab".repeat(5000), "00".repeat(256))) {
            assertFailsWith<AuthKeyCodec.InvalidKey> { AuthKeyCodec.decode(bad) }
        }
    }

    @Test fun production_and_test_data_centers_are_distinguished() {
        for (dc in 1..5) AuthKeyCodec.validateDc(dc)
        for (dc in 1..3) AuthKeyCodec.validateDc(dc, true)
        for (dc in listOf(-1, 0, 6, Int.MAX_VALUE)) {
            assertFailsWith<AuthKeyCodec.InvalidKey> { AuthKeyCodec.validateDc(dc) }
        }
        assertFailsWith<AuthKeyCodec.InvalidKey> { AuthKeyCodec.validateDc(4, true) }
    }

    @Test fun the_fingerprint_uses_the_last_sha1_bytes_as_a_little_endian_integer() {
        // SHA1 of the fixture 00..ff: 4916d6bdb7f78e6803698cab32d1586ea457dfc8.
        assertEquals(java.lang.Long.parseUnsignedLong("c8df57a46e58d132", 16), AuthKeyCodec.keyId(key))
    }
}
