package net.mullvad.mullvadvpn.lib.model

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.Locale

/** Exact immutable SSID bytes; neither text nor encodings enter diagnostics. */
class SsidIdentity private constructor(private val value: ByteArray) {
    fun bytes(): ByteArray = value.copyOf()

    fun encodedBytes(): String = value.joinToString("") { "%02x".format(Locale.ROOT, it) }

    /** User-facing UTF-8 text when valid, otherwise the lossless hex identity. */
    fun displayText(): String =
        try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value))
                .toString()
        } catch (_: CharacterCodingException) {
            encodedBytes()
        }

    override fun equals(other: Any?): Boolean =
        other is SsidIdentity && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "SsidIdentity(redacted)"

    companion object {
        private const val MAX_BYTES = 32

        fun fromBytes(bytes: ByteArray): SsidIdentity? =
            bytes.takeIf { it.size in 1..MAX_BYTES }?.let { SsidIdentity(it.copyOf()) }

        fun fromUserText(text: String): SsidIdentity? {
            val buffer =
                try {
                    Charsets.UTF_8.newEncoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .encode(CharBuffer.wrap(text))
                } catch (_: CharacterCodingException) {
                    return null
                }
            val bytes = ByteArray(buffer.remaining())
            buffer.get(bytes)
            return fromBytes(bytes)
        }
    }
}
