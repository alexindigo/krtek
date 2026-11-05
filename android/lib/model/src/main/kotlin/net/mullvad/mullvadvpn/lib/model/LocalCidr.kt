package net.mullvad.mullvadvpn.lib.model

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure

sealed interface LocalCidrError {
    data object Malformed : LocalCidrError

    data class Noncanonical(val suggested: String) : LocalCidrError

    data object OutsideLocalScope : LocalCidrError
}

/** Numeric-only CIDR parsing. No platform APIs, host lookup or DNS are involved. */
class LocalCidr private constructor(private val address: ByteArray, val prefix: Int) {
    val isIpv4: Boolean
        get() = address.size == IPV4_BYTES

    fun networkBytes(): ByteArray = address.copyOf()

    fun contains(destination: ByteArray): Boolean =
        destination.size == address.size && masked(destination, prefix).contentEquals(address)

    override fun equals(other: Any?): Boolean =
        other is LocalCidr && prefix == other.prefix && address.contentEquals(other.address)

    override fun hashCode(): Int = prefix + BITS_PER_BYTE * address.contentHashCode()

    override fun toString(): String = formatAddress(address) + "/" + prefix

    companion object {
        private const val IPV4_BYTES = 4
        private const val IPV6_BYTES = 16
        private const val IPV6_WORDS = 8
        private const val BITS_PER_BYTE = 8
        private const val BYTES_PER_WORD = 2
        private const val HEX_RADIX = 16
        private const val OCTET_MASK = 255
        private const val CIDR_PARTS = 2

        private val scopes =
            listOf(
                    "10.0.0.0" to 8,
                    "172.16.0.0" to 12,
                    "192.168.0.0" to 16,
                    "169.254.0.0" to 16,
                    "fc00::" to 7,
                    "fe80::" to 10,
                )
                .map { (base, prefix) -> checkNotNull(parseAddress(base)) to prefix }

        fun parse(text: String): Either<LocalCidrError, LocalCidr> = either {
            val parts = text.split('/')
            ensure(parts.size == CIDR_PARTS) { LocalCidrError.Malformed }
            ensure(parts[1].isNotEmpty() && parts[1].all { it in '0'..'9' }) {
                LocalCidrError.Malformed
            }
            val address = parseAddress(parts[0]) ?: raise(LocalCidrError.Malformed)
            val prefix = parts[1].toIntOrNull() ?: raise(LocalCidrError.Malformed)
            ensure(prefix in 0..address.size * BITS_PER_BYTE) { LocalCidrError.Malformed }
            val network = masked(address, prefix)
            ensure(network.contentEquals(address)) {
                LocalCidrError.Noncanonical(formatAddress(network) + "/" + prefix)
            }
            ensure(
                scopes.any { (base, bits) ->
                    base.size == address.size &&
                        prefix >= bits &&
                        masked(address, bits).contentEquals(base)
                }
            ) {
                LocalCidrError.OutsideLocalScope
            }
            LocalCidr(network, prefix)
        }

        fun parseAddress(text: String): ByteArray? =
            if (':' in text) parseIpv6(text) else parseIpv4(text)

        private fun parseIpv4(text: String): ByteArray? {
            val parts = text.split('.')
            val octets = parts.map { part ->
                part
                    .takeIf {
                        it.isNotEmpty() &&
                            it.all { digit -> digit in '0'..'9' } &&
                            (it.length == 1 || it[0] != '0')
                    }
                    ?.toIntOrNull()
                    ?.takeIf { it in 0..OCTET_MASK }
            }
            return if (parts.size != IPV4_BYTES || octets.any { it == null }) null
            else ByteArray(IPV4_BYTES) { checkNotNull(octets[it]).toByte() }
        }

        private fun parseIpv6(text: String): ByteArray? =
            ipv6Groups(text)?.let { groups ->
                ByteArray(IPV6_BYTES) { index ->
                    (groups[index / BYTES_PER_WORD] shr
                            (if (index % BYTES_PER_WORD == 0) BITS_PER_BYTE else 0))
                        .toByte()
                }
            }

        private fun ipv6Groups(text: String): List<Int>? {
            val parts = text.split("::")
            val left = words(parts[0], parts.size == 1)
            val right = if (parts.size == CIDR_PARTS) words(parts[1], true) else emptyList()
            if (left == null || right == null || parts.size > CIDR_PARTS) return null
            val count = left.size + right.size
            return when {
                parts.size == 1 && count != IPV6_WORDS -> null
                parts.size == CIDR_PARTS && count >= IPV6_WORDS -> null
                else -> left + List(IPV6_WORDS - count) { 0 } + right
            }
        }

        private fun words(text: String, allowIpv4: Boolean): List<Int>? {
            val groups = if (text.isEmpty()) emptyList() else text.split(':')
            val parsed = groups.mapIndexed { index, group ->
                parseWord(group, allowIpv4 && index == groups.lastIndex)
            }
            return if (parsed.any { it == null }) null else parsed.filterNotNull().flatten()
        }

        private fun parseWord(group: String, allowIpv4: Boolean): List<Int>? =
            when {
                '.' in group ->
                    if (allowIpv4) parseIpv4(group)?.toList()?.chunked(BYTES_PER_WORD)?.map(::word)
                    else null
                group.isEmpty() || group.length > IPV4_BYTES -> null
                group.any { it !in "0123456789abcdefABCDEF" } -> null
                else -> listOf(group.toInt(HEX_RADIX))
            }

        private fun word(bytes: List<Byte>): Int =
            ((bytes[0].toInt() and OCTET_MASK) shl BITS_PER_BYTE) or
                (bytes[1].toInt() and OCTET_MASK)

        private fun masked(bytes: ByteArray, prefix: Int): ByteArray =
            ByteArray(bytes.size) { index ->
                val bits = (prefix - index * BITS_PER_BYTE).coerceIn(0, BITS_PER_BYTE)
                (bytes[index].toInt() and (OCTET_MASK shl (BITS_PER_BYTE - bits))).toByte()
            }

        private fun formatAddress(bytes: ByteArray): String =
            if (bytes.size == IPV4_BYTES)
                bytes.joinToString(".") { (it.toInt() and OCTET_MASK).toString() }
            else formatIpv6(bytes)

        private fun formatIpv6(bytes: ByteArray): String {
            val words = bytes.toList().chunked(BYTES_PER_WORD).map(::word)
            var bestStart = -1
            var bestLength = 1
            var index = 0
            while (index < words.size) {
                val start = index
                if (words[index] != 0) {
                    index++
                } else {
                    while (index < words.size && words[index] == 0) index++
                    if (index - start > bestLength) {
                        bestStart = start
                        bestLength = index - start
                    }
                }
            }
            if (bestStart < 0) return words.joinToString(":") { it.toString(HEX_RADIX) }
            val left = words.take(bestStart).joinToString(":") { it.toString(HEX_RADIX) }
            val right =
                words.drop(bestStart + bestLength).joinToString(":") { it.toString(HEX_RADIX) }
            return "$left::$right"
        }
    }
}
