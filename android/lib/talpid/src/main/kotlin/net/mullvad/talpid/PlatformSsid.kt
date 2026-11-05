package net.mullvad.talpid

import net.mullvad.mullvadvpn.lib.model.SsidIdentity

/** WifiInfo returns quoted UTF-8, or unquoted hex for a non-UTF-8 SSID. */
internal fun platformSsid(value: String?): SsidIdentity? =
    when {
        value == null || value == "<unknown ssid>" -> null
        value.length >= HEX_PAIR && value.startsWith('"') && value.endsWith('"') ->
            SsidIdentity.fromUserText(value.substring(1, value.lastIndex))
        value.isNotEmpty() &&
            value.length % HEX_PAIR == 0 &&
            value.length <= MAX_HEX_LENGTH &&
            value.all { it.digitToIntOrNull(HEX_RADIX) != null } ->
            SsidIdentity.fromBytes(
                value.chunked(HEX_PAIR).map { it.toInt(HEX_RADIX).toByte() }.toByteArray()
            )
        else -> null
    }

private const val HEX_PAIR = 2
private const val HEX_RADIX = 16
private const val MAX_HEX_LENGTH = 64
