package net.mullvad.talpid

import net.mullvad.mullvadvpn.lib.model.LocalCidr

/** This path deliberately has no DNS configuration or upstream empty-DNS fallback. */
internal class LocalFrontendConfig private constructor(val routes: List<LocalCidr>) {
    fun configure(address: (String, Int) -> Unit, route: (LocalCidr) -> Unit) {
        address("192.0.2.2", IPV4_HOST_PREFIX)
        address("2001:db8::2", IPV6_HOST_PREFIX)
        routes.forEach(route)
    }

    companion object {
        private const val IPV4_HOST_PREFIX = 32
        private const val IPV6_HOST_PREFIX = 128

        fun parse(routes: Array<String>): LocalFrontendConfig? {
            val parsed = routes.map { LocalCidr.parse(it).getOrNull() ?: return null }
            return parsed.takeIf { it.isNotEmpty() }?.let(::LocalFrontendConfig)
        }
    }
}
