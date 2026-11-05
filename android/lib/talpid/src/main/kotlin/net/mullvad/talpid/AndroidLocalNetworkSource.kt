package net.mullvad.talpid

import android.app.AppOpsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.SupplicantState
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.system.OsConstants
import java.net.NetworkInterface
import java.net.SocketException
import net.mullvad.mullvadvpn.lib.common.constant.LOCAL_NETWORK_PERMISSION
import net.mullvad.talpid.model.InetNetwork
import net.mullvad.talpid.model.LocalPhysicalAddress
import net.mullvad.talpid.model.LocalPhysicalNetwork
import net.mullvad.talpid.model.LocalPhysicalRoute

/** Android subscription plumbing. Lifecycle is serialized by the watcher's lock. */
internal class AndroidLocalNetworkSource(private val context: Context) : LocalNetworkSource {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val appOps = context.getSystemService(AppOpsManager::class.java)
    private val accessReader = LocalIdentityAccessReader(context)
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var receiver: BroadcastReceiver? = null
    private var operationsListener: AppOpsManager.OnOpChangedListener? = null

    override fun readAccess(): LocalIdentityAccess = accessReader.read()

    override fun start(
        includeLocation: Boolean,
        onEvent: (LocalNetworkEvent) -> Unit,
        onAccessChanged: () -> Unit,
    ) {
        check(callback == null)
        val flags =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && includeLocation)
                ConnectivityManager.NetworkCallback.FLAG_INCLUDE_LOCATION_INFO
            else 0
        val next = callback(flags, onEvent)
        callback = next
        connectivity.registerNetworkCallback(request(), next)
        watchPermissions(onAccessChanged)
    }

    private fun watchPermissions(changed: () -> Unit) {
        val broadcast =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) = changed()
            }
        val filter = IntentFilter(LocationManager.MODE_CHANGED_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            context.registerReceiver(broadcast, filter, Context.RECEIVER_NOT_EXPORTED)
        else context.registerReceiver(broadcast, filter)
        receiver = broadcast
        val operations = AppOpsManager.OnOpChangedListener { _, packageName ->
            if (packageName == null || packageName == context.packageName) changed()
        }
        operationsListener = operations
        val watched =
            listOfNotNull(
                AppOpsManager.OPSTR_FINE_LOCATION,
                AppOpsManager.OPSTR_COARSE_LOCATION,
                AppOpsManager.permissionToOp(LOCAL_NETWORK_PERMISSION),
            )
        watched.distinct().forEach { operation ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                appOps.startWatchingMode(
                    operation,
                    context.packageName,
                    AppOpsManager.WATCH_FOREGROUND_CHANGES,
                    operations,
                )
            else appOps.startWatchingMode(operation, context.packageName, operations)
        }
    }

    override fun stop() {
        callback?.let {
            try {
                connectivity.unregisterNetworkCallback(it)
            } catch (_: IllegalArgumentException) {
                // Registration can fail before ConnectivityManager retains the callback.
            }
        }
        callback = null
        receiver?.let(context::unregisterReceiver)
        receiver = null
        operationsListener?.let(appOps::stopWatchingMode)
        operationsListener = null
    }

    private fun callback(
        flags: Int = 0,
        onEvent: (LocalNetworkEvent) -> Unit,
    ): ConnectivityManager.NetworkCallback =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PhysicalCallback(flags, onEvent)
        else LegacyPhysicalCallback(onEvent)

    private open class LegacyPhysicalCallback(private val event: (LocalNetworkEvent) -> Unit) :
        ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) =
            event(
                LocalNetworkEvent.Available(
                    network.networkHandle,
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
                )
            )

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) =
            event(capabilitiesEvent(network, capabilities))

        override fun onLinkPropertiesChanged(network: Network, links: LinkProperties) =
            event(linksEvent(network, links))

        override fun onBlockedStatusChanged(network: Network, blocked: Boolean) =
            event(LocalNetworkEvent.Update(network.networkHandle) { it.copy(blocked = blocked) })

        override fun onLost(network: Network) = event(LocalNetworkEvent.Lost(network.networkHandle))
    }

    @androidx.annotation.RequiresApi(Build.VERSION_CODES.S)
    private class PhysicalCallback(flags: Int, private val event: (LocalNetworkEvent) -> Unit) :
        ConnectivityManager.NetworkCallback(flags) {
        override fun onAvailable(network: Network) =
            event(LocalNetworkEvent.Available(network.networkHandle, true))

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) =
            event(capabilitiesEvent(network, capabilities))

        override fun onLinkPropertiesChanged(network: Network, links: LinkProperties) =
            event(linksEvent(network, links))

        override fun onBlockedStatusChanged(network: Network, blocked: Boolean) =
            event(LocalNetworkEvent.Update(network.networkHandle) { it.copy(blocked = blocked) })

        override fun onLost(network: Network) = event(LocalNetworkEvent.Lost(network.networkHandle))
    }

    @Suppress("DEPRECATION") // API 28–30 exposes only the current WifiManager connection.
    override fun withLegacyIdentity(
        networks: List<LocalPhysicalNetwork>,
        allowed: Boolean,
    ): List<LocalPhysicalNetwork> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) return networks
        val cleared = networks.map { it.copy(ssidHex = null) }
        val wifi =
            networks
                .singleOrNull { it.transport == LocalNetworkWatcher.WIFI }
                ?.takeIf {
                    allowed &&
                        networks.all { network -> network.capabilitiesFresh } &&
                        it.linksFresh &&
                        !it.blocked
                }
        val identity = wifi?.let(::legacyIdentity)
        return cleared.map {
            if (it.networkHandle == wifi?.networkHandle) it.copy(ssidHex = identity) else it
        }
    }

    @Suppress("DEPRECATION") // Public API 28–30 connection info and little-endian IPv4 value.
    private fun legacyIdentity(wifi: LocalPhysicalNetwork): String? {
        val info = context.getSystemService(WifiManager::class.java).connectionInfo ?: return null
        val address = ByteArray(IPV4_BYTES) { (info.ipAddress shr (it * BITS_PER_BYTE)).toByte() }
        val matches =
            info.supplicantState == SupplicantState.COMPLETED &&
                info.ipAddress != 0 &&
                wifi.addresses.any { it.usable && it.prefix.address.address.contentEquals(address) }
        return if (matches) platformSsid(info.ssid)?.encodedBytes() else null
    }

    companion object {
        private const val IPV4_BYTES = 4
        private const val BITS_PER_BYTE = 8
        private const val ROUTE_UNICAST = 1
        private const val ROUTE_UNREACHABLE = 7

        private fun request(): NetworkRequest {
            val builder = NetworkRequest.Builder()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) builder.clearCapabilities()
            else {
                builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
            }
            return builder
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
                .build()
        }

        private fun capabilitiesEvent(
            network: Network,
            capabilities: NetworkCapabilities,
        ): LocalNetworkEvent {
            val physical =
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
            val transport =
                when {
                    !physical -> 0
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ->
                        LocalNetworkWatcher.WIFI
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ->
                        LocalNetworkWatcher.ETHERNET
                    else -> 0
                }
            val identity =
                if (
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                        transport == LocalNetworkWatcher.WIFI
                )
                    platformSsid((capabilities.transportInfo as? WifiInfo)?.ssid)?.encodedBytes()
                else null
            return LocalNetworkEvent.Update(network.networkHandle) {
                it.copy(transport = transport, capabilitiesFresh = true, ssidHex = identity)
            }
        }

        private fun linksEvent(network: Network, links: LinkProperties): LocalNetworkEvent {
            val index = interfaceIndex(links.interfaceName)
            val addresses =
                links.linkAddresses.map {
                    LocalPhysicalAddress(
                        InetNetwork(it.address, it.prefixLength.toShort()),
                        it.flags and (OsConstants.IFA_F_TENTATIVE or OsConstants.IFA_F_DADFAILED) ==
                            0 &&
                            !it.address.isAnyLocalAddress &&
                            !it.address.isLoopbackAddress &&
                            !it.address.isMulticastAddress,
                    )
                }
            val routes =
                links.routes.map {
                    LocalPhysicalRoute(
                        InetNetwork(it.destination.address, it.destination.prefixLength.toShort()),
                        it.gateway?.takeUnless { gateway -> gateway.isAnyLocalAddress },
                        if (it.`interface` == null || it.`interface` == links.interfaceName) index
                        else 0,
                        when {
                            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> it.type
                            // Older public APIs prove only default-route types. Keep unknown as 0.
                            it.destination.prefixLength != 0 -> 0
                            it.isDefaultRoute -> ROUTE_UNICAST
                            else -> ROUTE_UNREACHABLE
                        },
                    )
                }
            return LocalNetworkEvent.Update(network.networkHandle) {
                it.copy(
                    linksFresh = true,
                    interfaceIndex = index,
                    addresses = ArrayList(addresses),
                    routes = ArrayList(routes),
                )
            }
        }

        private fun interfaceIndex(name: String?): Int =
            try {
                name?.let { NetworkInterface.getByName(it)?.index } ?: 0
            } catch (_: SocketException) {
                0
            }
    }
}
