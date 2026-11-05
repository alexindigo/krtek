package net.mullvad.talpid

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Process
import net.mullvad.talpid.model.CaptureNetworkObservation
import net.mullvad.talpid.model.CaptureRoute
import net.mullvad.talpid.model.InetNetwork

/** One registration per established capture. It never queries the default network. */
internal class LocalCaptureNetworkObserver(
    private val connectivity: ConnectivityManager,
    private val registration: Long,
    private val generation: Long,
    private val publish: (Long, Long, CaptureNetworkObservation) -> Unit =
        LocalCaptureNetworkBridge::published,
) {
    private class Entry(
        var capabilitiesSeen: Boolean = false,
        var vpn: Boolean = false,
        var ownerUid: Int? = null,
        var links: CaptureNetworkObservation? = null,
    )

    private val lock = Any()
    private val entries = linkedMapOf<Long, Entry>()
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var expectedInterface: String? = null
    private var pinnedHandle: Long? = null
    private var latest: CaptureNetworkObservation? = null
    private var closed = false

    fun start(): Unit =
        synchronized(lock) {
            check(callback == null && !closed)
            val next = CaptureCallback()
            callback = next
            try {
                val request =
                    NetworkRequest.Builder()
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                        .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                        .build()
                connectivity.registerNetworkCallback(request, next)
            } catch (_: RuntimeException) {
                fail()
            }
        }

    /** Called only after Rust binds the actual borrowed descriptor's interface. */
    fun bind(interfaceName: String): Boolean =
        synchronized(lock) {
            if (closed || expectedInterface != null || interfaceName.isEmpty()) return false
            expectedInterface = interfaceName
            entries.values.toList().forEach(::observe)
            true
        }

    /** Revocation is independent of fallible Android callback cleanup. */
    fun invalidate(): Unit =
        synchronized(lock) {
            if (!closed) {
                closed = true
                entries.clear()
                latest?.let { emit(it.copy(fresh = false, lost = true)) }
            }
        }

    /** Invalidate before unregister. An unregister error retains its retry obligation. */
    fun close(): Unit =
        synchronized(lock) {
            invalidate()
            callback?.let {
                try {
                    connectivity.unregisterNetworkCallback(it)
                } catch (_: IllegalArgumentException) {
                    // Registration may have failed before Android retained the callback.
                }
            }
            callback = null
        }

    private fun entry(network: Network): Entry? {
        val handle = network.networkHandle
        return when {
            closed || (pinnedHandle != null && pinnedHandle != handle) -> null
            entries.containsKey(handle) -> entries[handle]
            entries.size == MAX_NETWORKS -> {
                fail()
                null
            }
            else -> Entry().also { entries[handle] = it }
        }
    }

    private fun observe(entry: Entry) {
        val expected = expectedInterface
        val owned =
            entry.vpn &&
                (Build.VERSION.SDK_INT < Build.VERSION_CODES.R || entry.ownerUid == Process.myUid())
        val links = entry.links
        if (expected == null || !entry.capabilitiesSeen || links == null) return
        val handle = links.networkHandle
        if (pinnedHandle == null && owned && links.interfaceName == expected) {
            pinnedHandle = handle
            entries.keys.retainAll(setOf(handle))
        }
        if (pinnedHandle == handle) {
            emit(links.copy(ownerUid = entry.ownerUid, fresh = owned))
        }
    }

    private fun emit(observation: CaptureNetworkObservation) {
        if (latest == observation) return
        latest = observation
        publish(registration, generation, observation)
    }

    private fun fail() {
        closed = true
        entries.clear()
        emit(
            CaptureNetworkObservation(
                0,
                "",
                expectedInterface.orEmpty(),
                null,
                arrayListOf(),
                arrayListOf(),
                arrayListOf(),
                null,
                fresh = false,
                lost = true,
                apiLevel = Build.VERSION.SDK_INT,
            )
        )
    }

    private inner class CaptureCallback : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(
            network: Network,
            capabilities: NetworkCapabilities,
        ): Unit =
            synchronized(lock) {
                entry(network)?.let {
                    it.capabilitiesSeen = true
                    it.vpn = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    it.ownerUid =
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) capabilities.ownerUid
                        else null
                    observe(it)
                }
            }

        override fun onLinkPropertiesChanged(network: Network, links: LinkProperties): Unit =
            synchronized(lock) {
                entry(network)?.let {
                    it.links =
                        CaptureNetworkObservation(
                            networkHandle = network.networkHandle,
                            network = network.toString(),
                            interfaceName = links.interfaceName.orEmpty(),
                            ownerUid = null,
                            routes = ArrayList(links.routes.map(::route)),
                            addresses =
                                ArrayList(
                                    links.linkAddresses.map { address ->
                                        InetNetwork(address.address, address.prefixLength.toShort())
                                    }
                                ),
                            dnsServers = ArrayList(links.dnsServers),
                            mtu =
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) links.mtu
                                else null,
                            fresh = false,
                            lost = false,
                            apiLevel = Build.VERSION.SDK_INT,
                        )
                    observe(it)
                }
            }

        override fun onLost(network: Network): Unit =
            synchronized(lock) {
                if (closed) return
                entries.remove(network.networkHandle)
                if (pinnedHandle == network.networkHandle) {
                    closed = true
                    entries.clear()
                    latest?.let { emit(it.copy(fresh = false, lost = true)) }
                }
            }
    }

    companion object {
        private const val MAX_NETWORKS = 16

        private fun route(route: android.net.RouteInfo) =
            CaptureRoute(
                InetNetwork(route.destination.address, route.destination.prefixLength.toShort()),
                route.gateway?.takeUnless { it.isAnyLocalAddress },
                route.`interface`.orEmpty(),
                // A missing public property is represented as absent, never as
                // a guessed route type. Native comparison pins this API level.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) route.type else null,
            )
    }
}
