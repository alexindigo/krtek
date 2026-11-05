package net.mullvad.talpid.model

import java.net.InetAddress

/** Ephemeral physical-network observation. Never serialize this record or log its contents. */
data class LocalNetworkSnapshot(
    val sequence: Long,
    val observerRunning: Boolean,
    val localReady: Boolean,
    val fineReady: Boolean,
    val backgroundReady: Boolean,
    val locationEnabled: Boolean,
    val locationAllowed: Boolean,
    val networks: ArrayList<LocalPhysicalNetwork>,
) {
    override fun toString(): String =
        "LocalNetworkSnapshot(sequence=$sequence running=$observerRunning networks=${networks.size})"
}

data class LocalPhysicalNetwork(
    val networkHandle: Long,
    val transport: Int = 0,
    val capabilitiesFresh: Boolean = false,
    val linksFresh: Boolean = false,
    val blocked: Boolean = true,
    val interfaceIndex: Int = 0,
    val addresses: ArrayList<LocalPhysicalAddress> = arrayListOf(),
    val routes: ArrayList<LocalPhysicalRoute> = arrayListOf(),
    val ssidHex: String? = null,
) {
    override fun toString(): String = "LocalPhysicalNetwork(transport=$transport)"
}

data class LocalPhysicalAddress(val prefix: InetNetwork, val usable: Boolean) {
    override fun toString(): String = "LocalPhysicalAddress(redacted)"
}

data class LocalPhysicalRoute(
    val destination: InetNetwork,
    val gateway: InetAddress?,
    val interfaceIndex: Int,
    val routeType: Int,
) {
    override fun toString(): String = "LocalPhysicalRoute(type=$routeType)"
}
