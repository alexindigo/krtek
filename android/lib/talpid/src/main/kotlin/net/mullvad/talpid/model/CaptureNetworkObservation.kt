package net.mullvad.talpid.model

import java.net.InetAddress

data class CaptureRoute(
    val destination: InetNetwork,
    val gateway: InetAddress?,
    val interfaceName: String,
    val routeType: Int?,
)

data class CaptureNetworkObservation(
    val networkHandle: Long,
    val network: String,
    val interfaceName: String,
    val ownerUid: Int?,
    val routes: ArrayList<CaptureRoute>,
    val addresses: ArrayList<InetNetwork>,
    val dnsServers: ArrayList<InetAddress>,
    val mtu: Int?,
    val fresh: Boolean,
    val lost: Boolean,
    val apiLevel: Int,
)
