package net.mullvad.mullvadvpn.lib.common.constant

private const val CONNECT_ACTION_SUFFIX = "connect_action"
private const val RECONNECT_ACTION_SUFFIX = "reconnect_action"
private const val DISCONNECT_ACTION_SUFFIX = "disconnect_action"
private const val REQUEST_VPN_PROFILE_SUFFIX = "request_vpn_profile"

fun connectAction(packageName: String) = clientAction(packageName, CONNECT_ACTION_SUFFIX)

fun reconnectAction(packageName: String) = clientAction(packageName, RECONNECT_ACTION_SUFFIX)

fun disconnectAction(packageName: String) = clientAction(packageName, DISCONNECT_ACTION_SUFFIX)

fun requestVpnProfileAction(packageName: String) =
    clientAction(packageName, REQUEST_VPN_PROFILE_SUFFIX)

private fun clientAction(packageName: String, suffix: String) = "$packageName.$suffix"
