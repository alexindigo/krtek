package net.mullvad.mullvadvpn.lib.pushnotification.tunnelstate

import kotlin.test.assertEquals
import net.mullvad.mullvadvpn.lib.common.constant.connectAction
import net.mullvad.mullvadvpn.lib.common.constant.disconnectAction
import net.mullvad.mullvadvpn.lib.common.constant.reconnectAction
import net.mullvad.mullvadvpn.lib.common.constant.requestVpnProfileAction
import net.mullvad.mullvadvpn.lib.model.NotificationAction
import org.junit.jupiter.api.Test

class IntentActionsTest {
    private val packageNames =
        listOf(
            "example.client",
            "example.client.devmole",
            "example.client.stagemole",
            "example.client.leakcanary",
            "example.client.devmole.leakcanary",
            "example.client.stagemole.leakcanary",
        )

    @Test
    fun `should build exact package scoped client action strings for every variant`() {
        packageNames.forEach { packageName ->
            assertEquals("$packageName.connect_action", connectAction(packageName))
            assertEquals("$packageName.reconnect_action", reconnectAction(packageName))
            assertEquals("$packageName.disconnect_action", disconnectAction(packageName))
            assertEquals("$packageName.request_vpn_profile", requestVpnProfileAction(packageName))
        }
    }

    @Test
    fun `should use the client action contract for every notification variant`() {
        packageNames.forEach { packageName ->
            assertEquals(
                connectAction(packageName),
                NotificationAction.Tunnel.Connect.toKey(packageName),
            )
            assertEquals(
                reconnectAction(packageName),
                NotificationAction.Tunnel.Reconnect.toKey(packageName),
            )
            assertEquals(
                requestVpnProfileAction(packageName),
                NotificationAction.Tunnel.RequestVpnProfile.toKey(packageName),
            )
            listOf(
                    NotificationAction.Tunnel.Cancel,
                    NotificationAction.Tunnel.Disconnect,
                    NotificationAction.Tunnel.Dismiss,
                )
                .forEach { action ->
                    assertEquals(disconnectAction(packageName), action.toKey(packageName))
                }
        }
    }
}
