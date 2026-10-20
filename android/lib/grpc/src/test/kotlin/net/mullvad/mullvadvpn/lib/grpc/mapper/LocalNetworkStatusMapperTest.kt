package net.mullvad.mullvadvpn.lib.grpc.mapper

import java.io.File
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import mullvad_daemon.management_interface.ConnectedWifi
import mullvad_daemon.management_interface.LocalNetworkStatus
import mullvad_daemon.management_interface.LocalRuleInactiveReason
import mullvad_daemon.management_interface.LocalRuleStatus
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi as ModelConnectedWifi
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason as ModelInactiveReason
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.WifiUnknownReason
import okio.ByteString.Companion.decodeHex
import org.junit.jupiter.api.Test

class LocalNetworkStatusMapperTest {
    @Test
    fun `should consume the Rust verified wire fixtures for every reason and Wi-Fi variant`() {
        val fixture =
            generateSequence(File(requireNotNull(System.getProperty("user.dir")))) { it.parentFile }
                .map { File(it, "mullvad-management-interface/testdata/local-network-status.hex") }
                .first { it.isFile }
        val statuses =
            fixture.readLines().map { LocalNetworkStatus.ADAPTER.decode(it.decodeHex()).toDomain() }
        assertEquals(6, statuses.size)
        for ((index, status) in statuses.withIndex()) {
            assertEquals(ULong.MAX_VALUE, status.revision)
            assertEquals(true, status.observerAvailable)
            assertEquals(ForwardingAvailability.NotAvailable, status.forwarding)
            assertEquals(13, status.rules.size)
            assertEquals(LocalRuleState.ConditionsMet, status.rules.first().state)
            assertEquals(UUID(0, 0), status.rules.first().id)
            assertEquals(
                ModelInactiveReason.entries,
                status.rules.drop(1).map { assertIs<LocalRuleState.Inactive>(it.state).reason },
            )
            if (index == 0) {
                assertEquals(
                    listOf(0, 255, 65, 32),
                    assertIs<ModelConnectedWifi.Known>(status.currentWifi).ssid.bytes().map {
                        it.toInt() and 255
                    },
                )
            } else {
                assertEquals(
                    WifiUnknownReason.entries[index - 1],
                    assertIs<ModelConnectedWifi.Unknown>(status.currentWifi).reason,
                )
            }
        }
    }

    @Test
    fun `should reject incoherent rule states without echoing identity bytes`() {
        val wire =
            LocalNetworkStatus(
                current_wifi =
                    ConnectedWifi(
                        identity =
                            ConnectedWifi.Identity.Unknown(ConnectedWifi.UnknownReason.PENDING)
                    )
            )
        for (rule in
            listOf(
                LocalRuleStatus(
                    id = UUID(0, 0).toString(),
                    state = LocalRuleStatus.State.CONDITIONS_MET,
                    reason = LocalRuleInactiveReason.POLICY_OFF,
                ),
                LocalRuleStatus(id = UUID(0, 0).toString(), state = LocalRuleStatus.State.INACTIVE),
            )) {
            assertFailsWith<IllegalArgumentException> { wire.copy(rules = listOf(rule)).toDomain() }
        }
        assertFailsWith<IllegalArgumentException> { wire.copy(current_wifi = null).toDomain() }
    }

    @Test
    fun `should redact connected Wi-Fi in model diagnostics`() {
        val ssid =
            net.mullvad.mullvadvpn.lib.model.SsidIdentity.fromUserText("private-wifi-marker")!!
        val value = ModelConnectedWifi.Known(ssid)
        assertFalse(value.toString().contains("private-wifi-marker"))
        assertFalse(value.toString().contains(ssid.encodedBytes()))
    }
}
