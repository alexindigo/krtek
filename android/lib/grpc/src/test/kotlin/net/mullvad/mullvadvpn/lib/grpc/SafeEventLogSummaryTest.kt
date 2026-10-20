package net.mullvad.mullvadvpn.lib.grpc

import co.touchlab.kermit.LogWriter
import co.touchlab.kermit.Logger
import co.touchlab.kermit.Severity
import co.touchlab.kermit.StaticConfig
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import mullvad_daemon.management_interface.DaemonEvent
import mullvad_daemon.management_interface.LocalBypassRule
import mullvad_daemon.management_interface.LocalNetworkAccess
import mullvad_daemon.management_interface.Settings
import okio.Buffer
import okio.ByteString.Companion.encodeUtf8
import org.junit.jupiter.api.Test

class SafeEventLogSummaryTest {
    @Test
    fun `should log only counts without private rule values or unknown fields`() {
        val ssid = "wifi-Ł船-marker"
        val name = "private-rule-marker"
        val cidr = "192.168.240.0/28"
        val bytes = ssid.encodeUtf8()
        // unknownFields contains encoded fields, not arbitrary payload bytes:
        // field 99, length-delimited, with this short synthetic SSID as payload.
        val unknownFields =
            Buffer()
                .writeByte(0x9a)
                .writeByte(0x06)
                .writeByte(bytes.size)
                .write(bytes)
                .readByteString()
        val event =
            DaemonEvent(
                event =
                    DaemonEvent.Event.Settings(
                        Settings(
                            local_network_access =
                                LocalNetworkAccess(
                                    enabled = true,
                                    rules =
                                        listOf(
                                            LocalBypassRule(
                                                id = "00000000-0000-0000-0000-000000000001",
                                                name = name,
                                                enabled = true,
                                                cidrs = listOf(cidr),
                                                ssid_ids = listOf(bytes),
                                            )
                                        ),
                                )
                        )
                    )
            )
        val decoded = DaemonEvent.ADAPTER.decode(DaemonEvent.ADAPTER.encode(event))
        assertTrue(decoded.toString().contains(name))
        val messages = mutableListOf<String>()
        val writer =
            object : LogWriter() {
                override fun log(
                    severity: Severity,
                    message: String,
                    tag: String,
                    throwable: Throwable?,
                ) {
                    assertEquals(Severity.Verbose, severity)
                    assertEquals(null, throwable)
                    messages.add(message)
                }
            }
        val logger =
            Logger(StaticConfig(minSeverity = Severity.Verbose, logWriterList = listOf(writer)))
        decoded.logSafeEventSummary(logger)
        DaemonEvent(unknownFields = unknownFields).logSafeEventSummary(logger)
        val status =
            mullvad_daemon.management_interface.LocalNetworkStatus(
                current_wifi =
                    mullvad_daemon.management_interface.ConnectedWifi(
                        identity =
                            mullvad_daemon.management_interface.ConnectedWifi.Identity.Ssid(bytes)
                    ),
                unknownFields = unknownFields,
            )
        val statusEvent = DaemonEvent(event = DaemonEvent.Event.LocalNetworkStatus(status))
        DaemonEvent.ADAPTER.decode(DaemonEvent.ADAPTER.encode(statusEvent))
            .logSafeEventSummary(logger)
        assertEquals(
            listOf(
                "Event(type=settings local-rule-count=1)",
                "Event(type=unknown)",
                "Event(type=local-network-status)",
            ),
            messages,
        )
        val output = messages.joinToString("\n")
        for (secret in
            listOf(
                ssid,
                name,
                cidr,
                bytes.hex(),
                Base64.getEncoder().encodeToString(bytes.toByteArray()),
            )) {
            assertFalse(output.contains(secret))
        }
    }
}
