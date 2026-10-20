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
import okio.ByteString.Companion.encodeUtf8
import org.junit.jupiter.api.Test

class SafeEventLogSummaryTest {
    @Test
    fun `should log only counts without private rule values or unknown fields`() {
        val ssid = "wifi-Ł船-marker"
        val name = "private-rule-marker"
        val cidr = "192.168.240.0/28"
        val bytes = ssid.encodeUtf8()
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
        DaemonEvent(unknownFields = bytes).logSafeEventSummary(logger)
        assertEquals(
            listOf("Event(type=settings local-rule-count=1)", "Event(type=unknown)"),
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
