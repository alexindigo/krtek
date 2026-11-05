package net.mullvad.mullvadvpn.lib.grpc

import arrow.core.Either
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import java.io.File
import kotlin.test.assertEquals
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import mullvad_daemon.management_interface.ConnectedWifi
import mullvad_daemon.management_interface.DaemonEvent
import mullvad_daemon.management_interface.LocalNetworkStatus
import mullvad_daemon.management_interface.ManagementServiceClient
import net.mullvad.mullvadvpn.lib.model.ApiAccessMethodSetting
import net.mullvad.mullvadvpn.lib.model.AppVersionInfo
import net.mullvad.mullvadvpn.lib.model.DeviceState
import net.mullvad.mullvadvpn.lib.model.RelayList
import net.mullvad.mullvadvpn.lib.model.Settings
import net.mullvad.mullvadvpn.lib.model.TunnelState
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class LocalNetworkStatusServiceTest {
    private fun wire(revision: Long, available: Boolean = true) =
        LocalNetworkStatus(
            revision = revision,
            observer_available = available,
            current_wifi =
                ConnectedWifi(
                    identity = ConnectedWifi.Identity.Unknown(ConnectedWifi.UnknownReason.PENDING)
                ),
        )

    private fun TestScope.service(
        rpc: ManagementServiceClient,
        events: Channel<DaemonEvent>,
    ): ManagementService {
        val service =
            spyk(
                ManagementService(
                    File("unused-status-test.sock"),
                    false,
                    backgroundScope,
                    StandardTestDispatcher(testScheduler),
                ),
                recordPrivateCalls = true,
            )
        every { service getProperty "grpc" } returns rpc
        coEvery { rpc.EventsListen().executeIn(any(), Unit) } returns events
        coEvery { service["getTunnelState"]() } returns mockk<TunnelState>()
        coEvery { service["getDeviceState"]() } returns mockk<DeviceState>()
        coEvery { service["getSettings"]() } returns mockk<Settings>()
        coEvery { service["getVersionInfo"]() } returns Either.Right(mockk<AppVersionInfo>())
        coEvery { service["getRelayList"]() } returns mockk<RelayList>()
        coEvery { service["getCurrentApiAccessMethod"]() } returns mockk<ApiAccessMethodSetting>()
        return service
    }

    @Test
    fun `should fill initial flow and ignore lower revision events but accept equal revisions`() =
        runTest {
            val rpc = mockk<ManagementServiceClient>(relaxed = true)
            val events = Channel<DaemonEvent>(Channel.UNLIMITED)
            coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } returns wire(7)
            val service = service(rpc, events)
            service.start()
            runCurrent()
            assertEquals(7uL, service.localNetworkStatus.value?.revision)
            events.send(DaemonEvent(event = DaemonEvent.Event.LocalNetworkStatus(wire(6, false))))
            runCurrent()
            assertEquals(true, service.localNetworkStatus.value?.observerAvailable)
            events.send(DaemonEvent(event = DaemonEvent.Event.LocalNetworkStatus(wire(7, false))))
            runCurrent()
            assertEquals(false, service.localNetworkStatus.value?.observerAvailable)
            service.stop()
        }

    @Test
    fun `should retain a newer event when the initial fetch finishes late including unsigned revisions`() =
        runTest {
            val rpc = mockk<ManagementServiceClient>(relaxed = true)
            val events = Channel<DaemonEvent>(Channel.UNLIMITED)
            val initial = CompletableDeferred<LocalNetworkStatus>()
            coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } coAnswers { initial.await() }
            val service = service(rpc, events)
            service.start()
            runCurrent()
            events.send(DaemonEvent(event = DaemonEvent.Event.LocalNetworkStatus(wire(-1))))
            runCurrent()
            initial.complete(wire(8, false))
            runCurrent()
            assertEquals(ULong.MAX_VALUE, service.localNetworkStatus.value?.revision)
            assertEquals(true, service.localNetworkStatus.value?.observerAvailable)
            service.stop()
        }

    @Test
    fun `should reset the revision baseline on resubscribe and expose the new initial status`() =
        runTest {
            val rpc = mockk<ManagementServiceClient>(relaxed = true)
            val events = Channel<DaemonEvent>(Channel.UNLIMITED)
            coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } returns wire(90)
            val service = service(rpc, events)
            service.start()
            runCurrent()
            assertEquals(90uL, service.localNetworkStatus.value?.revision)
            service.stop()
            runCurrent()
            coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } returns wire(1, false)
            service.start()
            runCurrent()
            assertEquals(1uL, service.localNetworkStatus.value?.revision)
            assertEquals(false, service.localNetworkStatus.value?.observerAvailable)
            service.stop()
        }
}
