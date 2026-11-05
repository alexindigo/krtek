package net.mullvad.talpid

import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Process
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import io.mockk.verifyOrder
import java.net.InetAddress
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import net.mullvad.talpid.model.CaptureNetworkObservation
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class LocalCaptureNetworkObserverTest {
    private val connectivity = mockk<ConnectivityManager>(relaxed = true)
    private val callback = slot<ConnectivityManager.NetworkCallback>()
    private val output = mutableListOf<Triple<Long, Long, CaptureNetworkObservation>>()
    private lateinit var observer: LocalCaptureNetworkObserver
    private val builder = mockk<NetworkRequest.Builder>()
    private val request = mockk<NetworkRequest>()
    private var oldSdk = 0

    @BeforeEach
    fun setup() {
        oldSdk = Build.VERSION.SDK_INT
        LocalCaptureTestPlatform.setSdk(33)
        mockkStatic(Process::class)
        every { Process.myUid() } returns UID
        mockkConstructor(NetworkRequest.Builder::class)
        every { anyConstructed<NetworkRequest.Builder>().removeCapability(any()) } returns builder
        every { builder.addTransportType(any()) } returns builder
        every { builder.build() } returns request
        every {
            connectivity.registerNetworkCallback(any<NetworkRequest>(), capture(callback))
        } returns Unit
        observer = newObserver(11)
    }

    @AfterEach
    fun cleanup() {
        unmockkAll()
        LocalCaptureTestPlatform.setSdk(oldSdk)
    }

    private fun newObserver(generation: Long) =
        LocalCaptureNetworkObserver(connectivity, 9, generation) {
            registration,
            current,
            observation ->
            output += Triple(registration, current, observation)
        }

    private fun network(handle: Long): Network {
        val network = mockk<Network>()
        every { network.networkHandle } returns handle
        every { network.toString() } returns "257"
        return network
    }

    private fun capabilities(uid: Int = UID) =
        mockk<NetworkCapabilities> {
            every { hasTransport(NetworkCapabilities.TRANSPORT_VPN) } returns true
            every { ownerUid } returns uid
        }

    private fun links(name: String = "tun7") =
        mockk<LinkProperties> {
            every { interfaceName } returns name
            every { routes } returns emptyList()
            every { linkAddresses } returns
                listOf(
                    mockk<LinkAddress> {
                        every { address } returns
                            InetAddress.getByAddress(byteArrayOf(10, 64, 0, 2))
                        every { prefixLength } returns 32
                    }
                )
            every { dnsServers } returns listOf(InetAddress.getByAddress(byteArrayOf(10, 64, 0, 1)))
            every { mtu } returns 1380
        }

    @Test
    fun `should buffer both callback orders without publishing before fd interface binding`() {
        for (linksFirst in listOf(false, true)) {
            observer = newObserver(if (linksFirst) 12 else 11)
            observer.start()
            val network = network(HANDLE)
            if (linksFirst) callback.captured.onLinkPropertiesChanged(network, links())
            else callback.captured.onCapabilitiesChanged(network, capabilities())
            assertTrue(output.isEmpty())
            if (linksFirst) callback.captured.onCapabilitiesChanged(network, capabilities())
            else callback.captured.onLinkPropertiesChanged(network, links())
            assertTrue(output.isEmpty())
            assertTrue(observer.bind("tun7"))
            val (registration, generation, observed) = output.single()
            assertEquals(9L, registration)
            assertEquals(if (linksFirst) 12L else 11L, generation)
            assertEquals(HANDLE, observed.networkHandle)
            assertEquals("tun7", observed.interfaceName)
            assertEquals(UID, observed.ownerUid)
            assertEquals(1380, observed.mtu)
            assertEquals("10.64.0.2", observed.addresses.single().address.hostAddress)
            assertEquals("10.64.0.1", observed.dnsServers.single().hostAddress)
            assertTrue(observed.fresh)
            assertFalse(observed.lost)
            assertFalse(observer.bind("tun7"))
            observer.close()
            output.clear()
        }
        verifyOrder {
            anyConstructed<NetworkRequest.Builder>()
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            builder.addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            connectivity.registerNetworkCallback(
                request,
                any<ConnectivityManager.NetworkCallback>(),
            )
        }
        verify(exactly = 0) {
            connectivity.registerDefaultNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        }
    }

    @Test
    fun `should refuse foreign identity pin the first full handle and ignore retired callbacks`() {
        observer.start()
        observer.bind("tun7")
        val oldCallback = callback.captured
        val network = network(HANDLE)
        oldCallback.onLinkPropertiesChanged(network, links())
        oldCallback.onCapabilitiesChanged(network, capabilities(UID + 1))
        assertTrue(output.isEmpty())
        oldCallback.onCapabilitiesChanged(network, capabilities())
        assertEquals(1, output.size)
        val other = network(HANDLE + 1)
        oldCallback.onCapabilitiesChanged(other, capabilities())
        oldCallback.onLinkPropertiesChanged(other, links())
        oldCallback.onLost(other)
        assertEquals(1, output.size)
        observer.close()
        assertTrue(output.last().third.lost)
        val closedCount = output.size
        oldCallback.onCapabilitiesChanged(network, capabilities())
        oldCallback.onLinkPropertiesChanged(network, links())
        assertEquals(closedCount, output.size)
        observer = newObserver(12)
        observer.start()
        observer.bind("tun7")
        oldCallback.onLinkPropertiesChanged(network, links())
        assertEquals(closedCount, output.size)
        callback.captured.onCapabilitiesChanged(network, capabilities())
        callback.captured.onLinkPropertiesChanged(network, links())
        assertEquals(12L, output.last().second)
        callback.captured.onLost(network)
        assertTrue(output.last().third.lost)
    }

    @Test
    fun `should refuse wrong interfaces then publish same handle mismatch and loss without rebind`() {
        observer.start()
        observer.bind("tun7")
        val network = network(HANDLE)
        callback.captured.onCapabilitiesChanged(network, capabilities())
        callback.captured.onLinkPropertiesChanged(network, links("tun0"))
        assertTrue(output.isEmpty())
        callback.captured.onLinkPropertiesChanged(network, links())
        assertEquals(1, output.size)
        callback.captured.onLinkPropertiesChanged(network, links())
        assertEquals(1, output.size)
        callback.captured.onLinkPropertiesChanged(network, links("tun0"))
        assertEquals("tun0", output.last().third.interfaceName)
        callback.captured.onCapabilitiesChanged(network, capabilities(UID + 1))
        assertFalse(output.last().third.fresh)
        callback.captured.onLost(network)
        assertTrue(output.last().third.lost)
        val count = output.size
        callback.captured.onLinkPropertiesChanged(network, links())
        assertEquals(count, output.size)
    }

    @Test
    fun `should report registration failure and retain unregister error for a later release`() {
        every {
            connectivity.registerNetworkCallback(
                any<NetworkRequest>(),
                any<ConnectivityManager.NetworkCallback>(),
            )
        } throws SecurityException("denied")
        observer.start()
        assertEquals(0L, output.single().third.networkHandle)
        assertTrue(output.single().third.lost)
        assertFalse(observer.bind("tun7"))
        every {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        } throws SecurityException("retry")
        assertTrue(runCatching { observer.close() }.isFailure)
        every {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        } returns Unit
        observer.close()
        observer.close()
        verify(exactly = 2) {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        }
    }

    companion object {
        private const val UID = 10181
        private const val HANDLE = Long.MIN_VALUE + 0x1_0000_0001
    }
}
