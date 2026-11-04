package net.mullvad.talpid

import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.RouteInfo
import android.net.VpnService
import android.os.Build
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import arrow.core.right
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import java.net.InetAddress
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import net.mullvad.mullvadvpn.lib.common.util.prepareVpnSafe
import net.mullvad.mullvadvpn.lib.model.Prepared
import net.mullvad.talpid.model.CaptureNetworkObservation
import net.mullvad.talpid.model.CreateTunResult
import net.mullvad.talpid.model.InetNetwork
import net.mullvad.talpid.model.TunConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class LocalCaptureServiceTest {
    private lateinit var service: TalpidVpnService
    private lateinit var descriptor: ParcelFileDescriptor
    private val connectivity = mockk<ConnectivityManager>(relaxed = true)
    private val callbacks = mutableListOf<ConnectivityManager.NetworkCallback>()
    private val publications = mutableListOf<Triple<Long, Long, CaptureNetworkObservation>>()
    private val sdkField = Build.VERSION::class.java.getDeclaredField("SDK_INT")
    private var oldSdk = 0
    private val config =
        TunConfig(
            arrayListOf(ip("10.64.0.2"), ip("fd42::2")),
            arrayListOf(ip("10.64.0.1"), ip("fd42::1")),
            arrayListOf(InetNetwork(ip("0.0.0.0"), 0), InetNetwork(ip("::"), 0)),
            arrayListOf("example.excluded"),
            1420,
        )

    @BeforeEach
    fun setup() {
        // Stage only the JVM's platform constant, then restore it after each test.
        // The SDK jar retains a final field, so ordinary Field.setInt cannot set it.
        oldSdk = sdkField.getInt(null)
        setSdk(Build.VERSION_CODES.TIRAMISU)
        mockkStatic("net.mullvad.mullvadvpn.lib.common.util.VpnServiceUtilsKt")
        mockkStatic(Looper::class)
        mockkStatic(Process::class)
        every { Looper.getMainLooper() } returns mockk()
        every { Process.myUid() } returns UID
        service = spyk(TalpidVpnService())
        service.connectivityListener = mockk(relaxed = true)
        every { service.prepareVpnSafe() } returns Prepared.right()
        every { service.getSystemService(ConnectivityManager::class.java) } returns connectivity
        every { service.getSystemService(android.content.Context.CONNECTIVITY_SERVICE) } returns
            connectivity
        mockkConstructor(VpnService.Builder::class)
        val builder = mockk<VpnService.Builder>(relaxed = true)
        every { anyConstructed<VpnService.Builder>().setMtu(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().setBlocking(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().setMetered(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().addAddress(any<InetAddress>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addAddress(any<String>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addRoute(any<InetAddress>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addDisallowedApplication(any()) } returns
            builder
        descriptor = mockk<ParcelFileDescriptor>()
        every { anyConstructed<VpnService.Builder>().establish() } returns descriptor
        every { descriptor.detachFd() } returns 7
        every { descriptor.close() } returns Unit
        mockkConstructor(NetworkRequest.Builder::class)
        val requestBuilder = mockk<NetworkRequest.Builder>()
        every { anyConstructed<NetworkRequest.Builder>().removeCapability(any()) } returns
            requestBuilder
        every { requestBuilder.addTransportType(any()) } returns requestBuilder
        every { requestBuilder.build() } returns mockk()
        val callback = slot<ConnectivityManager.NetworkCallback>()
        every {
            connectivity.registerNetworkCallback(any<NetworkRequest>(), capture(callback))
        } answers
            {
                callbacks += callback.captured
                // Keep the actual service-created observer and all callback logic.
                // This JVM cannot execute Android JNI; capture its existing injected
                // publication closure at the same boundary as the observer unit tests.
                val observer =
                    checkNotNull(
                        TalpidVpnService::class
                            .java
                            .getDeclaredField("captureObserver")
                            .apply { isAccessible = true }
                            .get(service)
                    )
                val publish: (Long, Long, CaptureNetworkObservation) -> Unit =
                    { registration, generation, observation ->
                        publications += Triple(registration, generation, observation)
                    }
                LocalCaptureNetworkObserver::class
                    .java
                    .getDeclaredField("publish")
                    .apply { isAccessible = true }
                    .set(observer, publish)
            }
        assertTrue(service.attachCaptureNetwork(9))
    }

    @AfterEach
    fun cleanup() {
        unmockkAll()
        setSdk(oldSdk)
    }

    private fun setSdk(value: Int) {
        val type = Class.forName("sun.misc.Unsafe")
        val unsafe = type.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null)
        val base =
            type
                .getMethod("staticFieldBase", java.lang.reflect.Field::class.java)
                .invoke(unsafe, sdkField)
        val offset =
            type
                .getMethod("staticFieldOffset", java.lang.reflect.Field::class.java)
                .invoke(unsafe, sdkField)
        type
            .getMethod(
                "putIntVolatile",
                Any::class.java,
                Long::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
            )
            .invoke(unsafe, base, offset, value)
        assertEquals(value, sdkField.getInt(null))
    }

    @Test
    fun `should configure assigned capture exactly without synthetic fields or Native cache`() {
        assertEquals(CreateTunResult.Success(7), service.openSecuredFrontend(11, config))
        config.addresses.forEach {
            verify(exactly = 1) {
                anyConstructed<VpnService.Builder>()
                    .addAddress(it, if (it.address.size == 4) 32 else 128)
            }
        }
        config.routes.forEach {
            verify(exactly = 1) {
                anyConstructed<VpnService.Builder>().addRoute(it.address, it.prefixLength.toInt())
            }
        }
        config.dnsServers.forEach {
            verify(exactly = 1) { anyConstructed<VpnService.Builder>().addDnsServer(it) }
        }
        verify(exactly = 1) { anyConstructed<VpnService.Builder>().setMtu(1420) }
        verify(exactly = 1) {
            anyConstructed<VpnService.Builder>().addDisallowedApplication("example.excluded")
        }
        verify(exactly = 0) {
            anyConstructed<VpnService.Builder>().addAddress(any<String>(), any())
        }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().addDnsServer(any<String>()) }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().allowBypass() }
        assertEquals(CreateTunResult.EstablishError, service.openTun(config))
        assertEquals(CreateTunResult.EstablishError, service.openSecuredFrontend(12, config))
        // Native cache invalidation cannot invent a capture observation or change ownership.
        service.closeTun()
        assertTrue(service.isLocalFrontendActive())
        assertTrue(publications.isEmpty())
        service.finishLocalFrontend()
        assertFalse(service.isLocalFrontendActive())
    }

    @Test
    fun `should push only the fd bound generation and ignore replaced callbacks after cache clearing`() {
        assertEquals(CreateTunResult.Success(7), service.openSecuredFrontend(11, config))
        val old = callbacks.single()
        val network = network(HANDLE)
        old.onLinkPropertiesChanged(network, links("tun7"))
        old.onCapabilitiesChanged(network, capabilities(UID))
        assertTrue(publications.isEmpty())
        assertFalse(service.bindLocalFrontend(10, "tun7"))
        assertTrue(service.bindLocalFrontend(11, "tun7"))
        val pushed = publications.single()
        assertEquals(9L, pushed.first)
        assertEquals(11L, pushed.second)
        assertEquals(HANDLE, pushed.third.networkHandle)
        assertEquals("257", pushed.third.network)
        assertEquals(UID, pushed.third.ownerUid)
        assertEquals("tun7", pushed.third.interfaceName)
        assertEquals(config.addresses, pushed.third.addresses.map { it.address })
        assertEquals(config.dnsServers, pushed.third.dnsServers)
        assertEquals(config.routes, pushed.third.routes.map { it.destination })
        assertTrue(pushed.third.routes.all { it.routeType == 1 })
        assertEquals(config.mtu, pushed.third.mtu)
        assertTrue(pushed.third.fresh)
        val foreign = network(HANDLE + 1)
        old.onCapabilitiesChanged(foreign, capabilities(UID))
        old.onLinkPropertiesChanged(foreign, links("tun7"))
        assertEquals(1, publications.size)
        service.finishLocalFrontend()
        assertTrue(publications.last().third.lost)
        val count = publications.size
        assertEquals(CreateTunResult.Success(7), service.openSecuredFrontend(12, config))
        service.closeTun()
        old.onCapabilitiesChanged(network, capabilities(UID))
        old.onLinkPropertiesChanged(network, links("tun7"))
        assertEquals(count, publications.size)
        assertFalse(service.bindLocalFrontend(11, "tun7"))
        assertTrue(service.bindLocalFrontend(12, "tun7"))
        val current = callbacks.last()
        current.onCapabilitiesChanged(foreign, capabilities(UID + 1))
        current.onLinkPropertiesChanged(foreign, links("tun7"))
        assertEquals(count, publications.size)
        current.onCapabilitiesChanged(foreign, capabilities(UID))
        assertEquals(12L, publications.last().second)
        assertEquals(HANDLE + 1, publications.last().third.networkHandle)
        current.onLost(foreign)
        assertTrue(publications.last().third.lost)
        service.finishLocalFrontend()
    }

    @Test
    fun `should invalidate before fallible unregister and retain ownership until finish retry`() {
        assertEquals(CreateTunResult.Success(7), service.openSecuredFrontend(11, config))
        val callback = callbacks.single()
        val network = network(HANDLE)
        service.bindLocalFrontend(11, "tun7")
        callback.onCapabilitiesChanged(network, capabilities(UID))
        callback.onLinkPropertiesChanged(network, links("tun7"))
        every {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        } throws SecurityException("retry")
        assertTrue(runCatching { service.finishLocalFrontend() }.isFailure)
        assertTrue(publications.last().third.lost)
        assertTrue(service.isLocalFrontendActive())
        assertEquals(CreateTunResult.EstablishError, service.openSecuredFrontend(12, config))
        val count = publications.size
        callback.onLinkPropertiesChanged(network, links("tun7"))
        assertEquals(count, publications.size)
        every {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        } returns Unit
        service.finishLocalFrontend()
        service.finishLocalFrontend()
        assertFalse(service.isLocalFrontendActive())
        verify(exactly = 2) {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        }
    }

    @Test
    fun `should refuse inexact secured configuration before establishment`() {
        for (invalid in
            listOf(
                config.copy(addresses = arrayListOf()),
                config.copy(addresses = arrayListOf(ip("0.0.0.0"))),
                config.copy(routes = arrayListOf()),
                config.copy(dnsServers = arrayListOf()),
                config.copy(mtu = 1279),
                config.copy(addresses = arrayListOf(ip("10.64.0.2"))),
            )) {
            assertEquals(CreateTunResult.EstablishError, service.openSecuredFrontend(11, invalid))
            assertFalse(service.isLocalFrontendActive())
        }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().establish() }
    }

    @Test
    fun `should retain failed startup observer cleanup until explicit finish retry`() {
        every { descriptor.detachFd() } throws IllegalStateException("detach")
        every {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        } throws SecurityException("retry")
        assertTrue(runCatching { service.openSecuredFrontend(11, config) }.isFailure)
        verify(exactly = 1) { descriptor.close() }
        assertTrue(service.isLocalFrontendActive())
        assertFalse(service.bindLocalFrontend(11, "tun7"))
        assertEquals(CreateTunResult.EstablishError, service.openSecuredFrontend(12, config))
        assertTrue(runCatching { service.finishLocalFrontend() }.isFailure)
        val old = callbacks.single()
        old.onCapabilitiesChanged(network(HANDLE), capabilities(UID))
        old.onLinkPropertiesChanged(network(HANDLE), links("tun7"))
        assertTrue(publications.isEmpty())
        every {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        } returns Unit
        service.finishLocalFrontend()
        assertFalse(service.isLocalFrontendActive())
        every { descriptor.detachFd() } returns 7
        assertEquals(CreateTunResult.Success(7), service.openSecuredFrontend(12, config))
        old.onLinkPropertiesChanged(network(HANDLE), links("tun7"))
        assertTrue(publications.isEmpty())
        service.finishLocalFrontend()
    }

    @Test
    fun `should release observer allocated before failed descriptor detach`() {
        every { descriptor.detachFd() } throws IllegalStateException("detach")
        assertEquals(CreateTunResult.EstablishError, service.openSecuredFrontend(11, config))
        assertFalse(service.isLocalFrontendActive())
        verify(exactly = 1) { descriptor.close() }
        verify(exactly = 1) {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        }
        val old = callbacks.single()
        old.onCapabilitiesChanged(network(HANDLE), capabilities(UID))
        old.onLinkPropertiesChanged(network(HANDLE), links("tun7"))
        assertTrue(publications.isEmpty())
        service.finishLocalFrontend()
        verify(exactly = 1) {
            connectivity.unregisterNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        }
    }

    @Test
    fun `should keep Partial independent of capture observation on every supported API`() {
        assertTrue(service.detachCaptureNetwork(9))
        for (api in listOf(28, 30, 32, 33)) {
            setSdk(api)
            assertEquals(
                CreateTunResult.Success(7),
                service.openLocalFrontend(11, arrayOf("10.0.2.2/32")),
            )
            assertTrue(service.isLocalFrontendActive())
            assertFalse(service.bindLocalFrontend(11, "tun7"))
            service.finishLocalFrontend()
            assertFalse(service.isLocalFrontendActive())
            assertEquals(
                CreateTunResult.Success(7),
                service.openLocalFrontend(12, arrayOf("10.0.2.99/32")),
            )
            service.finishLocalFrontend()
            service.finishLocalFrontend()
            assertFalse(service.isLocalFrontendActive())
        }
        assertTrue(callbacks.isEmpty())
        verify(exactly = 0) {
            connectivity.registerNetworkCallback(
                any<NetworkRequest>(),
                any<ConnectivityManager.NetworkCallback>(),
            )
        }
        verify(exactly = 0) {
            anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>())
        }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().allowBypass() }
        verify(exactly = 8) { descriptor.detachFd() }
        verify(exactly = 4) { anyConstructed<VpnService.Builder>().addRoute(ip("10.0.2.2"), 32) }
        verify(exactly = 4) { anyConstructed<VpnService.Builder>().addRoute(ip("10.0.2.99"), 32) }
        verify(exactly = 8) { anyConstructed<VpnService.Builder>().setMtu(1280) }
    }

    @Test
    fun `should report only public Secured properties at each supported API`() {
        for (api in listOf(28, 29, 30, 32, 33)) {
            setSdk(api)
            assertEquals(
                CreateTunResult.Success(7),
                service.openSecuredFrontend(api.toLong(), config),
            )
            val callback = callbacks.last()
            val caps = capabilities(UID)
            val lp = links("tun7")
            callback.onCapabilitiesChanged(network(HANDLE), caps)
            callback.onLinkPropertiesChanged(network(HANDLE), lp)
            assertTrue(service.bindLocalFrontend(api.toLong(), "tun7"))
            val observation = publications.last().third
            assertEquals(api, observation.apiLevel)
            assertEquals(if (api >= 30) UID else null, observation.ownerUid)
            assertEquals(if (api >= 29) config.mtu else null, observation.mtu)
            assertTrue(observation.routes.all { it.routeType == if (api >= 33) 1 else null })
            if (api < 30) verify(exactly = 0) { caps.ownerUid }
            if (api < 29) verify(exactly = 0) { lp.mtu }
            if (api < 33) lp.routes.forEach { route -> verify(exactly = 0) { route.type } }
            service.finishLocalFrontend()
            assertTrue(publications.last().third.lost)
        }
    }

    private fun network(handle: Long): Network {
        val network = mockk<Network>()
        every { network.networkHandle } returns handle
        every { network.toString() } returns "257"
        return network
    }

    private fun capabilities(uid: Int) =
        mockk<NetworkCapabilities> {
            every { ownerUid } returns uid
            every { hasTransport(NetworkCapabilities.TRANSPORT_VPN) } returns true
        }

    private fun links(name: String) =
        mockk<LinkProperties> {
            every { interfaceName } returns name
            every { mtu } returns config.mtu
            every { dnsServers } returns config.dnsServers
            every { linkAddresses } returns
                config.addresses.map { address ->
                    mockk<LinkAddress> link@{
                        every { this@link.address } returns address
                        every { prefixLength } returns if (address.address.size == 4) 32 else 128
                    }
                }
            every { routes } returns
                config.routes.map { prefix ->
                    mockk<RouteInfo> {
                        every { destination } returns
                            mockk {
                                every { address } returns prefix.address
                                every { prefixLength } returns prefix.prefixLength.toInt()
                            }
                        every { gateway } returns null
                        every { `interface` } returns name
                        every { type } returns 1
                    }
                }
        }

    companion object {
        private const val UID = 10181
        private const val HANDLE = Long.MIN_VALUE + 0x1_0000_0001

        private fun ip(text: String) = InetAddress.getByName(text)
    }
}
