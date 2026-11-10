package net.mullvad.talpid

import android.net.Network
import android.net.VpnService
import android.os.Looper
import android.os.ParcelFileDescriptor
import arrow.core.right
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import io.mockk.verifyOrder
import java.io.FileDescriptor
import java.lang.reflect.Proxy
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.common.util.prepareVpnSafe
import net.mullvad.mullvadvpn.lib.model.Prepared
import net.mullvad.talpid.model.CreateTunResult
import net.mullvad.talpid.model.LocalNetworkSnapshot
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class TalpidVpnServiceFrontendTest {
    private lateinit var service: FrontendService

    @BeforeEach
    fun setup() {
        mockkStatic("net.mullvad.mullvadvpn.lib.common.util.VpnServiceUtilsKt")
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk()
        service = spyk(FrontendService(), recordPrivateCalls = true)
        every { service getProperty "connectivityListener" } returns
            mockk<ConnectivityListener>(relaxed = true)
        every { service.prepareVpnSafe() } returns Prepared.right()
        mockkConstructor(VpnService.Builder::class)
        val builder = mockk<VpnService.Builder>(relaxed = true)
        every { anyConstructed<VpnService.Builder>().addAddress(any<String>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addAddress(any<InetAddress>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addDnsServer(any<String>()) } returns builder
        every { anyConstructed<VpnService.Builder>().addRoute(any<InetAddress>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addRoute(any<String>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().setMtu(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().setBlocking(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().addDisallowedApplication(any()) } returns
            builder
        val fd = mockk<ParcelFileDescriptor>()
        every { anyConstructed<VpnService.Builder>().establish() } returns fd
        every { fd.fd } returns 7
        every { fd.detachFd() } returns 7
        every { fd.close() } returns Unit
    }

    @AfterEach fun cleanup() = unmockkAll()

    @Test
    fun `should configure zero DNS servers on initial and replacement frontends without a watcher`() {
        val expectedRoutes = mutableListOf<Pair<InetAddress, Int>>()
        for (routes in
            listOf(
                arrayOf("10.0.2.2/32"),
                arrayOf("fd42::/64"),
                arrayOf("169.254.0.0/16", "fe80::/10"),
            )) {
            assertEquals(CreateTunResult.Success(7), service.openLocalFrontend(1, routes))
            expectedRoutes += routes.map {
                InetAddress.getByName(it.substringBefore('/')) to it.substringAfter('/').toInt()
            }
            verify(exactly = expectedRoutes.size) {
                anyConstructed<VpnService.Builder>().addRoute(any<InetAddress>(), any())
            }
            for ((address, prefix) in expectedRoutes.distinct()) {
                verify(exactly = expectedRoutes.count { it == (address to prefix) }) {
                    anyConstructed<VpnService.Builder>().addRoute(address, prefix)
                }
            }
            verify(exactly = 0) {
                anyConstructed<VpnService.Builder>().addRoute(any<InetAddress>(), 0)
            }
            verify(exactly = 0) {
                anyConstructed<VpnService.Builder>().addRoute(any<String>(), any())
            }
            verify(exactly = 0) { anyConstructed<VpnService.Builder>().allowBypass() }
            assertTrue(service.isLocalFrontendActive())
            assertEquals(CreateTunResult.EstablishError, service.openLocalFrontend(1, routes))
            assertEquals(
                CreateTunResult.EstablishError,
                service.openTun(TalpidVpnServiceFallbackDnsTest.baseTunConfig),
            )
            service.onRevoke()
            assertEquals(4, service.prepareLocalSocket(7, 9, 1, false))
            assertTrue(service.isLocalFrontendActive())
            service.finishLocalFrontend(1)
            assertFalse(service.isLocalFrontendActive())
        }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().addDnsServer(any<String>()) }
        verify(exactly = 0) {
            anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>())
        }
        verify(exactly = 3) { anyConstructed<VpnService.Builder>().addAddress("192.0.2.2", 32) }
        verify(exactly = 3) { anyConstructed<VpnService.Builder>().addAddress("2001:db8::2", 128) }
        verify(exactly = 3) { anyConstructed<VpnService.Builder>().establish() }
    }

    @Test
    fun `should apply exact exclusions on initial and replacement Partial frontends`() {
        val excluded = arrayOf("com.android.deskclock", "com.android.calendar")
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(11, arrayOf("10.0.2.2/32"), excluded),
        )
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverLocalFrontend(11, 12, arrayOf("10.0.2.99/32"), excluded).result,
        )
        service.finishLocalFrontend(11)
        service.finishLocalFrontend(12)
        for (app in excluded) {
            verify(exactly = 2) {
                anyConstructed<VpnService.Builder>().addDisallowedApplication(app)
            }
        }
        verify(exactly = 4) { anyConstructed<VpnService.Builder>().addDisallowedApplication(any()) }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().addDnsServer(any<String>()) }
        verify(exactly = 0) {
            anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>())
        }
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(13, arrayOf("10.0.2.2/32")),
        )
        verify(exactly = 4) { anyConstructed<VpnService.Builder>().addDisallowedApplication(any()) }
        service.finishLocalFrontend(13)
    }

    @Test
    fun `should reject invalid routes before prepare and establish without acquiring ownership`() {
        for (routes in
            listOf(
                emptyArray(),
                arrayOf("0.0.0.0/0"),
                arrayOf("localhost/32"),
                arrayOf("10.0.2.2/24"),
            )) {
            assertEquals(CreateTunResult.EstablishError, service.openLocalFrontend(1, routes))
            assertFalse(service.isLocalFrontendActive())
        }
        verify(exactly = 0) { service.prepareVpnSafe() }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().establish() }
    }

    @Test
    fun `should release ownership after establishment failure for a later attempt`() {
        every { anyConstructed<VpnService.Builder>().establish() } returns null
        assertEquals(
            CreateTunResult.EstablishError,
            service.openLocalFrontend(1, arrayOf("10.0.0.0/8")),
        )
        assertFalse(service.isLocalFrontendActive())
        assertEquals(4, service.prepareLocalSocket(7, 9, 1, false))
    }

    @Test
    fun `should keep foreground after a concurrent frontend open during guarded demotion`() {
        val attempted = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val result = AtomicReference<CreateTunResult>()
        var opener: Thread? = null
        service.demote {
            opener = thread {
                attempted.countDown()
                try {
                    result.set(service.openLocalFrontend(1, arrayOf("10.0.2.2/32")))
                } finally {
                    finished.countDown()
                }
            }
            assertTrue(attempted.await(1, TimeUnit.SECONDS))
            finished.await(100, TimeUnit.MILLISECONDS)
            service.foreground = false
        }
        assertTrue(finished.await(2, TimeUnit.SECONDS))
        opener?.join(2000)
        assertEquals(CreateTunResult.Success(7), result.get())
        assertTrue(service.foreground, "concurrent frontend was demoted after its promotion")
        service.demote { error("an active frontend must not be demoted") }
        service.finishLocalFrontend(1)
    }

    @Test
    fun `should release upstream ownership after a closed open result`() {
        every { anyConstructed<VpnService.Builder>().establish() } returns null
        assertEquals(
            CreateTunResult.EstablishError,
            service.openTun(TalpidVpnServiceFallbackDnsTest.baseTunConfig),
        )
        val fd = mockk<ParcelFileDescriptor>()
        every { anyConstructed<VpnService.Builder>().establish() } returns fd
        every { fd.fd } returns 8
        every { fd.close() } returns Unit
        assertEquals(
            CreateTunResult.Success(8),
            service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
        )
        service.finishLocalFrontend(1)
    }

    @Test
    fun `should retain upstream ownership for descriptor bearing errors until close`() {
        mockkStatic(ParcelFileDescriptor::class)
        val closed = mockk<ParcelFileDescriptor>(relaxed = true)
        every { ParcelFileDescriptor.adoptFd(7) } returns closed
        val config =
            TalpidVpnServiceFallbackDnsTest.baseTunConfig.copy(
                dnsServers = arrayListOf(InetAddress.getByName("1.1.1.1"))
            )
        every { anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>()) } throws
            IllegalArgumentException("invalid DNS")
        val invalidDns = service.openTun(config)
        assertTrue(invalidDns is CreateTunResult.InvalidDnsServers && invalidDns.isOpen)
        assertEquals(
            CreateTunResult.EstablishError,
            service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
        )
        service.closeTun()
        every { anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>()) } returns
            mockk(relaxed = true)
        val invalidIpv6 =
            service.openTun(config.copy(dnsServers = arrayListOf(InetAddress.getByName("::1"))))
        assertTrue(invalidIpv6 is CreateTunResult.InvalidIpv6Config && invalidIpv6.isOpen)
        assertEquals(
            CreateTunResult.EstablishError,
            service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
        )
        service.closeTun()
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
        )
        verify(exactly = 2) { closed.close() }
        service.finishLocalFrontend(1)
    }

    private class FrontendService : TalpidVpnService() {
        @Volatile var foreground = false
        var failDemotion = false
        val changes = mutableListOf<Boolean>()

        fun demote(action: () -> Unit) = withoutLocalFrontend(action)

        override fun onLocalFrontendChanged(active: Boolean) {
            if (!active && failDemotion) error("foreground release acknowledgement")
            changes += active
            foreground = active
        }
    }

    @Test
    fun `should retain foreground through handover and ignore predecessor finish after successor opens`() {
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(11, arrayOf("10.0.2.2/32")),
        )
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverLocalFrontend(11, 12, arrayOf("10.0.2.99/32")).result,
        )
        service.demote { error("handover lost foreground ownership") }
        service.finishLocalFrontend(11)
        service.finishLocalFrontend(11)
        assertTrue(service.foreground)
        assertTrue(service.changes.all { it })
        service.demote { error("late predecessor finish demoted successor") }
        service.finishLocalFrontend(12)
        assertFalse(service.foreground)
        assertEquals(listOf(true, true, false), service.changes)
        service.demote { service.foreground = false }
    }

    @Test
    fun `should retain final epoch and foreground after failed demotion until exact finish retry`() {
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(11, arrayOf("10.0.2.2/32")),
        )
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverLocalFrontend(11, 12, arrayOf("10.0.2.99/32")).result,
        )
        service.failDemotion = true
        service.finishLocalFrontend(11)
        assertTrue(runCatching { service.finishLocalFrontend(12) }.isFailure)
        assertTrue(service.isLocalFrontendActive())
        assertTrue(service.foreground)
        assertEquals(
            CreateTunResult.EstablishError,
            service.openLocalFrontend(13, arrayOf("10.0.2.99/32")),
        )
        service.failDemotion = false
        service.finishLocalFrontend(11)
        assertTrue(service.foreground)
        service.finishLocalFrontend(12)
        assertFalse(service.foreground)
        assertFalse(service.isLocalFrontendActive())
        assertEquals(listOf(true, true, false), service.changes)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `should prepare through the actual service gate with both framework calls under its lock`() =
        runTest {
            val network = mockk<Network>()
            val fixture =
                WatcherFixture(backgroundScope, StandardTestDispatcher(testScheduler), network)
            TalpidVpnService::class.java.getDeclaredField("localNetworkWatcher").apply {
                isAccessible = true
                set(service, fixture.watcher)
            }
            fixture.invoke("start")
            fixture.invoke("attach", 1L)
            fixture.event("Available", 9L, false)
            runCurrent()
            assertEquals(
                CreateTunResult.Success(7),
                service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
            )
            every { service.protect(7) } returns true
            assertEquals(1, service.prepareLocalSocket(7, 9, fixture.sequence - 1, false))
            fixture.event("Available", 10L, false)
            assertEquals(1, service.prepareLocalSocket(7, 9, fixture.sequence, false))
            verify(exactly = 0) { service.protect(any<Int>()) }
            verify(exactly = 0) { network.bindSocket(any<FileDescriptor>()) }
            runCurrent()

            val attempted = CountDownLatch(1)
            val completed = CountDownLatch(1)
            var update: Thread? = null
            mockkStatic(ParcelFileDescriptor::class)
            val duplicate = mockk<ParcelFileDescriptor>()
            val descriptor = FileDescriptor()
            every { ParcelFileDescriptor.fromFd(7) } returns duplicate
            every { duplicate.fileDescriptor } returns descriptor
            every { duplicate.close() } returns Unit
            every { service.protect(7) } answers
                {
                    assertTrue(Thread.holdsLock(fixture.lock), "protect escaped the watcher gate")
                    update = thread {
                        attempted.countDown()
                        fixture.event("Lost", 9L)
                        completed.countDown()
                    }
                    assertTrue(attempted.await(1, TimeUnit.SECONDS))
                    assertFalse(completed.await(100, TimeUnit.MILLISECONDS))
                    true
                }
            every { network.bindSocket(descriptor) } answers
                {
                    assertTrue(Thread.holdsLock(fixture.lock), "bind escaped the watcher gate")
                    assertEquals(1L, completed.count)
                }
            try {
                assertEquals(0, service.prepareLocalSocket(7, 9, fixture.sequence, false))
                assertTrue(completed.await(1, TimeUnit.SECONDS))
                update?.join(1000)
                assertEquals(1, service.prepareLocalSocket(7, 9, fixture.sequence, false))
                verify(exactly = 1) { service.protect(7) }
                verify(exactly = 1) { network.bindSocket(descriptor) }
                verifyOrder {
                    service.protect(7)
                    ParcelFileDescriptor.fromFd(7)
                    network.bindSocket(descriptor)
                    duplicate.close()
                }
            } finally {
                fixture.invoke("stop")
                service.finishLocalFrontend(1)
                update?.join(1000)
            }
        }

    /** Reflection is confined to this test: the app must not expose a watcher injection API. */
    private class WatcherFixture(
        scope: CoroutineScope,
        dispatcher: CoroutineDispatcher,
        network: Network,
    ) {
        private val sourceType = Class.forName("net.mullvad.talpid.LocalNetworkSource")
        private val watcherType = Class.forName("net.mullvad.talpid.LocalNetworkWatcher")
        private var callback: (Any) -> Unit = {}
        var sequence = 0L
        private val access =
            Class.forName("net.mullvad.talpid.LocalIdentityAccess")
                .getDeclaredConstructor(*Array(5) { Boolean::class.javaPrimitiveType })
                .newInstance(true, true, true, true, true)
        @Suppress("UNCHECKED_CAST")
        private val source =
            Proxy.newProxyInstance(sourceType.classLoader, arrayOf(sourceType)) { _, method, args ->
                when (method.name) {
                    "readAccess" -> access
                    "network" -> network
                    "withLegacyIdentity" -> args[0]
                    "start" -> {
                        callback = args[1] as (Any) -> Unit
                        Unit
                    }
                    "stop" -> Unit
                    else -> error("Unexpected source call ${method.name}")
                }
            }
        private val publish: (Long, LocalNetworkSnapshot) -> Unit = { _, record ->
            sequence = record.sequence
        }
        val watcher: Any =
            watcherType
                .getDeclaredConstructor(
                    sourceType,
                    CoroutineScope::class.java,
                    CoroutineDispatcher::class.java,
                    Function2::class.java,
                )
                .newInstance(source, scope, dispatcher, publish)
        val lock: Any =
            checkNotNull(
                watcherType.getDeclaredField("lock").apply { isAccessible = true }.get(watcher)
            )

        fun invoke(name: String, vararg args: Any) {
            watcherType.declaredMethods.single { it.name == name }.invoke(watcher, *args)
        }

        fun event(name: String, vararg args: Any) {
            val type = Class.forName("net.mullvad.talpid.LocalNetworkEvent\$$name")
            callback(
                type.declaredConstructors
                    .single { it.parameterCount == args.size }
                    .newInstance(*args)
            )
        }
    }
}
