package net.mullvad.talpid

import java.lang.reflect.Modifier
import java.net.InetAddress
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.talpid.model.InetNetwork
import net.mullvad.talpid.model.LocalNetworkSnapshot
import net.mullvad.talpid.model.LocalPhysicalAddress
import net.mullvad.talpid.model.LocalPhysicalNetwork
import net.mullvad.talpid.model.LocalPhysicalRoute
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class LocalNetworkWatcherTest {
    @Test
    fun `should build complete physical records and coalesce fake callbacks`() = runTest {
        val source = FakeSource()
        val pushes = mutableListOf<LocalNetworkSnapshot>()
        val watcher =
            LocalNetworkWatcher(source, backgroundScope, StandardTestDispatcher(testScheduler)) {
                id,
                value ->
                assertEquals(7L, id)
                pushes += value
            }
        watcher.start()
        assertTrue(watcher.attach(7))
        runCurrent()
        assertEquals(1, pushes.size)
        assertTrue(pushes.single().networks.isEmpty())
        source.emit(LocalNetworkEvent.Available(9, true))
        val prefix = InetNetwork(InetAddress.getByName("192.0.2.2"), 24)
        source.emit(
            LocalNetworkEvent.Update(9) {
                it.copy(transport = 1, capabilitiesFresh = true, ssidHex = "70726976617465")
            }
        )
        source.emit(
            LocalNetworkEvent.Update(9) {
                it.copy(
                    blocked = false,
                    linksFresh = true,
                    interfaceIndex = 4,
                    addresses = arrayListOf(LocalPhysicalAddress(prefix, true)),
                    routes = arrayListOf(LocalPhysicalRoute(prefix, null, 4, 1)),
                )
            }
        )
        runCurrent()
        assertEquals(2, pushes.size)
        val network = pushes.last().networks.single()
        assertEquals(9L, network.networkHandle)
        assertEquals(1, network.transport)
        assertTrue(network.capabilitiesFresh && network.linksFresh)
        assertFalse(network.blocked)
        assertEquals(4, network.interfaceIndex)
        assertEquals(prefix, network.addresses.single().prefix)
        assertEquals(prefix, network.routes.single().destination)
        assertEquals("70726976617465", network.ssidHex)
        source.emit(LocalNetworkEvent.Lost(9))
        runCurrent()
        assertTrue(pushes.last().networks.isEmpty())
        assertEquals(listOf(1L, 2L, 3L), pushes.map { it.sequence })
        watcher.stop()
    }

    @Test
    fun `should omit names without identity access but retain physical records`() = runTest {
        for (access in
            listOf(
                LocalIdentityAccess(true, false, true, true, true),
                LocalIdentityAccess(true, true, false, true, true),
                LocalIdentityAccess(true, true, true, false, true),
                LocalIdentityAccess(true, true, true, true, false),
            )) {
            val source = FakeSource(access)
            val pushes = mutableListOf<LocalNetworkSnapshot>()
            val watcher =
                LocalNetworkWatcher(
                    source,
                    backgroundScope,
                    StandardTestDispatcher(testScheduler),
                ) { _, value ->
                    pushes += value
                }
            watcher.start()
            watcher.attach(1)
            source.emit(LocalNetworkEvent.Available(9, false))
            source.emit(LocalNetworkEvent.Update(9) { it.copy(transport = 1, ssidHex = "6162") })
            runCurrent()
            assertTrue(pushes.last().localReady)
            assertEquals(1, pushes.last().networks.size)
            assertNull(pushes.last().networks.single().ssidHex)
            watcher.stop()
        }
    }

    @Test
    fun `should reregister on permission refresh and ignore stale callbacks`() = runTest {
        val source = FakeSource()
        val pushes = mutableListOf<LocalNetworkSnapshot>()
        val watcher =
            LocalNetworkWatcher(source, backgroundScope, StandardTestDispatcher(testScheduler)) {
                _,
                value ->
                pushes += value
            }
        watcher.start()
        watcher.attach(1)
        val oldCallback = source.event
        source.access = source.access.copy(fine = false)
        source.changed()
        runCurrent()
        assertEquals(listOf(true, false), source.flags)
        oldCallback(LocalNetworkEvent.Available(9, false))
        runCurrent()
        assertTrue(pushes.last().networks.isEmpty())
        assertFalse(pushes.last().fineReady)
        source.access = source.access.copy(fine = true)
        source.changed()
        runCurrent()
        assertEquals(listOf(true, false, true), source.flags)
        assertTrue(pushes.last().networks.isEmpty())
        watcher.stop()
    }

    @Test
    fun `should restart after stop with increasing sequence and inert old registration`() =
        runTest {
            val source = FakeSource()
            val pushes = mutableListOf<Pair<Long, LocalNetworkSnapshot>>()
            val watcher =
                LocalNetworkWatcher(
                    source,
                    backgroundScope,
                    StandardTestDispatcher(testScheduler),
                ) { id, value ->
                    pushes += id to value
                }
            watcher.start()
            assertTrue(watcher.attach(1))
            assertFalse(watcher.attach(2))
            runCurrent()
            assertFalse(watcher.detach(2))
            assertTrue(watcher.detach(1))
            source.emit(LocalNetworkEvent.Available(9, false))
            runCurrent()
            assertEquals(1, pushes.size)
            val oldCallback = source.event
            watcher.stop()
            assertFalse(watcher.attach(2))
            watcher.start()
            oldCallback(LocalNetworkEvent.Available(10, false))
            assertTrue(watcher.attach(2))
            runCurrent()
            assertEquals(listOf(1L, 2L), pushes.map { it.first })
            assertTrue(pushes.last().second.sequence > pushes.first().second.sequence)
            assertTrue(pushes.last().second.networks.isEmpty())
            watcher.stop()
        }

    @Test
    fun `should disable only the watcher on subscription failure`() = runTest {
        val source = FakeSource().apply { fail = true }
        val watcher =
            LocalNetworkWatcher(source, backgroundScope, StandardTestDispatcher(testScheduler)) {
                _,
                _ ->
                error("Unexpected push")
            }
        watcher.start()
        assertFalse(watcher.attach(1))
        assertEquals(1, source.stops)
        watcher.stop()
    }

    @Test
    fun `should preserve JNI names and field getter types`() {
        val service = TalpidVpnService::class.java
        for (name in listOf("attachLocalNetwork", "detachLocalNetwork")) {
            assertEquals(
                Boolean::class.javaPrimitiveType,
                service.getDeclaredMethod(name, Long::class.javaPrimitiveType).returnType,
            )
        }
        val published =
            LocalNetworkBridge::class
                .java
                .getDeclaredMethod(
                    "published",
                    Long::class.javaPrimitiveType,
                    LocalNetworkSnapshot::class.java,
                )
        assertTrue(Modifier.isNative(published.modifiers))
        assertTrue(Modifier.isStatic(published.modifiers))
        assertEquals(Void.TYPE, published.returnType)
        assertEquals(
            Long::class.javaPrimitiveType,
            LocalNetworkSnapshot::class.java.getDeclaredMethod("getSequence").returnType,
        )
        assertEquals(
            ArrayList::class.java,
            LocalNetworkSnapshot::class.java.getDeclaredMethod("getNetworks").returnType,
        )
        assertNotNull(LocalPhysicalNetwork::class.java.getDeclaredMethod("getSsidHex"))
        assertNotNull(LocalPhysicalAddress::class.java.getDeclaredMethod("getPrefix"))
        assertNotNull(LocalPhysicalRoute::class.java.getDeclaredMethod("getDestination"))
    }

    @Test
    fun `should preserve exact identity bytes and redact record diagnostics`() {
        assertEquals("206e616d6520", platformSsid("\" name \"")?.encodedBytes())
        assertEquals("ff0080", platformSsid("ff0080")?.encodedBytes())
        for (value in listOf(null, "<unknown ssid>", "", "\"\"", "xyz", "0")) assertNull(
            platformSsid(value)
        )
        val prefix = InetNetwork(InetAddress.getByName("192.0.2.2"), 24)
        val address = LocalPhysicalAddress(prefix, true)
        val route = LocalPhysicalRoute(prefix, prefix.address, 4, 1)
        val network =
            LocalPhysicalNetwork(
                9,
                ssidHex = "736563726574",
                addresses = arrayListOf(address),
                routes = arrayListOf(route),
            )
        val snapshot =
            LocalNetworkSnapshot(1, true, true, true, true, true, true, arrayListOf(network))
        val diagnostics = listOf(address, route, network, snapshot).joinToString()
        for (secret in listOf("192.0.2.2", "736563726574", "secret")) assertFalse(
            diagnostics.contains(secret)
        )
    }

    private class FakeSource(
        var access: LocalIdentityAccess = LocalIdentityAccess(true, true, true, true, true)
    ) : LocalNetworkSource {
        var event: (LocalNetworkEvent) -> Unit = {}
        var changed: () -> Unit = {}
        val flags = mutableListOf<Boolean>()
        var stops = 0
        var fail = false

        override fun readAccess(): LocalIdentityAccess = access

        override fun start(
            includeLocation: Boolean,
            onEvent: (LocalNetworkEvent) -> Unit,
            onAccessChanged: () -> Unit,
        ) {
            if (fail) throw SecurityException()
            flags += includeLocation
            event = onEvent
            changed = onAccessChanged
        }

        override fun stop() {
            stops++
        }

        override fun withLegacyIdentity(
            networks: List<LocalPhysicalNetwork>,
            allowed: Boolean,
        ): List<LocalPhysicalNetwork> = networks

        fun emit(value: LocalNetworkEvent) = event(value)
    }
}
