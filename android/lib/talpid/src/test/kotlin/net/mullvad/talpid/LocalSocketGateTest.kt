package net.mullvad.talpid

import android.net.Network
import io.mockk.mockk
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.talpid.model.LocalPhysicalNetwork
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class LocalSocketGateTest {
    @Test
    fun `should refuse stale pending blocked missing lost access and unknown wifi without action`() =
        runTest {
            val source = Source()
            var sequence = 0L
            val watcher =
                LocalNetworkWatcher(
                    source,
                    backgroundScope,
                    StandardTestDispatcher(testScheduler),
                ) { _, record ->
                    sequence = record.sequence
                }
            var calls = 0
            fun prepare(handle: Long = 9, revision: Long = sequence, wifi: Boolean = false) =
                watcher.withCurrentNetwork(handle, revision, wifi) {
                    calls++
                    LocalSocketPreparation.READY
                }
            assertEquals(LocalSocketPreparation.INACTIVE, prepare())
            watcher.start()
            assertEquals(LocalSocketPreparation.INACTIVE, prepare())
            watcher.attach(1)
            source.event(LocalNetworkEvent.Available(9, false))
            runCurrent()
            assertEquals(LocalSocketPreparation.STALE, prepare(revision = sequence - 1))
            assertEquals(LocalSocketPreparation.STALE, prepare(handle = 10))
            assertEquals(LocalSocketPreparation.STALE, prepare(wifi = true))
            source.event(LocalNetworkEvent.Update(9) { it.copy(blocked = true) })
            assertEquals(LocalSocketPreparation.STALE, prepare())
            runCurrent()
            assertEquals(LocalSocketPreparation.STALE, prepare())
            source.event(LocalNetworkEvent.Update(9) { it.copy(blocked = false) })
            runCurrent()
            source.access = source.access.copy(local = false)
            assertEquals(LocalSocketPreparation.STALE, prepare())
            assertEquals(LocalSocketPreparation.STALE, prepare())
            runCurrent()
            source.event(LocalNetworkEvent.Available(9, false))
            runCurrent()
            assertEquals(LocalSocketPreparation.STALE, prepare())
            watcher.detach(1)
            assertEquals(LocalSocketPreparation.INACTIVE, prepare())
            watcher.stop()
            assertEquals(LocalSocketPreparation.INACTIVE, prepare())
            assertEquals(0, calls)
        }

    @Test
    fun `should run action under watcher lock and retain frontend on watcher loss`() = runTest {
        val source = Source()
        var sequence = 0L
        val watcher =
            LocalNetworkWatcher(
                source,
                backgroundScope,
                StandardTestDispatcher(testScheduler),
            ) { _, record ->
                sequence = record.sequence
            }
        val owner = LocalFrontendOwnership()
        assertTrue(owner.tryFrontend())
        watcher.start()
        watcher.attach(1)
        source.event(LocalNetworkEvent.Available(9, false))
        source.event(LocalNetworkEvent.Update(9) { it.copy(transport = 1, ssidHex = "6162") })
        runCurrent()
        val attempted = CountDownLatch(1)
        val completed = CountDownLatch(1)
        var changer: Thread? = null
        assertEquals(
            LocalSocketPreparation.READY,
            watcher.withCurrentNetwork(9, sequence, true) {
                assertEquals(source.physical, it)
                changer = thread {
                    attempted.countDown()
                    source.event(LocalNetworkEvent.Lost(9))
                    completed.countDown()
                }
                assertTrue(attempted.await(1, TimeUnit.SECONDS))
                assertFalse(completed.await(100, TimeUnit.MILLISECONDS))
                LocalSocketPreparation.READY
            },
        )
        assertTrue(completed.await(1, TimeUnit.SECONDS))
        assertNotNull(changer).join(1000)
        watcher.stop()
        assertEquals(
            LocalSocketPreparation.INACTIVE,
            watcher.withCurrentNetwork(9, sequence, false) { error("must not prepare") },
        )
        assertTrue(owner.frontendActive)
        assertNotNull(LocalFrontendConfig.parse(arrayOf("10.0.2.2/32")))
    }

    private class Source : LocalNetworkSource {
        var access = LocalIdentityAccess(true, true, true, true, true)
        val physical = mockk<Network>()
        var event: (LocalNetworkEvent) -> Unit = {}

        override fun readAccess() = access

        override fun network(handle: Long) = physical

        override fun start(
            includeLocation: Boolean,
            onEvent: (LocalNetworkEvent) -> Unit,
            onAccessChanged: () -> Unit,
        ) {
            event = onEvent
        }

        override fun stop() = Unit

        override fun withLegacyIdentity(networks: List<LocalPhysicalNetwork>, allowed: Boolean) =
            networks
    }
}
