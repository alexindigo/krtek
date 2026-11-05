package net.mullvad.talpid

import co.touchlab.kermit.Logger
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import net.mullvad.talpid.model.LocalNetworkSnapshot
import net.mullvad.talpid.model.LocalPhysicalNetwork

/** One writer, one coalesced delivery worker. Native calls never run under [lock]. */
internal class LocalNetworkWatcher(
    private val source: LocalNetworkSource,
    private val scope: CoroutineScope,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val publish: (Long, LocalNetworkSnapshot) -> Unit = LocalNetworkBridge::published,
) {
    private val lock = Any()
    private val changes = Channel<Unit>(Channel.CONFLATED)
    private val networks = linkedMapOf<Long, LocalPhysicalNetwork>()
    private var access = LocalIdentityAccess(false, false, false, false, false)
    private var running = false
    private var registration = 0L
    private var epoch = 0L
    private var sequence = 0L
    private var worker: Job? = null

    fun start(): Unit =
        synchronized(lock) {
            if (running) return
            running = true
            try {
                access = source.readAccess()
                subscribe()
                worker =
                    scope.launch(ioDispatcher) {
                        for (ignored in changes) {
                            // A suspended receiver can reserve one signal while another is pending.
                            changes.tryReceive()
                            deliver()
                        }
                    }
                changed()
            } catch (_: RuntimeException) {
                unavailable()
            }
        }

    fun stop(): Unit =
        synchronized(lock) {
            running = false
            epoch++
            registration = 0
            networks.clear()
            source.stop()
            worker?.cancel()
            worker = null
        }

    fun attach(value: Long): Boolean =
        synchronized(lock) {
            if (!running || value <= 0 || registration != 0L) return false
            registration = value
            changed()
            true
        }

    fun detach(value: Long): Boolean =
        synchronized(lock) {
            if (value != registration || value == 0L) return false
            registration = 0
            true
        }

    private fun subscribe() {
        val current = ++epoch
        networks.clear()
        source.start(
            access.fine,
            { event ->
                synchronized(lock) {
                    if (running && current == epoch) {
                        event.applyTo(networks)
                        changed()
                    }
                }
            },
            { synchronized(lock) { if (running && current == epoch) changed() } },
        )
    }

    private fun changed() {
        changes.trySend(Unit)
    }

    private fun unavailable() {
        running = false
        epoch++
        networks.clear()
        source.stop()
        Logger.w("Local network watcher unavailable")
    }

    private fun deliver() {
        val delivery =
            synchronized(lock) {
                if (!running) return
                val snapshot = observation()
                if (registration == 0L) null else registration to snapshot
            }
        delivery?.let { publish(it.first, it.second) }
    }

    private fun observation(): LocalNetworkSnapshot =
        try {
            val fresh = source.readAccess()
            if (fresh != access) {
                access = fresh
                source.stop()
                subscribe()
            }
            access = fresh
            val observed = source.withLegacyIdentity(networks.values.toList(), access.identity)
            LocalNetworkSnapshot(
                ++sequence,
                running,
                access.local,
                access.fine,
                access.background,
                access.location,
                access.operations,
                ArrayList(
                    observed.map {
                        if (access.identity && it.transport == WIFI) it else it.copy(ssidHex = null)
                    }
                ),
            )
        } catch (_: RuntimeException) {
            unavailable()
            LocalNetworkSnapshot(
                ++sequence,
                false,
                false,
                false,
                false,
                false,
                false,
                arrayListOf(),
            )
        }

    companion object {
        const val WIFI = 1
        const val ETHERNET = 2
    }
}

internal interface LocalNetworkSource {
    fun readAccess(): LocalIdentityAccess

    fun start(
        includeLocation: Boolean,
        onEvent: (LocalNetworkEvent) -> Unit,
        onAccessChanged: () -> Unit,
    )

    fun stop()

    fun withLegacyIdentity(
        networks: List<LocalPhysicalNetwork>,
        allowed: Boolean,
    ): List<LocalPhysicalNetwork>
}

/** Callback values are already owned records; only the watcher owns the mutable map. */
internal sealed interface LocalNetworkEvent {
    fun applyTo(networks: MutableMap<Long, LocalPhysicalNetwork>)

    data class Available(val handle: Long, val blocked: Boolean) : LocalNetworkEvent {
        override fun applyTo(networks: MutableMap<Long, LocalPhysicalNetwork>) {
            networks[handle] = LocalPhysicalNetwork(handle, blocked = blocked)
        }
    }

    data class Update(
        val handle: Long,
        val update: (LocalPhysicalNetwork) -> LocalPhysicalNetwork,
    ) : LocalNetworkEvent {
        override fun applyTo(networks: MutableMap<Long, LocalPhysicalNetwork>) {
            networks[handle]?.let { networks[handle] = update(it) }
        }
    }

    data class Lost(val handle: Long) : LocalNetworkEvent {
        override fun applyTo(networks: MutableMap<Long, LocalPhysicalNetwork>) {
            networks.remove(handle)
        }
    }
}
