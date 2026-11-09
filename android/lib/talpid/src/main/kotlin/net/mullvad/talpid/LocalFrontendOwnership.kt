package net.mullvad.talpid

/**
 * Serialized by the service monitor. Revocation denies preparation without releasing native's fd.
 */
internal class LocalFrontendOwnership {
    private enum class Owner {
        Idle,
        Upstream,
        Frontend,
    }

    private var owner = Owner.Idle
    private var revoked = false
    private val epochs = mutableSetOf<Long>()
    private var current: Long? = null

    val frontendActive: Boolean
        get() = owner == Owner.Frontend

    val canPrepare: Boolean
        get() = frontendActive && !revoked && current != null

    fun tryUpstream(): Boolean {
        if (frontendActive) return false
        owner = Owner.Upstream
        return true
    }

    fun upstreamClosed() {
        if (owner == Owner.Upstream) owner = Owner.Idle
    }

    fun tryFrontend(generation: Long): Boolean {
        if (generation <= 0 || owner != Owner.Idle) return false
        owner = Owner.Frontend
        revoked = false
        epochs.add(generation)
        current = generation
        return true
    }

    fun tryHandover(predecessor: Long, successor: Long): Boolean {
        if (!canPrepare || current != predecessor || epochs.size != 1 || successor <= predecessor)
            return false
        epochs.add(successor)
        return true
    }

    /** Entering establish is the last point where the predecessor is known usable. */
    fun establishing(generation: Long) {
        check(generation in epochs)
        current = generation
    }

    fun establishmentFailed(generation: Long) {
        if (current == generation) current = null
    }

    fun owns(generation: Long): Boolean = generation in epochs

    fun predecessorCurrent(generation: Long): Boolean = canPrepare && current == generation

    fun isLast(generation: Long): Boolean = owns(generation) && epochs.size == 1

    fun frontendFinished(generation: Long) {
        if (!epochs.remove(generation)) return
        if (current == generation) current = null
        if (epochs.isEmpty()) owner = Owner.Idle
    }

    fun revoke() {
        revoked = true
    }
}
