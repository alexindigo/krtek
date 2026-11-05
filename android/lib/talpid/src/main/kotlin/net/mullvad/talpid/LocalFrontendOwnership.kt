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

    val frontendActive: Boolean
        get() = owner == Owner.Frontend

    val canPrepare: Boolean
        get() = frontendActive && !revoked

    fun tryUpstream(): Boolean {
        if (frontendActive) return false
        owner = Owner.Upstream
        return true
    }

    fun upstreamClosed() {
        if (owner == Owner.Upstream) owner = Owner.Idle
    }

    fun tryFrontend(): Boolean {
        if (owner != Owner.Idle) return false
        owner = Owner.Frontend
        revoked = false
        return true
    }

    fun frontendFinished() {
        if (frontendActive) owner = Owner.Idle
    }

    fun revoke() {
        revoked = true
    }
}
