package net.mullvad.talpid

import net.mullvad.talpid.model.LocalNetworkSnapshot

object LocalNetworkBridge {
    @JvmStatic external fun published(registration: Long, snapshot: LocalNetworkSnapshot)
}
