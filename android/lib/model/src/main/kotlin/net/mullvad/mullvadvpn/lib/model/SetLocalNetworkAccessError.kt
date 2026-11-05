package net.mullvad.mullvadvpn.lib.model

sealed interface SetLocalNetworkAccessError {
    data object Conflict : SetLocalNetworkAccessError

    data object Invalid : SetLocalNetworkAccessError

    data class Unknown(val cause: Throwable) : SetLocalNetworkAccessError
}
