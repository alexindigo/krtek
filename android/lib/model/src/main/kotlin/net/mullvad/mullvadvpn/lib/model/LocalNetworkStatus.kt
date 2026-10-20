package net.mullvad.mullvadvpn.lib.model

import java.util.UUID

data class LocalNetworkStatus(
    val revision: ULong,
    val observerAvailable: Boolean,
    val forwarding: ForwardingAvailability,
    val currentWifi: ConnectedWifi,
    val rules: List<LocalRuleStatus>,
)

enum class ForwardingAvailability {
    NotAvailable
}

sealed interface ConnectedWifi {
    data class Known(val ssid: SsidIdentity) : ConnectedWifi

    data class Unknown(val reason: WifiUnknownReason) : ConnectedWifi
}

enum class WifiUnknownReason {
    PermissionMissing,
    LocationOff,
    NotOnWifi,
    MultipleWifi,
    Pending,
}

data class LocalRuleStatus(val id: UUID, val state: LocalRuleState)

sealed interface LocalRuleState {
    data object ConditionsMet : LocalRuleState

    data class Inactive(val reason: LocalRuleInactiveReason) : LocalRuleState
}

enum class LocalRuleInactiveReason {
    PolicyOff,
    RuleOff,
    LocalPermissionMissing,
    LocationPermissionMissing,
    BackgroundLocationMissing,
    LocationOff,
    NoEligibleNetwork,
    WaitingForNetworkDetails,
    DifferentWifi,
    WifiNameUnknown,
    MultipleNetworks,
    ObserverUnavailable,
}
