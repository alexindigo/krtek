package net.mullvad.mullvadvpn.lib.grpc.mapper

import mullvad_daemon.management_interface.ConnectedWifi
import mullvad_daemon.management_interface.LocalNetworkStatus
import mullvad_daemon.management_interface.LocalRuleInactiveReason
import mullvad_daemon.management_interface.LocalRuleStatus
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi as ModelConnectedWifi
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus as ModelLocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason as ModelInactiveReason
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.LocalRuleStatus as ModelLocalRuleStatus
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import net.mullvad.mullvadvpn.lib.model.WifiUnknownReason

internal fun LocalNetworkStatus.toDomain(): ModelLocalNetworkStatus =
    ModelLocalNetworkStatus(
        revision = revision.toULong(),
        observerAvailable = observer_available,
        forwarding =
            when (forwarding) {
                LocalNetworkStatus.ForwardingAvailability.NOT_AVAILABLE ->
                    ForwardingAvailability.NotAvailable
                LocalNetworkStatus.ForwardingAvailability.OFF -> ForwardingAvailability.Off
                LocalNetworkStatus.ForwardingAvailability.ACTIVE -> ForwardingAvailability.Active
                LocalNetworkStatus.ForwardingAvailability.PAUSED_WHILE_CONNECTED ->
                    ForwardingAvailability.PausedWhileConnected
                LocalNetworkStatus.ForwardingAvailability.FAILED -> ForwardingAvailability.Failed
            },
        currentWifi = requireNotNull(current_wifi) { "Missing current Wi-Fi status" }.toDomain(),
        rules = rules.map { it.toDomain() },
    )

internal fun ConnectedWifi.toDomain(): ModelConnectedWifi =
    when (val identity = identity) {
        is ConnectedWifi.Identity.Ssid ->
            ModelConnectedWifi.Known(
                requireNotNull(SsidIdentity.fromBytes(identity.value.toByteArray())) {
                    "Invalid SSID byte identity"
                }
            )
        is ConnectedWifi.Identity.Unknown ->
            ModelConnectedWifi.Unknown(
                when (identity.value) {
                    ConnectedWifi.UnknownReason.PERMISSION_MISSING ->
                        WifiUnknownReason.PermissionMissing
                    ConnectedWifi.UnknownReason.LOCATION_OFF -> WifiUnknownReason.LocationOff
                    ConnectedWifi.UnknownReason.NOT_ON_WIFI -> WifiUnknownReason.NotOnWifi
                    ConnectedWifi.UnknownReason.MULTIPLE_WIFI -> WifiUnknownReason.MultipleWifi
                    ConnectedWifi.UnknownReason.PENDING -> WifiUnknownReason.Pending
                }
            )
        null -> throw IllegalArgumentException("Missing current Wi-Fi identity")
    }

internal fun LocalRuleStatus.toDomain(): ModelLocalRuleStatus {
    val mappedState =
        when (state) {
            LocalRuleStatus.State.CONDITIONS_MET -> {
                require(reason == null) { "Conditions-met rule has an inactive reason" }
                LocalRuleState.ConditionsMet
            }
            LocalRuleStatus.State.FORWARDING -> {
                require(reason == null) { "Forwarding rule has an inactive reason" }
                LocalRuleState.Forwarding
            }
            LocalRuleStatus.State.INACTIVE ->
                LocalRuleState.Inactive(
                    requireNotNull(reason) { "Missing inactive reason" }.toDomain()
                )
        }
    return ModelLocalRuleStatus(localRuleId(id), mappedState)
}

internal fun LocalRuleInactiveReason.toDomain(): ModelInactiveReason =
    when (this) {
        LocalRuleInactiveReason.POLICY_OFF -> ModelInactiveReason.PolicyOff
        LocalRuleInactiveReason.RULE_OFF -> ModelInactiveReason.RuleOff
        LocalRuleInactiveReason.LOCAL_PERMISSION_MISSING ->
            ModelInactiveReason.LocalPermissionMissing
        LocalRuleInactiveReason.LOCATION_PERMISSION_MISSING ->
            ModelInactiveReason.LocationPermissionMissing
        LocalRuleInactiveReason.BACKGROUND_LOCATION_MISSING ->
            ModelInactiveReason.BackgroundLocationMissing
        LocalRuleInactiveReason.LOCATION_OFF -> ModelInactiveReason.LocationOff
        LocalRuleInactiveReason.NO_ELIGIBLE_NETWORK -> ModelInactiveReason.NoEligibleNetwork
        LocalRuleInactiveReason.WAITING_FOR_NETWORK_DETAILS ->
            ModelInactiveReason.WaitingForNetworkDetails
        LocalRuleInactiveReason.DIFFERENT_WIFI -> ModelInactiveReason.DifferentWifi
        LocalRuleInactiveReason.WIFI_NAME_UNKNOWN -> ModelInactiveReason.WifiNameUnknown
        LocalRuleInactiveReason.MULTIPLE_NETWORKS -> ModelInactiveReason.MultipleNetworks
        LocalRuleInactiveReason.OBSERVER_UNAVAILABLE -> ModelInactiveReason.ObserverUnavailable
    }
