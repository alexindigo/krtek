package net.mullvad.mullvadvpn.lib.grpc

import co.touchlab.kermit.Logger
import mullvad_daemon.management_interface.DaemonEvent

internal fun DaemonEvent.logSafeEventSummary(logger: Logger = Logger) {
    logger.v(safeEventLogSummary())
}

/** Log only allowlisted metadata, never protobuf payloads or unknown fields. */
internal fun DaemonEvent.safeEventLogSummary(): String =
    when (val event = event) {
        is DaemonEvent.Event.Settings ->
            "Event(type=settings local-rule-count=${event.value.local_network_access?.rules?.size ?: 0})"
        is DaemonEvent.Event.Device -> "Event(type=device)"
        is DaemonEvent.Event.NewAccessMethod -> "Event(type=access-method)"
        is DaemonEvent.Event.RelayList -> "Event(type=relay-list)"
        is DaemonEvent.Event.TunnelState -> "Event(type=tunnel-state)"
        is DaemonEvent.Event.VersionInfo -> "Event(type=version-info)"
        is DaemonEvent.Event.RemoveDevice -> "Event(type=remove-device)"
        is DaemonEvent.Event.LeakInfo -> "Event(type=leak-info)"
        null -> "Event(type=unknown)"
    }
