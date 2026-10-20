package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import java.util.UUID
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.ui.component.listitem.SwitchListItem
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryButton
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryTextButton
import net.mullvad.mullvadvpn.lib.ui.theme.Dimens

@Composable
internal fun LocalPolicyControls(state: LocalNetworkSharingUiState, actions: LocalPolicyActions) {
    var confirmEnable by rememberSaveable { mutableStateOf(false) }
    var deleteId by rememberSaveable { mutableStateOf<String?>(null) }
    Column(
        Modifier.fillMaxWidth().padding(bottom = Dimens.screenBottomMarginNew),
        verticalArrangement = Arrangement.spacedBy(Dimens.smallPadding),
    ) {
        LocalPolicyHeader(state) { if (it) confirmEnable = true else actions.onEnabled(false) }
        if (state.editor.draft == null) {
            state.error?.let { Text(stringResource(it), color = MaterialTheme.colorScheme.error) }
            if (state.policy.rules.isEmpty()) Text(stringResource(R.string.local_access_empty))
            state.policy.rules.forEach { rule ->
                LocalRuleRow(
                    rule = rule,
                    condition = state.status?.rules?.find { it.id == rule.id }?.state,
                    enabled = !state.saving,
                    onEdit = { actions.onEdit(rule) },
                    onDelete = { deleteId = rule.id.toString() },
                )
                HorizontalDivider()
            }
            PrimaryButton(
                text = stringResource(R.string.local_access_add_rule),
                isEnabled = !state.saving,
                onClick = { actions.onEdit(null) },
            )
        } else {
            LocalRuleEditorControls(state, actions)
        }
    }
    if (confirmEnable) {
        LocalPolicyConfirmation(
            title = R.string.local_access_enable_title,
            confirm = R.string.enable,
            onConfirm = {
                confirmEnable = false
                actions.onEnabled(true)
            },
            onCancel = { confirmEnable = false },
            description = R.string.local_access_confirmation,
        )
    }
    deleteId?.let { id ->
        LocalPolicyConfirmation(
            title = R.string.local_access_delete_title,
            confirm = R.string.local_access_delete,
            onConfirm = {
                deleteId = null
                actions.onDelete(UUID.fromString(id))
            },
            onCancel = { deleteId = null },
        )
    }
    if (state.editor.confirmDiscard) {
        LocalPolicyConfirmation(
            title = R.string.local_access_discard_title,
            confirm = R.string.local_access_discard,
            cancel = R.string.local_access_keep_editing,
            onConfirm = actions.onDiscard,
            onCancel = actions.onKeep,
        )
    }
}

@Composable
private fun LocalPolicyHeader(state: LocalNetworkSharingUiState, onEnabled: (Boolean) -> Unit) {
    Text(stringResource(R.string.local_access_title), style = MaterialTheme.typography.titleMedium)
    Text(
        stringResource(R.string.local_access_scope_help),
        style = MaterialTheme.typography.bodyMedium,
    )
    SwitchListItem(
        title = stringResource(R.string.local_access_enable),
        isToggled = state.policy.enabled,
        isEnabled = !state.saving && state.editor.draft == null,
        singeLine = false,
        onCellClicked = onEnabled,
    )
    if (state.status?.forwarding == ForwardingAvailability.NotAvailable) {
        Text(
            stringResource(R.string.local_access_forwarding_unavailable),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun LocalRuleRow(
    rule: LocalBypassRule,
    condition: LocalRuleState?,
    enabled: Boolean,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(Dimens.smallPadding)) {
        Text(
            rule.name.ifEmpty { stringResource(R.string.local_access_unnamed) },
            style = MaterialTheme.typography.titleMedium,
        )
        Text(rule.cidrs.joinToString(", "), style = MaterialTheme.typography.bodyMedium)
        if (rule.ssidIds.isEmpty())
            Text(
                stringResource(R.string.local_access_any_network),
                style = MaterialTheme.typography.bodyMedium,
            )
        rule.ssidIds.forEach {
            Text(
                stringResource(R.string.local_access_wifi, it.displayText()),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Text(stringResource(condition.message()), style = MaterialTheme.typography.bodyMedium)
        FlowRow {
            PrimaryTextButton(
                onClick = onEdit,
                isEnabled = enabled,
                text = stringResource(R.string.local_access_edit),
            )
            PrimaryTextButton(
                onClick = onDelete,
                isEnabled = enabled,
                text = stringResource(R.string.local_access_delete),
            )
        }
    }
}

@Composable
private fun LocalPolicyConfirmation(
    title: Int,
    confirm: Int,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
    cancel: Int = android.R.string.cancel,
    description: Int? = null,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(title)) },
        text = description?.let { { Text(stringResource(it)) } },
        confirmButton = { PrimaryTextButton(onClick = onConfirm, text = stringResource(confirm)) },
        dismissButton = { PrimaryTextButton(onClick = onCancel, text = stringResource(cancel)) },
    )
}

internal fun LocalRuleState?.message(): Int =
    when (this) {
        null -> R.string.local_access_waiting_status
        LocalRuleState.ConditionsMet -> R.string.local_access_conditions_met
        is LocalRuleState.Inactive -> reason.message()
    }

internal fun LocalRuleInactiveReason.message(): Int =
    when (this) {
        LocalRuleInactiveReason.PolicyOff -> R.string.local_access_policy_off
        LocalRuleInactiveReason.RuleOff -> R.string.local_access_rule_off
        LocalRuleInactiveReason.LocalPermissionMissing -> R.string.local_access_local_missing
        LocalRuleInactiveReason.LocationPermissionMissing -> R.string.local_access_fine_missing
        LocalRuleInactiveReason.BackgroundLocationMissing ->
            R.string.local_access_background_missing
        LocalRuleInactiveReason.LocationOff -> R.string.local_access_location_off
        LocalRuleInactiveReason.NoEligibleNetwork -> R.string.local_access_no_network
        LocalRuleInactiveReason.WaitingForNetworkDetails -> R.string.local_access_waiting_details
        LocalRuleInactiveReason.DifferentWifi -> R.string.local_access_different_wifi
        LocalRuleInactiveReason.WifiNameUnknown -> R.string.local_access_wifi_unknown
        LocalRuleInactiveReason.MultipleNetworks -> R.string.local_access_multiple_networks
        LocalRuleInactiveReason.ObserverUnavailable -> R.string.local_access_observer_unavailable
    }
