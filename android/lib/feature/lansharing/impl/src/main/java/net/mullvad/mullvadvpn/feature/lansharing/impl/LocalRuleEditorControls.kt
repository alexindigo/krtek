package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.ui.component.listitem.SwitchListItem
import net.mullvad.mullvadvpn.lib.ui.component.textfield.CustomTextField
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryButton
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryTextButton

@Composable
internal fun LocalRuleEditorControls(
    state: LocalNetworkSharingUiState,
    actions: LocalPolicyActions,
) {
    val draft = state.editor.draft ?: return
    val enabled = !state.saving
    Text(
        stringResource(
            if (state.policy.rules.any { it.id.toString() == draft.id })
                R.string.local_access_edit_rule
            else R.string.local_access_add_rule
        ),
        style = MaterialTheme.typography.titleMedium,
    )
    LocalDraftField(draft.name, R.string.local_access_name, "local_access_name", enabled) { value ->
        actions.onUpdate { it.copy(name = value) }
    }
    LocalDraftField(
        draft.addresses,
        R.string.local_access_addresses,
        "local_access_addresses",
        enabled,
    ) { value ->
        actions.onUpdate { it.copy(addresses = value) }
    }
    Text(
        stringResource(R.string.local_access_addresses_help),
        style = MaterialTheme.typography.bodyMedium,
    )
    if (state.error == R.string.local_access_invalid_rule) {
        draft.canonicalSuggestion()?.let {
            Text(
                stringResource(R.string.local_access_canonical_suggestion, it),
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
    LocalWifiFields(draft, enabled, actions.onUpdate)
    SwitchListItem(
        title = stringResource(R.string.local_access_rule_enabled),
        isToggled = draft.enabled,
        isEnabled = enabled,
        onCellClicked = { value -> actions.onUpdate { it.copy(enabled = value) } },
    )
    state.error?.let { Text(stringResource(it), color = MaterialTheme.colorScheme.error) }
    PrimaryButton(
        text = stringResource(R.string.local_access_save),
        isEnabled = enabled,
        onClick = actions.onSave,
    )
    PrimaryTextButton(
        onClick = actions.onClose,
        isEnabled = enabled,
        text = stringResource(android.R.string.cancel),
    )
}

@Composable
private fun LocalWifiFields(
    draft: LocalRuleDraft,
    enabled: Boolean,
    onUpdate: ((LocalRuleDraft) -> LocalRuleDraft) -> Unit,
) {
    Text(
        stringResource(R.string.local_access_wifi_names),
        style = MaterialTheme.typography.titleMedium,
    )
    draft.wifiNames.forEachIndexed { index, wifi ->
        LocalDraftField(
            wifi.text,
            R.string.local_access_wifi_name,
            "local_access_wifi_$index",
            enabled,
        ) { value ->
            onUpdate {
                it.copy(
                    wifiNames =
                        it.wifiNames.mapIndexed { i, field ->
                            if (i == index) LocalWifiDraft(value) else field
                        }
                )
            }
        }
        PrimaryTextButton(
            onClick = {
                onUpdate {
                    it.copy(wifiNames = it.wifiNames.filterIndexed { i, _ -> i != index })
                }
            },
            isEnabled = enabled,
            text = stringResource(R.string.local_access_remove_wifi),
        )
    }
    PrimaryTextButton(
        onClick = { onUpdate { it.copy(wifiNames = it.wifiNames + LocalWifiDraft("")) } },
        isEnabled = enabled && draft.wifiNames.size < LocalNetworkAccess.MAX_SSIDS_PER_RULE,
        text = stringResource(R.string.local_access_add_wifi),
    )
    Text(
        stringResource(R.string.local_access_wifi_help),
        style = MaterialTheme.typography.bodyMedium,
    )
}

@Composable
private fun LocalDraftField(
    value: String,
    label: Int,
    tag: String,
    enabled: Boolean,
    onValue: (String) -> Unit,
) {
    CustomTextField(
        value = value,
        labelText = stringResource(label),
        modifier = Modifier.testTag(tag),
        keyboardType = KeyboardType.Text,
        isEnabled = enabled,
        isValidValue = true,
        isDigitsOnlyAllowed = false,
        onValueChanged = onValue,
        onSubmit = {},
    )
}
