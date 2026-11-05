package net.mullvad.mullvadvpn.feature.lansharing.impl

import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus

data class LocalNetworkSharingUiState(
    val lanSharingEnabled: Boolean,
    val isModal: Boolean = false,
    val policy: LocalNetworkAccess = LocalNetworkAccess(),
    val status: LocalNetworkStatus? = null,
    val editor: LocalEditorState = LocalEditorState(),
    val saving: Boolean = false,
    val error: Int? = null,
    val deleteTarget: LocalRuleDeleteTarget? = null,
)
