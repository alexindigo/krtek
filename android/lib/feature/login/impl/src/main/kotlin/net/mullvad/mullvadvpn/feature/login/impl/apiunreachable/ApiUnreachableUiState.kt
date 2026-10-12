package net.mullvad.mullvadvpn.feature.login.impl.apiunreachable

import net.mullvad.mullvadvpn.feature.login.api.LoginAction

data class ApiUnreachableUiState(
    val showEnableAllAccessMethodsButton: Boolean,
    val fallbackUrl: String? = null,
    val loginAction: LoginAction,
)
