package net.mullvad.mullvadvpn.feature.login.impl.apiunreachable

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.mullvad.mullvadvpn.core.Navigator
import net.mullvad.mullvadvpn.feature.login.api.ApiUnreachableInfoDialogResult
import net.mullvad.mullvadvpn.feature.login.api.ApiUnreachableNavKey
import net.mullvad.mullvadvpn.feature.login.api.LoginAction
import net.mullvad.mullvadvpn.lib.common.compose.CollectSideEffectWithLifecycle
import net.mullvad.mullvadvpn.lib.common.compose.safeOpenUri
import net.mullvad.mullvadvpn.lib.ui.component.CopyableLink
import net.mullvad.mullvadvpn.lib.ui.component.dialog.InfoDialog
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryButton
import net.mullvad.mullvadvpn.lib.ui.resource.R
import net.mullvad.mullvadvpn.lib.ui.theme.AppTheme
import org.koin.androidx.compose.koinViewModel
import org.koin.core.parameter.parametersOf

@Preview
@Composable
private fun PreviewApiUnreachableInfoDialog() {
    AppTheme {
        ApiUnreachableInfoDialog(
            state =
                ApiUnreachableUiState(
                    showEnableAllAccessMethodsButton = true,
                    loginAction = LoginAction.LOGIN,
                ),
            onEnableAllApiMethods = {},
            onOpenIssue = {},
            onDismiss = {},
        )
    }
}

@Composable
fun ApiUnreachableInfo(navArgs: ApiUnreachableNavKey, navigator: Navigator) {
    val viewModel = koinViewModel<ApiUnreachableViewModel> { parametersOf(navArgs) }

    val uriHandler = LocalUriHandler.current
    CollectSideEffectWithLifecycle(viewModel.uiSideEffect) { sideEffect ->
        when (sideEffect) {
            is ApiUnreachableSideEffect.OpenIssue -> {
                uriHandler.safeOpenUri(sideEffect.url).onLeft {
                    viewModel.onBrowserUnavailable(sideEffect.url)
                }
            }
            is ApiUnreachableSideEffect.EnableAllApiAccessMethods ->
                navigator.goBack(result = sideEffect.toResult())
        }
    }

    val state by viewModel.uiState.collectAsStateWithLifecycle()

    ApiUnreachableInfoDialog(
        state = state,
        onEnableAllApiMethods = viewModel::enableAllApiAccess,
        onOpenIssue = viewModel::openSupportIssue,
        onDismiss = navigator::goBack,
    )
}

@Composable
fun ApiUnreachableInfoDialog(
    state: ApiUnreachableUiState,
    onEnableAllApiMethods: () -> Unit,
    onOpenIssue: () -> Unit,
    onDismiss: () -> Unit,
) {
    InfoDialog(
        title = stringResource(id = R.string.unable_to_reach_api),
        message =
            buildAnnotatedString {
                append(
                    stringResource(
                        id =
                            when (state.loginAction) {
                                LoginAction.LOGIN ->
                                    R.string.unable_to_reach_api_dialog_message_first_login

                                LoginAction.CREATE_ACCOUNT ->
                                    R.string.unable_to_reach_api_dialog_message_first_create_account
                            }
                    )
                )
                append(stringResource(id = R.string.unable_to_reach_api_dialog_message_second))
                val firstItem =
                    stringResource(id = R.string.unable_to_reach_api_dialog_message_list_first)
                val secondItem =
                    stringResource(id = R.string.unable_to_reach_api_dialog_message_list_second)
                val thirdItem =
                    stringResource(id = R.string.unable_to_reach_api_dialog_message_list_third)
                withBulletList {
                    withBulletListItem { append(firstItem) }
                    withBulletListItem { append(secondItem) }
                    if (state.showEnableAllAccessMethodsButton) {
                        withBulletListItem { append(thirdItem) }
                    }
                }
            },
        additionalInfo = stringResource(id = R.string.unable_to_reach_api_github_message),
        showIcon = false,
        confirmButton = {
            Column {
                if (state.showEnableAllAccessMethodsButton) {
                    PrimaryButton(
                        modifier = Modifier.wrapContentHeight().fillMaxWidth(),
                        text = stringResource(R.string.enable_all_methods),
                        onClick = onEnableAllApiMethods,
                    )
                }
                PrimaryButton(
                    modifier = Modifier.wrapContentHeight().fillMaxWidth(),
                    text = stringResource(R.string.report_on_github),
                    onClick = onOpenIssue,
                )
                state.fallbackUrl?.let { CopyableLink(url = it) }
                PrimaryButton(
                    modifier = Modifier.wrapContentHeight().fillMaxWidth(),
                    text = stringResource(R.string.got_it),
                    onClick = onDismiss,
                )
            }
        },
        onDismiss = onDismiss,
    )
}

private fun ApiUnreachableSideEffect.EnableAllApiAccessMethods.toResult() =
    when (this) {
        ApiUnreachableSideEffect.EnableAllApiAccessMethods.Error ->
            ApiUnreachableInfoDialogResult.Error
        is ApiUnreachableSideEffect.EnableAllApiAccessMethods.Success ->
            ApiUnreachableInfoDialogResult.Success(navArgs)
    }
