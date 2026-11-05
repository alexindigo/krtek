package net.mullvad.mullvadvpn.feature.problemreport.impl

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewParameter
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.core.Navigator
import net.mullvad.mullvadvpn.feature.problemreport.api.ViewLogsNavKey
import net.mullvad.mullvadvpn.lib.common.compose.CollectSideEffectWithLifecycle
import net.mullvad.mullvadvpn.lib.common.compose.isTv
import net.mullvad.mullvadvpn.lib.common.compose.safeOpenUri
import net.mullvad.mullvadvpn.lib.common.compose.unlessIsDetail
import net.mullvad.mullvadvpn.lib.ui.component.CopyableLink
import net.mullvad.mullvadvpn.lib.ui.component.ScaffoldWithSmallTopBar
import net.mullvad.mullvadvpn.lib.ui.component.button.NavigateBackIconButton
import net.mullvad.mullvadvpn.lib.ui.component.drawVerticalScrollbar
import net.mullvad.mullvadvpn.lib.ui.component.textfield.mullvadDarkTextFieldColors
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryButton
import net.mullvad.mullvadvpn.lib.ui.designsystem.VariantButton
import net.mullvad.mullvadvpn.lib.ui.resource.R
import net.mullvad.mullvadvpn.lib.ui.theme.AppTheme
import net.mullvad.mullvadvpn.lib.ui.theme.Dimens
import net.mullvad.mullvadvpn.lib.ui.theme.color.AlphaScrollbar
import org.koin.androidx.compose.koinViewModel

@Preview("Loading|Ready|LogsUnavailable|BrowserUnavailable")
@Composable
private fun PreviewReportProblemScreen(
    @PreviewParameter(ReportProblemUiStatePreviewParameterProvider::class)
    state: ReportProblemUiState
) {
    AppTheme {
        ReportProblemScreen(
            state = state,
            onOpenIssue = {},
            onNavigateToViewLogs = {},
            onMessageChanged = {},
            onBackClick = {},
        )
    }
}

@Composable
fun ReportProblem(navigator: Navigator) {
    val vm = koinViewModel<ReportProblemViewModel>()
    val state by vm.uiState.collectAsStateWithLifecycle()
    val uriHandler = LocalUriHandler.current
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val browserUnavailable = stringResource(R.string.browser_unavailable)

    CollectSideEffectWithLifecycle(vm.uiSideEffect) { sideEffect ->
        when (sideEffect) {
            is ReportProblemSideEffect.OpenIssue -> {
                uriHandler.safeOpenUri(sideEffect.url).onLeft {
                    vm.onBrowserUnavailable(sideEffect.url)
                    scope.launch { snackbarHostState.showSnackbar(browserUnavailable) }
                }
            }
        }
    }

    ReportProblemScreen(
        state = state,
        onOpenIssue = vm::openSupportIssue,
        onNavigateToViewLogs = dropUnlessResumed { navigator.navigate(ViewLogsNavKey) },
        onMessageChanged = vm::updateMessage,
        onBackClick = dropUnlessResumed { navigator.goBack() },
        snackbarHostState = snackbarHostState,
    )
}

@Composable
private fun ReportProblemScreen(
    state: ReportProblemUiState,
    onOpenIssue: () -> Unit,
    onNavigateToViewLogs: () -> Unit,
    onMessageChanged: (String) -> Unit,
    onBackClick: () -> Unit,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    ScaffoldWithSmallTopBar(
        appBarTitle = stringResource(id = R.string.report_a_problem),
        navigationIcon = {
            unlessIsDetail { NavigateBackIconButton(onNavigateBack = onBackClick) }
        },
        snackbarHostState = snackbarHostState,
    ) { modifier ->
        val scrollState = rememberScrollState()
        Column(
            modifier =
                Modifier.imePadding() // imePadding needs to be applied before the parent modifier.
                    .then(modifier)
                    .drawVerticalScrollbar(
                        state = scrollState,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = AlphaScrollbar),
                    )
                    .verticalScroll(state = scrollState)
                    .padding(
                        start = Dimens.sideMargin,
                        end = Dimens.sideMargin,
                        bottom = Dimens.screenBottomMargin,
                    ),
            verticalArrangement = Arrangement.spacedBy(Dimens.mediumPadding),
        ) {
            Text(
                text = stringResource(R.string.problem_report_github_description),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelLarge,
            )
            TextField(
                modifier =
                    Modifier.fillMaxWidth()
                        .defaultMinSize(minHeight = Dimens.problemReportTextFieldMinHeight),
                value = state.message,
                onValueChange = onMessageChanged,
                placeholder = { Text(stringResource(R.string.problem_report_message_hint)) },
                colors = mullvadDarkTextFieldColors(),
                keyboardOptions =
                    KeyboardOptions(
                        capitalization = KeyboardCapitalization.Sentences,
                        keyboardType = KeyboardType.Text,
                        imeAction = if (isTv()) ImeAction.Next else ImeAction.Unspecified,
                    ),
            )
            PrimaryButton(
                onClick = onOpenIssue,
                text = stringResource(R.string.open_github_issue),
            )
            state.fallbackUrl?.let { CopyableLink(url = it) }
            VariantButton(
                onClick = onNavigateToViewLogs,
                text = stringResource(R.string.view_logs),
                isEnabled = state.logCollectingState == LogCollectingState.Success,
                isLoading = state.logCollectingState == LogCollectingState.Loading,
            )
            Text(
                text = stringResource(R.string.problem_report_public_logs_notice),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
