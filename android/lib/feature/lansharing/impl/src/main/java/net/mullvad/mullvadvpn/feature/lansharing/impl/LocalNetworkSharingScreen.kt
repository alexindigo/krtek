package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibilityScope
import androidx.compose.animation.SharedTransitionScope
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewParameter
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import kotlin.text.appendLine
import net.mullvad.mullvadvpn.core.Navigator
import net.mullvad.mullvadvpn.lib.common.Lc
import net.mullvad.mullvadvpn.lib.common.compose.CollectSideEffectWithLifecycle
import net.mullvad.mullvadvpn.lib.common.compose.unlessIsDetail
import net.mullvad.mullvadvpn.lib.model.FeatureIndicator
import net.mullvad.mullvadvpn.lib.ui.component.Accordion
import net.mullvad.mullvadvpn.lib.ui.component.ScaffoldWithSmallTopBar
import net.mullvad.mullvadvpn.lib.ui.component.annotatedStringResource
import net.mullvad.mullvadvpn.lib.ui.component.button.NavigateBackIconButton
import net.mullvad.mullvadvpn.lib.ui.component.button.NavigateCloseIconButton
import net.mullvad.mullvadvpn.lib.ui.component.drawVerticalScrollbar
import net.mullvad.mullvadvpn.lib.ui.component.listitem.SwitchListItem
import net.mullvad.mullvadvpn.lib.ui.component.text.ScreenDescription
import net.mullvad.mullvadvpn.lib.ui.designsystem.MullvadCircularProgressIndicatorLarge
import net.mullvad.mullvadvpn.lib.ui.tag.LOCAL_NETWORK_SHARING_SCREEN_TEST_TAG
import net.mullvad.mullvadvpn.lib.ui.theme.AppTheme
import net.mullvad.mullvadvpn.lib.ui.theme.Dimens
import net.mullvad.mullvadvpn.lib.ui.theme.color.AlphaScrollbar
import org.koin.androidx.compose.koinViewModel
import org.koin.core.parameter.parametersOf

@Preview("Loading|Disabled|Enabled")
@Composable
private fun PreviewLocalNetworkSharingScreen(
    @PreviewParameter(LocalNetworkSharingUiStatePreviewParameterProvider::class)
    state: Lc<Boolean, LocalNetworkSharingUiState>
) {
    AppTheme {
        LocalNetworkSharingScreen(
            state = state,
            onLocalNetworkSharingEnable = { _ -> },
            onBackClick = {},
        )
    }
}

@Composable
fun SharedTransitionScope.LocalNetworkSharing(
    navigator: Navigator,
    isModal: Boolean,
    animatedVisibilityScope: AnimatedVisibilityScope,
) {
    val viewModel = koinViewModel<LocalNetworkSharingViewModel> { parametersOf(isModal) }
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val requestAccess = localPermissionRequester()
    CollectSideEffectWithLifecycle(viewModel.uiSideEffect) { requestAccess(it.needsWifi) }

    val actions =
        LocalPolicyActions(
            onEnabled = viewModel::setPolicyEnabled,
            onEdit = viewModel::edit,
            onUpdate = viewModel::updateDraft,
            onSave = viewModel::save,
            onClose = viewModel::closeEditor,
            onDiscard = viewModel::discard,
            onKeep = viewModel::keepEditing,
            onDelete = viewModel::delete,
            onRequestDelete = viewModel::requestDelete,
            onCancelDelete = { viewModel.requestDelete(null) },
            onConnectedWifi = viewModel::useConnectedWifi,
            onRequestAccess = requestAccess,
        )

    LocalNetworkSharingScreen(
        state = state,
        modifier =
            Modifier.testTag(LOCAL_NETWORK_SHARING_SCREEN_TEST_TAG)
                .sharedBounds(
                    rememberSharedContentState(key = FeatureIndicator.LAN_SHARING),
                    animatedVisibilityScope = animatedVisibilityScope,
                ),
        onLocalNetworkSharingEnable = viewModel::setLocalNetworkSharingEnabled,
        onBackClick = dropUnlessResumed { navigator.goBack() },
        policyActions = actions,
    )
}

@Composable
fun LocalNetworkSharingScreen(
    state: Lc<Boolean, LocalNetworkSharingUiState>,
    onLocalNetworkSharingEnable: (enable: Boolean) -> Unit,
    onBackClick: () -> Unit,
    modifier: Modifier = Modifier,
    policyActions: LocalPolicyActions = LocalPolicyActions(),
) {
    val editing = (state as? Lc.Content)?.value?.editor?.draft != null
    val onBack = { if (editing) policyActions.onClose() else onBackClick() }
    BackHandler(enabled = editing, onBack = policyActions.onClose)
    ScaffoldWithSmallTopBar(
        appBarTitle = stringResource(id = R.string.local_network_sharing),
        modifier = modifier,
        navigationIcon = {
            if (state.isModal()) {
                NavigateCloseIconButton { onBack() }
            } else {
                unlessIsDetail { NavigateBackIconButton { onBack() } }
            }
        },
    ) { contentModifier ->
        val scrollState = rememberScrollState()
        Column(modifier = contentModifier) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier =
                    Modifier.weight(1f)
                        .drawVerticalScrollbar(
                            state = scrollState,
                            color =
                                MaterialTheme.colorScheme.onSurface.copy(alpha = AlphaScrollbar),
                        )
                        .verticalScroll(state = scrollState),
            ) {
                when (state) {
                    is Lc.Loading -> {
                        Loading()
                    }
                    is Lc.Content -> {
                        LocalNetworkSharingContent(
                            state = state.value,
                            onLanSharingEnabled = onLocalNetworkSharingEnable,
                            policyActions = policyActions,
                        )
                    }
                }
            }
            if (state is Lc.Content && editing && !state.value.saving) {
                LocalRuleEditorActions(state.value, policyActions)
            }
        }
    }
}

@Composable
private fun LocalNetworkSharingContent(
    state: LocalNetworkSharingUiState,
    onLanSharingEnabled: (enable: Boolean) -> Unit,
    policyActions: LocalPolicyActions,
) {
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = Dimens.sideMarginNew)) {
        Image(
            contentScale = ContentScale.FillWidth,
            modifier =
                Modifier.widthIn(max = Dimens.settingsDetailsImageMaxWidth)
                    .fillMaxWidth()
                    .align(Alignment.CenterHorizontally),
            painter = painterResource(id = R.drawable.local_network_sharing_illustration),
            contentDescription = stringResource(R.string.local_network_sharing),
        )

        Text(
            text = stringResource(R.string.local_access_connected_title),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = Dimens.mediumPadding),
        )
        ScreenDescription(
            modifier = Modifier.padding(vertical = Dimens.mediumPadding),
            text =
                buildAnnotatedString {
                    appendLine(annotatedStringResource(R.string.local_network_sharing_info))
                    appendLine(
                        annotatedStringResource(
                            R.string.local_network_sharing_info_block_connections_warning
                        )
                    )
                    append(annotatedStringResource(R.string.local_access_connected_warning))
                    appendLine()
                    appendLine()
                    append(annotatedStringResource(R.string.local_network_sharing_info2))
                },
        )

        var expandedState by rememberSaveable { mutableStateOf(false) }

        Accordion(
            title = stringResource(R.string.how_it_works),
            expandedText =
                buildAnnotatedString {
                    appendLine(annotatedStringResource(R.string.local_access_connected_details))
                    appendLine()
                    append(annotatedStringResource(R.string.local_network_sharing_info4))
                    appendLine()
                    append(annotatedStringResource(R.string.local_network_sharing_ip_ranges))
                },
            icon = Icons.Rounded.Info,
            iconContentDescription = stringResource(R.string.info),
            isExpanded = expandedState,
            onClick = { expandedState = !expandedState },
        )

        SwitchListItem(
            modifier = Modifier.padding(vertical = Dimens.screenBottomMarginNew),
            title = stringResource(R.string.local_access_connected_enable),
            isToggled = state.lanSharingEnabled,
            onCellClicked = onLanSharingEnabled,
        )
        HorizontalDivider(modifier = Modifier.padding(bottom = Dimens.mediumPadding))
        LocalPolicyControls(state, policyActions)
    }
}

@Composable
private fun Loading() {
    MullvadCircularProgressIndicatorLarge()
}

private fun Lc<Boolean, LocalNetworkSharingUiState>.isModal() =
    when (this) {
        is Lc.Loading -> this.value
        is Lc.Content -> this.value.isModal
    }
