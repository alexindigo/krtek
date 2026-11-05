package net.mullvad.mullvadvpn.feature.problemreport.impl

import androidx.compose.ui.tooling.preview.PreviewParameterProvider

class ReportProblemUiStatePreviewParameterProvider :
    PreviewParameterProvider<ReportProblemUiState> {
    override val values: Sequence<ReportProblemUiState>
        get() =
            sequenceOf(
                ReportProblemUiState(),
                ReportProblemUiState(logCollectingState = LogCollectingState.Success),
                ReportProblemUiState(logCollectingState = LogCollectingState.Failed),
                ReportProblemUiState(
                    message = "Unable to connect",
                    fallbackUrl = "https://example.test/issues/new?title=Problem+report",
                    logCollectingState = LogCollectingState.Success,
                ),
            )
}
