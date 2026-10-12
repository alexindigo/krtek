package net.mullvad.mullvadvpn.feature.problemreport.impl

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.WhileSubscribed
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.lib.common.constant.VIEW_MODEL_STOP_TIMEOUT
import net.mullvad.mullvadvpn.lib.repository.ProblemReportRepository
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueUseCase

data class ReportProblemUiState(
    val message: String = "",
    val fallbackUrl: String? = null,
    val logCollectingState: LogCollectingState = LogCollectingState.Loading,
)

sealed interface LogCollectingState {
    data object Loading : LogCollectingState

    data object Success : LogCollectingState

    data object Failed : LogCollectingState
}

sealed interface ReportProblemSideEffect {
    data class OpenIssue(val url: String) : ReportProblemSideEffect
}

class ReportProblemViewModel(
    private val problemReportRepository: ProblemReportRepository,
    private val supportIssueUseCase: SupportIssueUseCase,
) : ViewModel() {
    private val message = MutableStateFlow("")
    private val fallbackUrl = MutableStateFlow<String?>(null)
    private val logCollectingState =
        MutableStateFlow<LogCollectingState>(LogCollectingState.Loading)

    val uiState =
        combine(message, fallbackUrl, logCollectingState) { message, fallbackUrl, logCollectingState
                ->
                ReportProblemUiState(message, fallbackUrl, logCollectingState)
            }
            .stateIn(
                viewModelScope,
                SharingStarted.WhileSubscribed(VIEW_MODEL_STOP_TIMEOUT),
                ReportProblemUiState(),
            )

    private val _uiSideEffect = Channel<ReportProblemSideEffect>(Channel.BUFFERED)
    val uiSideEffect = _uiSideEffect.receiveAsFlow()

    fun updateMessage(value: String) {
        message.value = value
    }

    fun openSupportIssue() {
        viewModelScope.launch {
            fallbackUrl.emit(null)
            _uiSideEffect.send(
                ReportProblemSideEffect.OpenIssue(supportIssueUseCase(message = message.value))
            )
        }
    }

    fun onBrowserUnavailable(url: String) {
        fallbackUrl.value = url
    }

    init {
        viewModelScope.launch {
            logCollectingState.emit(
                if (problemReportRepository.collectLogs()) LogCollectingState.Success
                else LogCollectingState.Failed
            )
        }
    }

    override fun onCleared() {
        // Delete any logs if user leaves the screen
        problemReportRepository.deleteLogs()
    }
}
