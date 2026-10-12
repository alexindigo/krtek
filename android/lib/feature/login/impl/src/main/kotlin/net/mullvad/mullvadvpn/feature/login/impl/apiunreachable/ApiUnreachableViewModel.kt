package net.mullvad.mullvadvpn.feature.login.impl.apiunreachable

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.WhileSubscribed
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.feature.login.api.ApiUnreachableNavKey
import net.mullvad.mullvadvpn.lib.common.constant.VIEW_MODEL_STOP_TIMEOUT
import net.mullvad.mullvadvpn.lib.repository.ApiAccessRepository
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueUseCase

class ApiUnreachableViewModel(
    private val navArgs: ApiUnreachableNavKey,
    private val apiAccessRepository: ApiAccessRepository,
    private val supportIssueUseCase: SupportIssueUseCase,
) : ViewModel() {

    private val fallbackUrl = MutableStateFlow<String?>(null)
    private val hasEnabledAllApiAccessMethods = MutableStateFlow(false)

    private val _uiSideEffect = Channel<ApiUnreachableSideEffect>(Channel.BUFFERED)
    val uiSideEffect = _uiSideEffect.receiveAsFlow()

    val uiState =
        combine(fallbackUrl, hasEnabledAllApiAccessMethods) {
                fallbackUrl,
                hasEnabledAllApiAccessMethods ->
                ApiUnreachableUiState(
                    showEnableAllAccessMethodsButton = !hasEnabledAllApiAccessMethods,
                    fallbackUrl = fallbackUrl,
                    loginAction = navArgs.action,
                )
            }
            .stateIn(
                scope = viewModelScope,
                started = SharingStarted.WhileSubscribed(stopTimeout = VIEW_MODEL_STOP_TIMEOUT),
                initialValue =
                    ApiUnreachableUiState(
                        showEnableAllAccessMethodsButton = false,
                        loginAction = navArgs.action,
                    ),
            )

    init {
        viewModelScope.launch {
            hasEnabledAllApiAccessMethods.emit(
                apiAccessRepository.accessMethods.filterNotNull().first().all { it.enabled }
            )
        }
    }

    fun enableAllApiAccess() {
        viewModelScope.launch {
            apiAccessRepository
                .enableAllApiAccessMethods()
                .fold(
                    {
                        _uiSideEffect.send(ApiUnreachableSideEffect.EnableAllApiAccessMethods.Error)
                    },
                    {
                        _uiSideEffect.send(
                            ApiUnreachableSideEffect.EnableAllApiAccessMethods.Success(navArgs)
                        )
                    },
                )
        }
    }

    fun openSupportIssue() {
        viewModelScope.launch {
            fallbackUrl.emit(null)
            _uiSideEffect.send(
                ApiUnreachableSideEffect.OpenIssue(supportIssueUseCase(title = "API unreachable"))
            )
        }
    }

    fun onBrowserUnavailable(url: String) {
        fallbackUrl.value = url
    }
}

sealed interface ApiUnreachableSideEffect {
    data class OpenIssue(val url: String) : ApiUnreachableSideEffect

    sealed interface EnableAllApiAccessMethods : ApiUnreachableSideEffect {
        data class Success(val navArgs: ApiUnreachableNavKey) : EnableAllApiAccessMethods

        data object Error : EnableAllApiAccessMethods
    }
}
