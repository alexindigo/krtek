package net.mullvad.mullvadvpn.feature.login.impl.apiunreachable

import androidx.lifecycle.viewModelScope
import app.cash.turbine.test
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.feature.login.api.ApiUnreachableNavKey
import net.mullvad.mullvadvpn.feature.login.api.LoginAction
import net.mullvad.mullvadvpn.lib.common.test.TestCoroutineRule
import net.mullvad.mullvadvpn.lib.model.BuildVersion
import net.mullvad.mullvadvpn.lib.repository.ApiAccessRepository
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueUseCase
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

@ExtendWith(TestCoroutineRule::class)
class ApiUnreachableViewModelTest {
    private val issuesUrl = "https://example.test/issues"
    private val supportIssueUseCase =
        SupportIssueUseCase(issuesUrl, BuildVersion("test", 1), "16", 36, "Example", "Phone")

    private fun createViewModel(): ApiUnreachableViewModel {
        val repository = mockk<ApiAccessRepository>()
        every { repository.accessMethods } returns MutableStateFlow(emptyList())
        return ApiUnreachableViewModel(
            ApiUnreachableNavKey(LoginAction.LOGIN),
            repository,
            supportIssueUseCase,
        )
    }

    @Test
    fun `opening support should emit an API unreachable issue link without logs`() = runTest {
        val viewModel = createViewModel()
        try {
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue()
                assertEquals(
                    ApiUnreachableSideEffect.OpenIssue(
                        supportIssueUseCase(title = "API unreachable")
                    ),
                    awaitItem(),
                )
            }
        } finally {
            viewModel.viewModelScope.cancel()
        }
    }

    @Test
    fun `unavailable browser should expose copyable URL and a retry should clear it`() = runTest {
        val viewModel = createViewModel()
        try {
            viewModel.uiState.test {
                awaitItem()
                val url = supportIssueUseCase(title = "API unreachable")
                viewModel.onBrowserUnavailable(url)
                assertEquals(url, awaitItem().fallbackUrl)
                viewModel.openSupportIssue()
                assertNull(awaitItem().fallbackUrl)
            }
        } finally {
            viewModel.viewModelScope.cancel()
        }
    }
}
