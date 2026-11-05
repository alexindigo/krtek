package net.mullvad.mullvadvpn.feature.problemreport.impl

import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewModelScope
import app.cash.turbine.test
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mockk.verify
import java.net.URLDecoder
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.common.test.TestCoroutineRule
import net.mullvad.mullvadvpn.lib.model.BuildVersion
import net.mullvad.mullvadvpn.lib.repository.ProblemReportRepository
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueUseCase
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

@ExtendWith(TestCoroutineRule::class)
class ReportProblemViewModelTest {
    private val repository = mockk<ProblemReportRepository>(relaxed = true)
    private val issuesUrl = "https://example.test/issues"
    private val useCase =
        SupportIssueUseCase(issuesUrl, BuildVersion("test", 1), "16", 36, "Example", "Phone")
    private lateinit var viewModel: ReportProblemViewModel

    @BeforeEach
    fun setup() {
        coEvery { repository.collectLogs() } returns true
        viewModel = ReportProblemViewModel(repository, useCase)
    }

    @AfterEach
    fun tearDown() {
        viewModel.viewModelScope.cancel()
    }

    @Test
    fun `successful log collection should enable viewing logs`() = runTest {
        viewModel.uiState.test {
            assertEquals(LogCollectingState.Success, awaitItem().logCollectingState)
        }
        coVerify(exactly = 1) { repository.collectLogs() }
    }

    @Test
    fun `pending collection should stay loading while an issue can still be opened`() = runTest {
        viewModel.viewModelScope.cancel()
        val collected = CompletableDeferred<Boolean>()
        coEvery { repository.collectLogs() } coAnswers { collected.await() }
        viewModel = ReportProblemViewModel(repository, useCase)
        viewModel.uiState.test {
            assertEquals(LogCollectingState.Loading, awaitItem().logCollectingState)
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue()
                assertEquals(ReportProblemSideEffect.OpenIssue(useCase()), awaitItem())
            }
            collected.complete(true)
            assertEquals(LogCollectingState.Success, awaitItem().logCollectingState)
        }
    }

    @Test
    fun `failed log collection should not prevent opening an issue`() = runTest {
        viewModel.viewModelScope.cancel()
        coEvery { repository.collectLogs() } returns false
        viewModel = ReportProblemViewModel(repository, useCase)
        viewModel.uiState.test {
            assertEquals(LogCollectingState.Failed, awaitItem().logCollectingState)
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue()
                assertEquals(ReportProblemSideEffect.OpenIssue(useCase()), awaitItem())
            }
        }
    }

    @Test
    fun `opening an issue should emit the encoded message and details without reading logs`() =
        runTest {
            val message = "Connection & DNS?\nÅ test"
            viewModel.updateMessage(message)
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue()
                val effect = awaitItem() as ReportProblemSideEffect.OpenIssue
                assertEquals(useCase(message), effect.url)
                assertTrue(effect.url.startsWith("$issuesUrl/new?"))
                assertTrue(URLDecoder.decode(effect.url, "UTF-8").contains(message))
            }
            coVerify(exactly = 0) { repository.readLogs() }
            verify(exactly = 0) { repository.deleteLogs() }
        }

    @Test
    fun `an empty optional message should open an issue with basic details`() = runTest {
        viewModel.uiSideEffect.test {
            viewModel.openSupportIssue()
            val url = (awaitItem() as ReportProblemSideEffect.OpenIssue).url
            assertEquals(useCase(), url)
            assertTrue(URLDecoder.decode(url, "UTF-8").contains("Android: 16 (SDK 36)"))
        }
    }

    @Test
    fun `browser failure and retry should keep the message and use the latest text`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            viewModel.updateMessage("First message")
            assertEquals("First message", awaitItem().message)
            val firstUrl = useCase("First message")
            viewModel.onBrowserUnavailable(firstUrl)
            assertEquals(firstUrl, awaitItem().fallbackUrl)
            viewModel.updateMessage("Updated message")
            val edited = awaitItem()
            assertEquals("Updated message", edited.message)
            assertEquals(firstUrl, edited.fallbackUrl)
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue()
                assertEquals(
                    ReportProblemSideEffect.OpenIssue(useCase("Updated message")),
                    awaitItem(),
                )
            }
            val retried = awaitItem()
            assertNull(retried.fallbackUrl)
            assertEquals("Updated message", retried.message)
        }
    }

    @Test
    fun `consumer issue URL should redact account numbers and cap a long message`() = runTest {
        viewModel.updateMessage("1234 5678 9012 3456 " + "🔒&".repeat(3000))
        viewModel.uiSideEffect.test {
            viewModel.openSupportIssue()
            val url = (awaitItem() as ReportProblemSideEffect.OpenIssue).url
            val decoded = URLDecoder.decode(url, "UTF-8")
            assertTrue(url.length <= 4096)
            assertFalse(Regex("[0-9]{16}").containsMatchIn(url))
            assertFalse(decoded.contains("1234 5678 9012 3456"))
            assertTrue(decoded.contains("[account number removed]"))
            assertTrue(decoded.contains("[Message truncated to fit the issue link.]"))
        }
    }

    @Test
    fun `leaving the screen should delete collected logs`() = runTest {
        val store = ViewModelStore()
        store.put("report", viewModel)
        store.clear()
        verify(exactly = 1) { repository.deleteLogs() }
    }
}
