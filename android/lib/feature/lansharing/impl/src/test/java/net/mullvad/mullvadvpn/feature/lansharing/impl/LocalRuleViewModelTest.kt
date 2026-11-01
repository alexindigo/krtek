package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import app.cash.turbine.test
import arrow.core.left
import arrow.core.right
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.common.Lc
import net.mullvad.mullvadvpn.lib.common.test.TestCoroutineRule
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.SetLocalNetworkAccessError
import net.mullvad.mullvadvpn.lib.model.Settings
import net.mullvad.mullvadvpn.lib.model.WifiUnknownReason
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

@OptIn(ExperimentalCoroutinesApi::class)
@ExtendWith(TestCoroutineRule::class)
class LocalRuleViewModelTest {
    private val policy = LocalNetworkAccess()
    private val settings =
        MutableStateFlow<Settings?>(
            mockk<Settings> {
                every { allowLan } returns true
                every { localNetworkAccess } returns policy
            }
        )
    private val status = MutableStateFlow<LocalNetworkStatus?>(null)
    private val repository =
        mockk<SettingsRepository> {
            every { settingsUpdates } returns settings
            every { localNetworkStatus } returns status
        }
    private val handle = SavedStateHandle()
    private lateinit var viewModel: LocalNetworkSharingViewModel

    @BeforeEach
    fun setup() {
        viewModel = LocalNetworkSharingViewModel(false, repository, handle)
    }

    private fun content() = (viewModel.uiState.value as Lc.Content).value

    @AfterEach
    fun tearDown() {
        viewModel.viewModelScope.cancel()
    }

    @Test
    fun `should retain exact draft through saved state and keep or discard explicitly`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            viewModel.edit(null)
            viewModel.updateDraft { it.copy(name = "  unchanged text  ") }
            viewModel.closeEditor()
            runCurrent()
            assertTrue(content().editor.confirmDiscard)
            viewModel.keepEditing()
            runCurrent()
            assertFalse(content().editor.confirmDiscard)
            assertEquals("  unchanged text  ", content().editor.draft?.name)
            val restored = LocalNetworkSharingViewModel(false, repository, handle)
            restored.uiState.test {
                awaitItem()
                runCurrent()
                assertEquals(content().editor, (restored.uiState.value as Lc.Content).value.editor)
                cancelAndIgnoreRemainingEvents()
            }
            restored.viewModelScope.cancel()
            viewModel.discard()
            runCurrent()
            assertNull(content().editor.draft)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should send expected current policy and close editor on success without readback`() =
        runTest {
            coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
            viewModel.uiState.test {
                awaitItem()
                viewModel.edit(null)
                viewModel.updateDraft { it.copy(addresses = "10.0.0.0/8", name = "Home") }
                viewModel.save()
                runCurrent()
                coVerify(exactly = 1) {
                    repository.setLocalNetworkAccess(
                        match { it.rules.single().name == "Home" },
                        policy,
                    )
                }
                assertNull(content().editor.draft)
                assertFalse(content().saving)
                assertEquals(policy, settings.value?.localNetworkAccess)
                cancelAndIgnoreRemainingEvents()
            }
        }

    @Test
    fun `should preserve draft and map conflict invalid and unknown save errors`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            viewModel.edit(null)
            viewModel.updateDraft { it.copy(addresses = "10.0.0.0/8") }
            listOf(
                    SetLocalNetworkAccessError.Conflict to R.string.local_access_conflict,
                    SetLocalNetworkAccessError.Invalid to R.string.local_access_invalid_rule,
                    SetLocalNetworkAccessError.Unknown(IllegalStateException()) to
                        R.string.local_access_save_failed,
                )
                .forEach { (error, message) ->
                    coEvery { repository.setLocalNetworkAccess(any(), any()) } returns error.left()
                    viewModel.save()
                    runCurrent()
                    assertNotNull(content().editor.draft)
                    assertEquals(message, content().error)
                }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should map repository status directly without revision ordering`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            runCurrent()
            val sample =
                LocalNetworkStatus(
                    5u,
                    true,
                    ForwardingAvailability.NotAvailable,
                    ConnectedWifi.Unknown(WifiUnknownReason.NotOnWifi),
                    emptyList(),
                )
            status.value = sample
            runCurrent()
            assertEquals(sample, content().status)
            status.value = sample.copy(revision = 1u)
            runCurrent()
            assertEquals(1uL, content().status?.revision)
            assertTrue(content().lanSharingEnabled)
            assertEquals(policy, content().policy)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should give every condition reason its own readable message`() {
        val messages = LocalRuleInactiveReason.entries.map { LocalRuleState.Inactive(it).message() }
        assertEquals(12, messages.distinct().size)
        assertFalse(LocalRuleState.ConditionsMet.message() in messages)
        assertEquals(R.string.local_access_waiting_status, (null as LocalRuleState?).message())
    }

    @Test
    fun `should preserve other rules and ordering when editing then delete by id`() = runTest {
        val first =
            LocalRuleDraft(java.util.UUID.randomUUID().toString(), addresses = "10.0.0.0/8")
                .rule()!!
        val second = first.copy(id = java.util.UUID.randomUUID(), name = "Other")
        val current = LocalNetworkAccess(true, listOf(first, second))
        settings.value = mockk {
            every { allowLan } returns false
            every { localNetworkAccess } returns current
        }
        coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
        viewModel.uiState.test {
            awaitItem()
            viewModel.edit(first)
            viewModel.updateDraft { it.copy(name = "Edited") }
            viewModel.save()
            runCurrent()
            coVerify {
                repository.setLocalNetworkAccess(
                    current.copy(rules = listOf(first.copy(name = "Edited"), second)),
                    current,
                )
            }
            viewModel.delete(first.id)
            runCurrent()
            coVerify {
                repository.setLocalNetworkAccess(current.copy(rules = listOf(second)), current)
            }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should compare current policy when toggling and never request location`() = runTest {
        coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
        viewModel.setPolicyEnabled(true)
        runCurrent()
        coVerify(exactly = 1) {
            repository.setLocalNetworkAccess(policy.copy(enabled = true), policy)
        }
    }

    @Test
    fun `should expose the selected persisted delete name and cancel without changing policy`() =
        runTest {
            val rule =
                LocalRuleDraft(
                        java.util.UUID.randomUUID().toString(),
                        name = "Printer",
                        addresses = "10.0.0.0/8",
                    )
                    .rule()!!
            settings.value = mockk {
                every { allowLan } returns false
                every { localNetworkAccess } returns LocalNetworkAccess(rules = listOf(rule))
            }
            viewModel.uiState.test {
                awaitItem()
                viewModel.requestDelete(rule.copy(name = "Stale row name"))
                runCurrent()
                assertEquals(
                    LocalRuleDeleteTarget(rule.id.toString(), "Printer"),
                    content().deleteTarget,
                )
                assertEquals("Printer", content().deleteTarget?.displayName("Unnamed rule"))
                viewModel.requestDelete(null)
                runCurrent()
                assertNull(content().deleteTarget)
                coVerify(exactly = 0) { repository.setLocalNetworkAccess(any(), any()) }
                cancelAndIgnoreRemainingEvents()
            }
        }

    @Test
    fun `should carry an unnamed delete target and use the same confirmation for empty and populated lists`() =
        runTest {
            val rule =
                LocalRuleDraft(java.util.UUID.randomUUID().toString(), addresses = "10.0.0.0/8")
                    .rule()!!
            val current = LocalNetworkAccess(rules = listOf(rule))
            settings.value = mockk {
                every { allowLan } returns false
                every { localNetworkAccess } returns current
            }
            coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
            viewModel.uiState.test {
                awaitItem()
                viewModel.requestDelete(rule)
                runCurrent()
                assertEquals("Unnamed rule", content().deleteTarget?.displayName("Unnamed rule"))
                assertEquals(R.string.local_access_confirmation, content().confirmationMessage())
                assertEquals(
                    content().confirmationMessage(),
                    content().copy(policy = LocalNetworkAccess()).confirmationMessage(),
                )
                viewModel.delete(rule.id)
                runCurrent()
                assertNull(content().deleteTarget)
                coVerify(exactly = 1) {
                    repository.setLocalNetworkAccess(current.copy(rules = emptyList()), current)
                }
                cancelAndIgnoreRemainingEvents()
            }
        }

    @Test
    fun `should reject invalid draft before persistence and close untouched editor without discard`() =
        runTest {
            viewModel.uiState.test {
                awaitItem()
                viewModel.edit(null)
                viewModel.save()
                runCurrent()
                assertEquals(R.string.local_access_invalid_rule, content().error)
                coVerify(exactly = 0) { repository.setLocalNetworkAccess(any(), any()) }
                viewModel.closeEditor()
                runCurrent()
                assertNull(content().editor.draft)
                assertFalse(content().editor.confirmDiscard)
                cancelAndIgnoreRemainingEvents()
            }
        }
}
