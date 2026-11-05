package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import app.cash.turbine.test
import arrow.core.right
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
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
import net.mullvad.mullvadvpn.lib.model.Settings
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import net.mullvad.mullvadvpn.lib.model.WifiUnknownReason
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

@OptIn(ExperimentalCoroutinesApi::class)
@ExtendWith(TestCoroutineRule::class)
class ConnectedWifiDraftTest {
    private val status = MutableStateFlow<LocalNetworkStatus?>(null)
    private val settings =
        MutableStateFlow<Settings?>(
            mockk {
                every { allowLan } returns false
                every { localNetworkAccess } returns LocalNetworkAccess()
            }
        )
    private val repository =
        mockk<SettingsRepository> {
            every { settingsUpdates } returns settings
            every { localNetworkStatus } returns status
        }
    private lateinit var vm: LocalNetworkSharingViewModel

    @BeforeEach
    fun setup() {
        vm = LocalNetworkSharingViewModel(false, repository, SavedStateHandle())
    }

    @AfterEach
    fun tearDown() {
        vm.viewModelScope.cancel()
    }

    private fun edit() = (vm.uiState.value as Lc.Content).value.editor

    private fun observe(wifi: ConnectedWifi) {
        status.value =
            LocalNetworkStatus(1u, true, ForwardingAvailability.NotAvailable, wifi, emptyList())
    }

    @Test
    fun `should fill known binary wifi losslessly and avoid duplicates`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            val identity = SsidIdentity.fromBytes(byteArrayOf(-1, 0, -2))!!
            observe(ConnectedWifi.Known(identity))
            vm.useConnectedWifi()
            vm.useConnectedWifi()
            runCurrent()
            assertEquals(listOf(identity), edit().draft?.wifiNames?.map { it.identity() })
            assertNull(edit().wifiMessage)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should request missing access and fill from the daemon event after granting`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            observe(ConnectedWifi.Unknown(WifiUnknownReason.PermissionMissing))
            vm.uiSideEffect.test {
                vm.useConnectedWifi()
                assertEquals(LocalNetworkSharingSideEffect(true), awaitItem())
            }
            runCurrent()
            assertNull(edit().draft?.copy(addresses = "10.0.0.0/8")?.rule())
            val identity = SsidIdentity.fromUserText("  café, office  ")!!
            observe(ConnectedWifi.Known(identity))
            runCurrent()
            assertEquals(identity, edit().draft?.wifiNames?.single()?.identity())
            assertFalse(edit().waitingForWifi)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should explain unknown wifi and never save an unintended unconditional rule`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            listOf(
                    WifiUnknownReason.NotOnWifi,
                    WifiUnknownReason.LocationOff,
                    WifiUnknownReason.MultipleWifi,
                    WifiUnknownReason.Pending,
                )
                .forEach {
                    observe(ConnectedWifi.Unknown(it))
                    vm.useConnectedWifi()
                    runCurrent()
                    assertEquals(it.message(), edit().wifiMessage)
                    assertNull(edit().draft?.copy(addresses = "10.0.0.0/8")?.rule())
                }
            vm.uiSideEffect.test { expectNoEvents() }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should keep manual names instead of overwriting them with a later wifi event`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            observe(ConnectedWifi.Unknown(WifiUnknownReason.PermissionMissing))
            vm.useConnectedWifi()
            vm.updateDraft { it.copy(wifiNames = listOf(LocalWifiDraft("Manual"))) }
            observe(ConnectedWifi.Known(SsidIdentity.fromUserText("Observed")!!))
            runCurrent()
            assertEquals("Manual", edit().draft?.wifiNames?.single()?.text)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should request access only after successful saves for plain and wifi rules`() = runTest {
        coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
        vm.uiSideEffect.test {
            listOf(false, true).forEach { wifi ->
                vm.edit(null)
                vm.updateDraft {
                    it.copy(
                        addresses = "10.0.0.0/8",
                        wifiNames = if (wifi) listOf(LocalWifiDraft("Office")) else emptyList(),
                    )
                }
                vm.save()
                assertEquals(LocalNetworkSharingSideEffect(wifi), awaitItem())
            }
        }
    }

    @Test
    fun `should offer retry only for the three missing permission reasons`() {
        assertEquals(
            listOf(
                LocalRuleInactiveReason.LocalPermissionMissing,
                LocalRuleInactiveReason.LocationPermissionMissing,
                LocalRuleInactiveReason.BackgroundLocationMissing,
            ),
            LocalRuleInactiveReason.entries.filter { it.isMissingPermission() },
        )
        assertFalse((null as LocalRuleInactiveReason?).isMissingPermission())
    }
}
