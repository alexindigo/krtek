package net.mullvad.mullvadvpn.talpid

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.mullvad.mullvadvpn.app.MullvadApplication
import net.mullvad.mullvadvpn.feature.lansharing.impl.R
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.Test
import org.koin.android.ext.android.getKoin

/** Observe the rendered consumer after external change, with no status read/refresh. */
class LocalNetworkStatusInstrumentedTest {
    @Test
    fun externalLocationChangeUpdatesRenderedStatusWithoutRefresh() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        fun shell(command: String): String =
            instrumentation.uiAutomation.executeShellCommand(command).use { fd ->
                ParcelFileDescriptor.AutoCloseInputStream(fd).use {
                    it.readBytes().toString(Charsets.UTF_8).trim()
                }
            }
        val location = shell("settings get secure location_mode")
        check(location == "3")
        LocalNetworkEditorInstrumentedTest().withLocalAccessScreen { driver ->
            val repository =
                (target.applicationContext as MullvadApplication)
                    .getKoin()
                    .get<SettingsRepository>()
            runBlocking {
                val original =
                    checkNotNull(
                            withTimeout(10_000) {
                                repository.settingsUpdates.first { it != null }
                            }
                        )
                        .localNetworkAccess
                assertEquals(LocalNetworkAccess(), original, "Preserve unexpected policy")
                val known =
                    withTimeout(10_000) {
                            repository.localNetworkStatus.filterNotNull().first {
                                it.currentWifi is ConnectedWifi.Known
                            }
                        }
                        .currentWifi as ConnectedWifi.Known
                val rule =
                    LocalBypassRule(
                        UUID.randomUUID(),
                        "Krtek live status fixture",
                        true,
                        listOf(checkNotNull(LocalCidr.parse("192.168.240.10/32").getOrNull())),
                        listOf(known.ssid),
                    )
                val configured = LocalNetworkAccess(true, listOf(rule))
                suspend fun metRuleText(): String {
                    val state =
                        withTimeout(10_000) {
                                repository.localNetworkStatus.filterNotNull().first { status ->
                                    status.rules.any {
                                        it.id == rule.id &&
                                            (it.state == LocalRuleState.ConditionsMet ||
                                                it.state == LocalRuleState.Forwarding)
                                    }
                                }
                            }
                            .rules
                            .single { it.id == rule.id }
                            .state
                    return target.getString(
                        if (state == LocalRuleState.Forwarding) R.string.local_access_forwarding
                        else R.string.local_access_conditions_met
                    )
                }
                try {
                    assertTrue(repository.setLocalNetworkAccess(configured, original).isRight())
                    withTimeout(10_000) {
                        repository.settingsUpdates.first { it?.localNetworkAccess == configured }
                    }
                    driver.requireRenderedText(metRuleText())
                    // Supplemental external fault only. Activity stays visible; no settings
                    // navigation, onResume, Refresh click or status read after the fault.
                    shell("settings put secure location_mode 0")
                    driver.requireRenderedText(target.getString(R.string.local_access_location_off))
                    assertEquals(configured, repository.settingsUpdates.value?.localNetworkAccess)
                    shell("settings put secure location_mode $location")
                    driver.requireRenderedText(metRuleText())
                    assertEquals(configured, repository.settingsUpdates.value?.localNetworkAccess)
                } finally {
                    shell("settings put secure location_mode $location")
                    val current = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
                    check(current == original || current == configured) {
                        "Concurrent configuration retained"
                    }
                    if (current != original)
                        assertTrue(repository.setLocalNetworkAccess(original, current).isRight())
                    withTimeout(10_000) {
                        repository.settingsUpdates.first { it?.localNetworkAccess == original }
                    }
                }
            }
        }
    }
}
