package net.mullvad.mullvadvpn.talpid

import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.platform.app.InstrumentationRegistry
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.TimeUnit
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
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.Test
import org.koin.android.ext.android.getKoin

/**
 * Real shipped MainActivity and permission requester. Each method states the device permission
 * state it needs; the device runner stages that state before the method and restores it after.
 */
class LocalNetworkPermissionInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val target = instrumentation.targetContext
    private val repository: SettingsRepository
        get() = (target.applicationContext as MullvadApplication).getKoin().get()

    private fun granted(name: String) =
        target.checkSelfPermission("android.permission.$name") == PackageManager.PERMISSION_GRANTED

    private fun copy(id: Int, vararg args: Any): String = target.getString(id, *args)

    private fun systemNodes(packageName: String): List<AccessibilityNodeInfo> {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return emptyList()
        if (root.packageName?.toString() != packageName) return emptyList()
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        val result = mutableListOf<AccessibilityNodeInfo>()
        queue.add(root)
        while (queue.isNotEmpty() && result.size < 2048) {
            val node = queue.removeFirst()
            result.add(node)
            for (index in 0 until node.childCount) node.getChild(index)?.let(queue::add)
        }
        return result
    }

    private fun systemClick(packageName: String, predicate: (AccessibilityNodeInfo) -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        while (System.nanoTime() < deadline) {
            val selected = systemNodes(packageName).firstOrNull(predicate)
            if (selected != null) {
                var clickable: AccessibilityNodeInfo? = selected
                while (clickable != null && !clickable.isClickable) clickable = clickable.parent
                if (
                    clickable?.isEnabled == true &&
                        clickable.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                )
                    return
            }
            Thread.sleep(25)
        }
        error("Expected owned system permission/settings control did not appear")
    }

    private fun permissionControl(id: String) =
        systemClick("com.android.permissioncontroller") {
            it.viewIdResourceName == "com.android.permissioncontroller:id/$id"
        }

    private suspend fun awaitRuleReason(id: UUID, reason: LocalRuleInactiveReason) {
        withTimeout(10_000) {
            repository.localNetworkStatus.first { status ->
                status?.rules?.find { it.id == id }?.state == LocalRuleState.Inactive(reason)
            }
        }
    }

    private suspend fun awaitKnownWifi(): ConnectedWifi.Known =
        withTimeout(10_000) {
            repository.localNetworkStatus
                .filterNotNull()
                .first { it.currentWifi is ConnectedWifi.Known }
                .currentWifi as ConnectedWifi.Known
        }

    private fun withRestrictionEdit(
        block: (LocalNetworkEditorInstrumentedTest, LocalBypassRule) -> Unit
    ) =
        LocalNetworkEditorInstrumentedTest().withLocalAccessScreen { driver ->
            runBlocking {
                val original =
                    withTimeout(10_000) { repository.settingsUpdates.first { it != null } }
                        ?.localNetworkAccess
                assertEquals(LocalNetworkAccess(), original, "Preserve unexpected policy")
                val rule =
                    LocalBypassRule(
                        UUID.randomUUID(),
                        "Krtek permission fixture",
                        true,
                        listOf(checkNotNull(LocalCidr.parse("192.168.240.10/32").getOrNull())),
                    )
                val staged = LocalNetworkAccess(true, listOf(rule))
                assertTrue(repository.setLocalNetworkAccess(staged, original).isRight())
                withTimeout(10_000) {
                    repository.settingsUpdates.first { it?.localNetworkAccess == staged }
                }
                var primaryFailure: Throwable? = null
                try {
                    driver.click(copy(R.string.local_access_edit))
                    driver.click(copy(R.string.local_access_add_wifi))
                    driver.enter("local_access_wifi_0", "krtek-permission-mismatch-9231")
                    driver.click(copy(R.string.local_access_save))
                    withTimeout(10_000) {
                        repository.settingsUpdates.first {
                            it?.localNetworkAccess?.rules?.singleOrNull()?.ssidIds?.isNotEmpty() ==
                                true
                        }
                    }
                    block(driver, rule)
                } catch (error: Throwable) {
                    primaryFailure = error
                    throw error
                } finally {
                    try {
                        driver.returnFromSystemSettings()
                        val current =
                            checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
                        // Remove only this exact owned UUID through full-policy CAS; preserve
                        // concurrency.
                        check(
                            current.enabled &&
                                current.rules.size == 1 &&
                                current.rules.single().id == rule.id &&
                                current.rules.single().cidrs == rule.cidrs &&
                                current.rules.single().name == rule.name
                        )
                        val restoration =
                            repository.setLocalNetworkAccess(checkNotNull(original), current)
                        assertTrue(
                            restoration.isRight(),
                            "Exact original policy restoration was not acknowledged: ${restoration.fold({it.toString()},{"Acknowledged"})}",
                        )
                        withTimeout(10_000) {
                            repository.settingsUpdates.first { it?.localNetworkAccess == original }
                        }
                    } catch (restorationError: Throwable) {
                        val primary = primaryFailure
                        if (primary != null) primary.addSuppressed(restorationError)
                        else throw restorationError
                    }
                }
            }
        }

    @Test
    fun plainRuleDoesNotRequestLocation() {
        check(
            !granted("ACCESS_FINE_LOCATION") &&
                !granted("ACCESS_COARSE_LOCATION") &&
                !granted("ACCESS_BACKGROUND_LOCATION")
        ) {
            "Device must be staged with denied location permissions before this test"
        }
        LocalNetworkEditorInstrumentedTest()
            .realEditorRejectsBroadeningRetainsDirtyStateAndPersistsThenDeletesRule()
        assertTrue(
            !granted("ACCESS_FINE_LOCATION") &&
                !granted("ACCESS_COARSE_LOCATION") &&
                !granted("ACCESS_BACKGROUND_LOCATION")
        )
    }

    @Test
    fun alreadyGrantedDoesNotPromptAgain() {
        check(
            granted("ACCESS_LOCAL_NETWORK") &&
                granted("ACCESS_FINE_LOCATION") &&
                granted("ACCESS_BACKGROUND_LOCATION")
        ) {
            "Device must be staged with granted local and location permissions before this test"
        }
        withRestrictionEdit { driver, _ -> driver.requireNoIdentityPrompt() }
    }

    @Test
    fun deniedAndApproximateLocationKeepsRestrictedRuleInactive() {
        check(
            !granted("ACCESS_FINE_LOCATION") &&
                !granted("ACCESS_COARSE_LOCATION") &&
                !granted("ACCESS_BACKGROUND_LOCATION")
        ) {
            "Device must be staged with denied location permissions before this test"
        }
        withRestrictionEdit { driver, rule ->
            driver.click(copy(R.string.local_access_continue), false)
            driver.settleAction()
            permissionControl("permission_deny_button")
            runBlocking {
                awaitRuleReason(rule.id, LocalRuleInactiveReason.LocationPermissionMissing)
            }
            driver.requireRenderedText(copy(R.string.local_access_fine_missing))
            driver.click(copy(R.string.local_access_retry), false)
            driver.click(copy(R.string.local_access_continue), false)
            driver.settleAction()
            systemClick("com.android.permissioncontroller") { it.text?.toString() == "Approximate" }
            permissionControl("permission_allow_foreground_only_button")
            runBlocking {
                awaitRuleReason(rule.id, LocalRuleInactiveReason.LocationPermissionMissing)
                val saved =
                    checkNotNull(
                        repository.settingsUpdates.value?.localNetworkAccess?.rules?.single()
                    )
                assertEquals(rule.id, saved.id)
                assertTrue(saved.ssidIds.isNotEmpty(), "Permission refusal cleared the restriction")
            }
            driver.requireRenderedText(copy(R.string.local_access_approximate))
        }
    }

    @Test
    fun backgroundSettingsReturnRequiresFreshWifiStatus() {
        check(!granted("ACCESS_FINE_LOCATION") && !granted("ACCESS_BACKGROUND_LOCATION")) {
            "Device must be staged with denied precise and background location before this test"
        }
        withRestrictionEdit { driver, rule ->
            driver.click(copy(R.string.local_access_continue), false)
            driver.settleAction()
            systemClick("com.android.permissioncontroller") { it.text?.toString() == "Precise" }
            permissionControl("permission_allow_foreground_only_button")
            runBlocking {
                awaitRuleReason(rule.id, LocalRuleInactiveReason.BackgroundLocationMissing)
            }
            driver.click(copy(R.string.local_access_continue), false)
            driver.settleAction()
            systemClick("com.android.settings") { it.text?.toString() == "Permissions" }
            systemClick("com.android.permissioncontroller") { it.text?.toString() == "Location" }
            systemClick("com.android.permissioncontroller") {
                it.text?.toString() == "Allow all the time"
            }
            driver.returnFromSystemSettings()
            runBlocking {
                awaitKnownWifi()
                assertTrue(granted("ACCESS_BACKGROUND_LOCATION"))
                // The rule's Wi-Fi name differs from the connected network, so a fresh Known
                // status must surface as the different-network reason, not as missing access.
                awaitRuleReason(rule.id, LocalRuleInactiveReason.DifferentWifi)
            }
        }
    }

    @Test
    fun connectedWifiSelectionUsesFreshDraftOnly() =
        LocalNetworkEditorInstrumentedTest().withLocalAccessScreen { driver ->
            runBlocking {
                val original =
                    withTimeout(10_000) { repository.settingsUpdates.first { it != null } }
                        ?.localNetworkAccess
                assertEquals(LocalNetworkAccess(), original)
                check(granted("ACCESS_FINE_LOCATION") && granted("ACCESS_BACKGROUND_LOCATION"))
                val known = awaitKnownWifi()
                driver.click(copy(R.string.local_access_add_rule))
                driver.enter("local_access_addresses", "192.168.240.10/32")
                driver.click(copy(R.string.local_access_connected_wifi))
                driver.requireConnectedDraft(known.ssid)
                driver.requireNoIdentityPrompt()
                assertEquals(original, repository.settingsUpdates.value?.localNetworkAccess)
                driver.back()
                driver.click(copy(R.string.local_access_discard), false)
                assertEquals(original, repository.settingsUpdates.value?.localNetworkAccess)
            }
        }
}
