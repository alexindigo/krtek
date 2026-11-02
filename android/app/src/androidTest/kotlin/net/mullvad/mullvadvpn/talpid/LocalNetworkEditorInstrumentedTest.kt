package net.mullvad.mullvadvpn.talpid

import android.content.Intent
import android.graphics.Rect
import android.os.Bundle
import android.view.accessibility.AccessibilityNodeInfo
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.ComposeUiTest
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.v2.runEmptyComposeUiTest
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleCallback
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.mullvad.mullvadvpn.app.MainActivity
import net.mullvad.mullvadvpn.app.MullvadApplication
import net.mullvad.mullvadvpn.feature.lansharing.impl.R
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.Test
import org.koin.android.ext.android.getKoin

/** Drives the real feature navigation. Never retains raw trees or account-screen values. */
@OptIn(ExperimentalTestApi::class)
class LocalNetworkEditorInstrumentedTest {
    private lateinit var compose: ComposeUiTest
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val target = instrumentation.targetContext

    private fun withLiveActivity(block: (MainActivity) -> Unit) {
        val lifecycle = ActivityLifecycleMonitorRegistry.getInstance()
        val created = AtomicReference<MainActivity?>()
        val resumed = CountDownLatch(1)
        instrumentation.runOnMainSync {
            check(
                Stage.values().all { stage ->
                    lifecycle.getActivitiesInStage(stage).none { it is MainActivity }
                }
            ) {
                "Preserve an existing activity instead of reusing or clearing it"
            }
        }
        val callback = ActivityLifecycleCallback { activity, stage ->
            if (activity is MainActivity && stage == Stage.PRE_ON_CREATE)
                created.compareAndSet(null, activity)
            if (stage == Stage.RESUMED && activity === created.get()) resumed.countDown()
        }
        lifecycle.addLifecycleCallback(callback)
        try {
            target.startActivity(
                Intent(target, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
            check(resumed.await(10, TimeUnit.SECONDS)) {
                "Owned real activity did not reach resumed state"
            }
            compose.waitForIdle()
            block(checkNotNull(created.get()))
        } finally {
            lifecycle.removeLifecycleCallback(callback)
            created.get()?.let { activity -> instrumentation.runOnMainSync { activity.finish() } }
        }
    }

    private fun nodes(): List<AccessibilityNodeInfo> {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return emptyList()
        if (root.packageName?.toString() != target.packageName) return emptyList()
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

    private fun awaitNode(
        scroll: Boolean = false,
        predicate: (AccessibilityNodeInfo) -> Boolean,
    ): AccessibilityNodeInfo {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        var nextScroll = 0L
        while (System.nanoTime() < deadline) {
            compose.waitForIdle()
            val current = nodes()
            current.firstOrNull(predicate)?.let {
                return it
            }
            if (scroll && System.nanoTime() >= nextScroll) {
                current
                    .firstOrNull { it.isScrollable }
                    ?.performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
                nextScroll = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(350)
            }
            Thread.sleep(25)
        }
        error("Expected allowlisted editor action did not render")
    }

    internal fun copy(id: Int, vararg args: Any): String = target.getString(id, *args)

    internal fun click(text: String, scroll: Boolean = true) {
        val selected =
            awaitNode(scroll) {
                it.isEnabled &&
                    (it.text?.toString() == text || it.contentDescription?.toString() == text)
            }
        var node: AccessibilityNodeInfo? = selected
        while (node != null && !node.isClickable) node = node.parent
        assertTrue(
            node?.performAction(AccessibilityNodeInfo.ACTION_CLICK) == true,
            "Rendered editor action was not clickable",
        )
        instrumentation.waitForIdleSync()
    }

    private fun field(tag: String): AccessibilityNodeInfo {
        try {
            compose
                .onNode(hasTestTag(tag) and hasSetTextAction(), useUnmergedTree = true)
                .performScrollTo()
        } catch (_: AssertionError) {
            error("Owned editor field could not be scrolled into view")
        }
        return awaitNode { it.viewIdResourceName == tag && it.isEditable }
    }

    internal fun enter(tag: String, value: String) {
        val semantics =
            compose.onAllNodes(hasTestTag(tag) and hasSetTextAction(), useUnmergedTree = true)
        fun liveEditable() =
            try {
                semantics
                    .fetchSemanticsNodes()
                    .singleOrNull()
                    ?.config
                    ?.getOrNull(SemanticsProperties.EditableText)
                    ?.text
            } catch (_: AssertionError) {
                error("Live tagged editor semantics unavailable")
            }
        assertTrue(liveEditable() != null, "Expected unique tagged editable field")
        assertTrue(
            field(tag)
                .performAction(
                    AccessibilityNodeInfo.ACTION_SET_TEXT,
                    Bundle().apply {
                        putCharSequence(
                            AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                            value,
                        )
                    },
                )
        )
        compose.waitForIdle()
        assertEquals(
            value,
            liveEditable(),
            "Actual editable semantics did not consume the platform action",
        )
        val rendered = awaitNode {
            it.viewIdResourceName == tag && it.isEditable && it.text?.toString() == value
        }
        assertEquals(value, rendered.text?.toString())
    }

    internal fun back() {
        instrumentation.uiAutomation.executeShellCommand("input keyevent KEYCODE_BACK").use {
            descriptor ->
            android.os.ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes() }
        }
        instrumentation.uiAutomation.waitForIdle(500, 5_000)
        instrumentation.waitForIdleSync()
    }

    private fun mainActivityResumed(): Boolean {
        var resumed = false
        instrumentation.runOnMainSync {
            resumed =
                ActivityLifecycleMonitorRegistry.getInstance()
                    .getActivitiesInStage(Stage.RESUMED)
                    .any { it is MainActivity }
        }
        return resumed
    }

    /** One Back per acknowledged system window; resumption forbids further navigation. */
    internal fun returnFromSystemSettings(step: String) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        var departingWindow: Int? = null
        fun record(action: String, window: Int) {
            instrumentation.sendStatus(
                0,
                Bundle().apply { putString("krtek_settings_return", "$step:$action:$window") },
            )
        }
        while (System.nanoTime() < deadline) {
            val root = instrumentation.uiAutomation.rootInActiveWindow
            val owner = root?.packageName?.toString()
            val resumed = mainActivityResumed()
            if (resumed && owner == target.packageName) {
                compose.waitForIdle()
                assertTrue(
                    compose
                        .onAllNodes(
                            hasTestTag("local_network_sharing_screen_test_tag"),
                            useUnmergedTree = true,
                        )
                        .fetchSemanticsNodes()
                        .size == 1,
                    "System return left the original Local network sharing route",
                )
                departingWindow?.let { record("ack", it) }
                record("local-screen", checkNotNull(root).windowId)
                return
            }
            // Lifecycle and accessibility are independent channels. A stale system root
            // after MainActivity resumes must never authorize a Back into the app.
            if (!resumed && root != null && owner != target.packageName) {
                check(
                    owner == "com.android.settings" || owner == "com.android.permissioncontroller"
                ) {
                    "Refuse to navigate an unrelated system window"
                }
                if (root.windowId != departingWindow && root.refresh() && !mainActivityResumed()) {
                    departingWindow?.let { record("ack", it) }
                    departingWindow = root.windowId
                    record("back", root.windowId)
                    back()
                }
            }
            Thread.sleep(25)
        }
        error("System return transition was not acknowledged on the original route")
    }

    /** Reuses the proven async MainActivity environment for additional shipped-UI outcomes. */
    internal fun withLocalAccessScreen(block: (LocalNetworkEditorInstrumentedTest) -> Unit) =
        runEmptyComposeUiTest {
            compose = this
            withLiveActivity {
                click(target.getString(net.mullvad.mullvadvpn.lib.ui.resource.R.string.settings))
                click(
                    target.getString(net.mullvad.mullvadvpn.lib.ui.resource.R.string.settings_vpn)
                )
                click(
                    target.getString(
                        net.mullvad.mullvadvpn.lib.ui.resource.R.string.local_network_sharing
                    )
                )
                block(this@LocalNetworkEditorInstrumentedTest)
            }
        }

    internal fun requireNoIdentityPrompt() {
        val prompts =
            setOf(
                copy(R.string.local_access_fine_title),
                copy(R.string.local_access_background_title),
            )
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            compose.waitForIdle()
            assertTrue(
                instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString() !=
                    "com.android.permissioncontroller",
                "Unexpected permission prompt",
            )
            assertTrue(
                nodes().none { it.text?.toString() in prompts },
                "Already satisfied prerequisites prompted again",
            )
            Thread.sleep(25)
        }
    }

    internal fun settleAction() = compose.waitForIdle()

    internal fun requireRenderedText(expected: String) {
        awaitNode(true) { it.text?.toString() == expected }
    }

    internal fun requireConnectedDraft(ssid: SsidIdentity) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        val expected = ssid.displayText()
        while (System.nanoTime() < deadline) {
            compose.waitForIdle()
            if (field("local_access_wifi_0").text?.toString() == expected) return
            Thread.sleep(25)
        }
        error("Fresh connected Wi-Fi name did not reach the exact editor field")
    }

    @Test
    fun realEditorRejectsBroadeningRetainsDirtyStateAndPersistsThenDeletesRule() =
        runEmptyComposeUiTest {
            compose = this
            withLiveActivity {
                val repository =
                    (target.applicationContext as MullvadApplication)
                        .getKoin()
                        .get<SettingsRepository>()
                runBlocking {
                    val original =
                        withTimeout(10_000) { repository.settingsUpdates.first { it != null } }
                            ?.localNetworkAccess
                    assertEquals(
                        LocalNetworkAccess(),
                        original,
                        "Preserve unexpected configured policy",
                    )
                    val beforePermissions =
                        listOf(
                                "ACCESS_LOCAL_NETWORK",
                                "ACCESS_COARSE_LOCATION",
                                "ACCESS_FINE_LOCATION",
                                "ACCESS_BACKGROUND_LOCATION",
                            )
                            .associateWith { target.checkSelfPermission("android.permission.$it") }
                    val name = "Krtek editor fixture"
                    try {
                        click(
                            target.getString(
                                net.mullvad.mullvadvpn.lib.ui.resource.R.string.settings
                            )
                        )
                        click(
                            target.getString(
                                net.mullvad.mullvadvpn.lib.ui.resource.R.string.settings_vpn
                            )
                        )
                        click(
                            target.getString(
                                net.mullvad.mullvadvpn.lib.ui.resource.R.string
                                    .local_network_sharing
                            )
                        )
                        click(copy(R.string.local_access_add_rule))
                        enter("local_access_name", name)
                        enter("local_access_addresses", "192.168.240.11/28")
                        click(copy(R.string.local_access_save))
                        // The noncanonical prefix is rejected in place, with the canonical
                        // suggestion rendered under the addresses field.
                        val feedback = awaitNode {
                            it.text?.toString() == copy(R.string.local_access_invalid_rule)
                        }
                        val save = awaitNode {
                            it.text?.toString() == copy(R.string.local_access_save)
                        }
                        val feedbackBounds = Rect().also(feedback::getBoundsInScreen)
                        val saveBounds = Rect().also(save::getBoundsInScreen)
                        assertTrue(
                            feedbackBounds.bottom <= saveBounds.top,
                            "Validation feedback must be visible directly above Save",
                        )
                        // Return to the field that owns the canonical suggestion; scrolling
                        // only forward from Save cannot reach an earlier field.
                        field("local_access_addresses")
                        awaitNode(scroll = true) {
                            it.text?.toString() ==
                                copy(R.string.local_access_canonical_suggestion, "192.168.240.0/28")
                        }
                        assertEquals(
                            "192.168.240.11/28",
                            field("local_access_addresses").text?.toString(),
                        )
                        assertEquals(original, repository.settingsUpdates.value?.localNetworkAccess)
                        back()
                        click(copy(R.string.local_access_keep_editing), false)
                        assertEquals(name, field("local_access_name").text?.toString())
                        enter("local_access_addresses", "192.168.240.10/32")
                        click(copy(R.string.local_access_save))
                        val saved =
                            withTimeout(10_000) {
                                    repository.settingsUpdates.first {
                                        it?.localNetworkAccess?.rules?.singleOrNull()?.name == name
                                    }
                                }
                                ?.localNetworkAccess
                        assertTrue(saved != null && !saved.enabled)
                        assertEquals(
                            listOf("192.168.240.10/32"),
                            saved.rules.single().cidrs.map { it.toString() },
                        )
                        awaitNode(true) { it.text?.toString() == name }
                        click(copy(R.string.local_access_edit))
                        enter("local_access_name", "Krtek unsaved fixture")
                        back()
                        click(copy(R.string.local_access_discard), false)
                        assertEquals(saved, repository.settingsUpdates.value?.localNetworkAccess)
                        click(copy(R.string.local_access_delete))
                        requireRenderedText(copy(R.string.local_access_delete_description, name))
                        click(copy(android.R.string.cancel), false)
                        assertEquals(saved, repository.settingsUpdates.value?.localNetworkAccess)
                        click(copy(R.string.local_access_delete))
                        requireRenderedText(copy(R.string.local_access_delete_description, name))
                        click(copy(R.string.local_access_delete), false)
                        withTimeout(10_000) {
                            repository.settingsUpdates.first { it?.localNetworkAccess == original }
                        }
                        assertEquals(
                            beforePermissions,
                            beforePermissions.keys.associateWith {
                                target.checkSelfPermission("android.permission.$it")
                            },
                        )
                    } finally {
                        val current = repository.settingsUpdates.value?.localNetworkAccess
                        check(
                            current == original ||
                                (current?.enabled == false && current.rules.all { it.name == name })
                        ) {
                            "Concurrent configuration retained for investigation"
                        }
                        if (current != original) {
                            assertTrue(
                                repository
                                    .setLocalNetworkAccess(
                                        checkNotNull(original),
                                        checkNotNull(current),
                                    )
                                    .isRight()
                            )
                            withTimeout(10_000) {
                                repository.settingsUpdates.first {
                                    it?.localNetworkAccess == original
                                }
                            }
                        }
                    }
                }
            }
        }
}
