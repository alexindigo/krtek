package net.mullvad.mullvadvpn.feature.lansharing.impl

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class LocalPermissionRequestStateTest {
    private val granted = LocalPermissionGrants(37, true, true, true, true, true)

    @Test
    fun `should request only local access for a plain rule`() {
        val missing =
            granted.copy(
                local = false,
                fine = false,
                coarse = false,
                background = false,
                location = false,
            )
        val flight = LocalPermissionRequestState().begin(false, missing).launched()
        assertEquals(LocalPermissionStep.Local, flight.flight)
        assertFalse(flight.result(flight.token, missing.copy(local = true)).active)
    }

    @Test
    fun `should not prompt when wifi access is already granted`() {
        val result = LocalPermissionRequestState().begin(true, granted)
        assertFalse(result.active)
        assertNull(result.failure)
    }

    @Test
    fun `should separate foreground and background requests`() {
        val request =
            LocalPermissionRequestState()
                .begin(true, granted.copy(fine = false, coarse = false, background = false))
        assertEquals(LocalPermissionStep.ExplainFine, request.step)
        val flight = request.confirm().launched()
        assertEquals(
            LocalPermissionStep.ExplainBackground,
            flight.result(flight.token, granted.copy(background = false)).step,
        )
    }

    @Test
    fun `should skip background when already granted after foreground result`() {
        val flight =
            LocalPermissionRequestState()
                .begin(true, granted.copy(fine = false))
                .confirm()
                .launched()
        assertFalse(flight.result(flight.token, granted).active)
    }

    @Test
    fun `should stop an approximate grant until an explicit retry`() {
        val flight =
            LocalPermissionRequestState()
                .begin(true, granted.copy(fine = false))
                .confirm()
                .launched()
        val denied = flight.result(flight.token, granted.copy(fine = false))
        assertEquals(LocalPermissionFailure.ApproximateOnly, denied.failure)
        assertFalse(denied.active)
        assertEquals(
            LocalPermissionStep.ExplainFine,
            denied.begin(true, granted.copy(fine = false)).step,
        )
    }

    @Test
    fun `should never automatically repeat a denied foreground request`() {
        val missing = granted.copy(fine = false, coarse = false)
        val flight = LocalPermissionRequestState().begin(true, missing).confirm().launched()
        val denied = flight.result(flight.token, missing)
        assertEquals(LocalPermissionFailure.FineDenied, denied.failure)
        assertEquals(LocalPermissionStep.Idle, denied.step)
        assertFalse(denied.active)
    }

    @Test
    fun `should permit only one platform flight`() {
        val flight =
            LocalPermissionRequestState().begin(false, granted.copy(local = false)).launched()
        assertEquals(flight, flight.begin(true, granted))
        assertEquals(flight, flight.launched())
    }

    @Test
    fun `should drain cancelled results without resuming a superseded request`() {
        val flight =
            LocalPermissionRequestState()
                .begin(true, granted.copy(fine = false))
                .confirm()
                .launched()
        val cancelled = flight.cancel()
        assertEquals(cancelled, cancelled.begin(true, granted))
        val drained = cancelled.result(flight.token, granted.copy(background = false))
        assertFalse(drained.active)
        assertNull(drained.flight)
        assertEquals(
            LocalPermissionStep.ExplainBackground,
            drained.begin(true, granted.copy(background = false)).step,
        )
    }

    @Test
    fun `should ignore an unrelated late result token`() {
        val flight =
            LocalPermissionRequestState().begin(false, granted.copy(local = false)).launched()
        assertEquals(flight, flight.result(flight.token - 1, granted))
    }

    @Test
    fun `should require a real background grant on return from settings`() {
        val background =
            LocalPermissionRequestState()
                .begin(true, granted.copy(background = false))
                .confirm()
                .launched()
        val flight =
            background
                .result(background.token, granted.copy(background = false))
                .confirm()
                .launched()
        val denied = flight.result(flight.token, granted.copy(background = false))
        assertEquals(LocalPermissionFailure.BackgroundMissing, denied.failure)
        assertFalse(denied.active)
        assertNull(flight.result(flight.token, granted).failure)
    }

    @Test
    fun `should require neither separate background nor local access on API28`() {
        val result =
            LocalPermissionRequestState()
                .begin(true, granted.copy(sdk = 28, background = false, local = false))
        assertFalse(result.active)
        assertNull(result.failure)
    }

    @Test
    fun `should expose location off and settings unavailable without prompting in a loop`() {
        val result = LocalPermissionRequestState().begin(true, granted.copy(location = false))
        assertEquals(LocalPermissionFailure.LocationOff, result.failure)
        assertEquals(LocalPermissionStep.LocationSettings, result.settings().step)
        assertEquals(
            LocalPermissionFailure.SettingsUnavailable,
            result.settings().unavailable().failure,
        )
        assertFalse(result.settings().unavailable().active)
    }

    @Test
    fun `should request API37 local access after the entire wifi permission sequence`() {
        val missing = granted.copy(local = false, fine = false, coarse = false, background = false)
        val fine = LocalPermissionRequestState().begin(true, missing).confirm().launched()
        val background =
            fine.result(fine.token, missing.copy(fine = true, coarse = true)).confirm().launched()
        val local = background.result(background.token, granted.copy(local = false)).launched()
        assertEquals(LocalPermissionStep.Local, local.flight)
        assertFalse(local.result(local.token, granted).active)
        assertEquals(
            LocalPermissionFailure.LocalMissing,
            local.result(local.token, granted.copy(local = false)).failure,
        )
    }

    @Test
    fun `should request background directly with destination specific copy on API29 30 and 37`() {
        for (sdk in listOf(29, 30, 37)) {
            val explained =
                LocalPermissionRequestState()
                    .begin(true, granted.copy(sdk = sdk, background = false))
            val content = checkNotNull(explained.step.explanation(sdk))
            assertEquals(
                if (sdk == 29) R.string.local_access_background_dialog_help
                else R.string.local_access_background_help,
                content.help,
            )
            assertEquals(
                if (sdk == 29) R.string.local_access_request_location
                else R.string.local_access_location_permission,
                content.action,
            )
            assertEquals(LocalPermissionStep.Background, explained.confirm().launched().flight)
        }
    }

    @Test
    fun `should explain App info only after a background refusal without foreground departure`() {
        for (sdk in listOf(30, 37)) {
            val missing = granted.copy(sdk = sdk, background = false)
            val flight = LocalPermissionRequestState().begin(true, missing).confirm().launched()
            val fallback = flight.result(flight.token, missing)
            assertEquals(LocalPermissionStep.ExplainBackgroundFallback, fallback.step)
            assertTrue(fallback.active)
            assertNull(fallback.flight)
            assertEquals(fallback, fallback.begin(true, missing))
            val content = checkNotNull(fallback.step.explanation(sdk))
            assertEquals(R.string.local_access_background_settings_help, content.help)
            assertEquals(R.string.local_access_app_settings, content.action)
            assertEquals(LocalPermissionStep.AppSettings, fallback.confirm().launched().flight)
            val cancelled = fallback.cancel()
            assertFalse(cancelled.active)
            assertEquals(LocalPermissionStep.Idle, cancelled.step)
        }
    }

    @Test
    fun `should stop after a real background page refusal rather than offer the no UI fallback`() {
        for (sdk in listOf(29, 30, 37)) {
            val missing = granted.copy(sdk = sdk, background = false)
            val flight = LocalPermissionRequestState().begin(true, missing).confirm().launched()
            val denied = flight.foregroundLeft(flight.token).result(flight.token, missing)
            assertEquals(LocalPermissionFailure.BackgroundMissing, denied.failure)
            assertEquals(LocalPermissionStep.Idle, denied.step)
            assertFalse(denied.active)
            assertFalse(denied.leftForeground)
            assertEquals(LocalPermissionStep.AppSettings, denied.settings().step)
        }
    }

    @Test
    fun `should not offer the API30 fallback after an API29 dialog denial`() {
        val missing = granted.copy(sdk = 29, background = false)
        val flight = LocalPermissionRequestState().begin(true, missing).confirm().launched()
        assertEquals(
            LocalPermissionFailure.BackgroundMissing,
            flight.result(flight.token, missing).failure,
        )
    }

    @Test
    fun `should bind foreground departure to the live background flight token`() {
        val missing = granted.copy(background = false)
        val request = LocalPermissionRequestState().begin(true, missing)
        assertEquals(request, request.foregroundLeft(request.token))
        val flight = request.confirm().launched()
        assertEquals(flight, flight.foregroundLeft(flight.token - 1))
        val departed = flight.foregroundLeft(flight.token)
        assertTrue(departed.leftForeground)
        assertEquals(departed, departed.result(flight.token - 1, missing))
        val cancelled = departed.cancel()
        assertEquals(cancelled, cancelled.foregroundLeft(flight.token))
        assertEquals(cancelled, cancelled.begin(true, missing))
        val drained = cancelled.result(flight.token, missing)
        assertFalse(drained.active)
        assertFalse(drained.leftForeground)
        assertNull(drained.flightToken)
        assertNull(drained.failure)
        val next = drained.begin(true, missing).confirm().launched()
        assertFalse(next.leftForeground)
        assertEquals(next, next.foregroundLeft(flight.token))
    }

    @Test
    fun `should complete a synchronous background grant without showing fallback`() {
        val flight =
            LocalPermissionRequestState()
                .begin(true, granted.copy(background = false))
                .confirm()
                .launched()
        val result = flight.result(flight.token, granted)
        assertFalse(result.active)
        assertNull(result.failure)
        assertEquals(LocalPermissionStep.Idle, result.step)
    }

    @Test
    fun `should ignore foreground departure for other permission launchers`() {
        val flight =
            LocalPermissionRequestState().begin(false, granted.copy(local = false)).launched()
        assertEquals(flight, flight.foregroundLeft(flight.token))
    }

    @Test
    fun `should continue to local access after location is enabled`() {
        val flight =
            LocalPermissionRequestState()
                .begin(true, granted.copy(location = false, local = false))
                .settings()
                .launched()
        assertEquals(
            LocalPermissionStep.Local,
            flight.result(flight.token, granted.copy(local = false)).step,
        )
        assertTrue(flight.result(flight.token, granted.copy(local = false)).active)
    }
}
