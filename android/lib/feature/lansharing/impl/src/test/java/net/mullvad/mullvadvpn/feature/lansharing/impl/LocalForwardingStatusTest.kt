package net.mullvad.mullvadvpn.feature.lansharing.impl

import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNull
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.LocalRuleStatus
import net.mullvad.mullvadvpn.lib.model.WifiUnknownReason
import org.junit.jupiter.api.Test

class LocalForwardingStatusTest {
    private fun state(availability: ForwardingAvailability) =
        LocalNetworkSharingUiState(
            lanSharingEnabled = false,
            status =
                LocalNetworkStatus(
                    revision = 1u,
                    observerAvailable = true,
                    forwarding = availability,
                    currentWifi = ConnectedWifi.Unknown(WifiUnknownReason.Pending),
                    rules = emptyList(),
                ),
        )

    @Test
    fun `should show version unavailable only for NotAvailable`() {
        val state = state(ForwardingAvailability.NotAvailable)
        assertEquals(R.string.local_access_forwarding_unavailable, state.forwardingMessage())
        assertEquals(R.string.local_access_confirmation, state.confirmationMessage())
    }

    @Test
    fun `should show off for empty and disabled rule lists even when rules are on`() {
        val rule = LocalRuleDraft(UUID.randomUUID().toString(), addresses = "10.0.2.2/32").rule()!!
        for (policy in
            listOf(
                LocalNetworkAccess(),
                LocalNetworkAccess(enabled = true),
                LocalNetworkAccess(enabled = true, rules = listOf(rule.copy(enabled = false))),
            )) {
            val state = state(ForwardingAvailability.Off).copy(policy = policy)
            assertEquals(R.string.local_access_forwarding_off, state.forwardingMessage())
            assertEquals(R.string.local_access_delivery_confirmation, state.confirmationMessage())
        }
    }

    @Test
    fun `should show ready only from active forwarding availability`() {
        val state = state(ForwardingAvailability.Active)
        assertEquals(R.string.local_access_forwarding_active, state.forwardingMessage())
        assertEquals(R.string.local_access_delivery_confirmation, state.confirmationMessage())
    }

    @Test
    fun `should show paused while connecting or connected`() {
        val state = state(ForwardingAvailability.PausedWhileConnected)
        assertEquals(R.string.local_access_forwarding_paused, state.forwardingMessage())
        assertEquals(R.string.local_access_delivery_confirmation, state.confirmationMessage())
    }

    @Test
    fun `should show failed with the delivery confirmation`() {
        val state = state(ForwardingAvailability.Failed)
        assertEquals(R.string.local_access_forwarding_failed, state.forwardingMessage())
        assertEquals(R.string.local_access_delivery_confirmation, state.confirmationMessage())
    }

    @Test
    fun `should keep observer unavailable rule explanation while active without claiming forwarding`() {
        val rule = LocalRuleState.Inactive(LocalRuleInactiveReason.ObserverUnavailable)
        val state =
            state(ForwardingAvailability.Active).let {
                it.copy(
                    status =
                        it.status!!.copy(
                            observerAvailable = false,
                            rules = listOf(LocalRuleStatus(UUID(0, 0), rule)),
                        )
                )
            }
        assertEquals(R.string.local_access_forwarding_active, state.forwardingMessage())
        assertEquals(R.string.local_access_delivery_confirmation, state.confirmationMessage())
        assertEquals(
            R.string.local_access_observer_unavailable,
            state.status!!.rules.single().state.message(),
        )
    }

    @Test
    fun `should show forwarding only for the forwarding rule state`() {
        assertEquals(R.string.local_access_forwarding, LocalRuleState.Forwarding.message())
        assertEquals(R.string.local_access_conditions_met, LocalRuleState.ConditionsMet.message())
        for (reason in LocalRuleInactiveReason.entries) {
            assertEquals(reason.message(), LocalRuleState.Inactive(reason).message())
        }
    }

    @Test
    fun `should wait for status without inventing delivery availability`() {
        val state = LocalNetworkSharingUiState(lanSharingEnabled = false)
        assertNull(state.forwardingMessage())
        assertEquals(R.string.local_access_confirmation, state.confirmationMessage())
    }
}
