package net.mullvad.mullvadvpn.lib.grpc.mapper

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import mullvad_daemon.management_interface.LocalBypassRule
import mullvad_daemon.management_interface.LocalNetworkAccess
import mullvad_daemon.management_interface.LocalNetworkPolicyUpdate
import okio.ByteString.Companion.toByteString
import org.junit.jupiter.api.Test

class LocalNetworkAccessMapperTest {
    private fun policy() =
        LocalNetworkAccess(
            enabled = true,
            rules =
                listOf(
                    LocalBypassRule(
                        id = "00000000-0000-0000-0000-000000000001",
                        name = "private-rule",
                        enabled = true,
                        cidrs = listOf("192.168.240.0/28", "fe80::10/128"),
                        ssid_ids = listOf(byteArrayOf(0, -1, 65, 32).toByteString()),
                    )
                ),
        )

    @Test
    fun `should preserve wire policy and optional expected through encode decode and mapping`() {
        val wire = policy()
        for (expected in listOf(null, LocalNetworkAccess(), wire)) {
            val update =
                LocalNetworkPolicyUpdate(
                    policy = wire.toDomain().fromDomain(),
                    expected = expected?.toDomain()?.fromDomain(),
                )
            val decoded =
                LocalNetworkPolicyUpdate.ADAPTER.decode(
                    LocalNetworkPolicyUpdate.ADAPTER.encode(update)
                )
            assertEquals(update, decoded)
            assertEquals(wire.toDomain(), decoded.policy?.toDomain())
        }
        assertEquals(wire, wire.toDomain().fromDomain())
    }

    @Test
    fun `should reject malformed wire fields without echoing secrets`() {
        val rule = policy().rules[0]
        for (invalid in
            listOf(
                rule.copy(id = "private-marker"),
                rule.copy(id = "1-1-1-1-1"),
                rule.copy(cidrs = listOf("private-marker")),
                rule.copy(cidrs = listOf("192.168.241.27/24")),
                rule.copy(ssid_ids = listOf(ByteArray(33).toByteString())),
            )) {
            val error =
                assertFailsWith<IllegalArgumentException> {
                    policy().copy(rules = listOf(invalid)).toDomain()
                }
            assertFalse(error.toString().contains("private-marker"))
            assertFalse(error.toString().contains("192.168.241"))
        }
    }

    @Test
    fun `should enforce limits and rule validity before normalizing entries`() {
        val rule = policy().rules[0]
        for (invalid in
            listOf(
                rule.copy(name = "x".repeat(65)),
                rule.copy(cidrs = List(33) { rule.cidrs[0] }),
                rule.copy(ssid_ids = List(17) { rule.ssid_ids[0] }),
                rule.copy(cidrs = emptyList()),
            )) {
            assertFailsWith<IllegalArgumentException> {
                policy().copy(rules = listOf(invalid)).toDomain()
            }
        }
        assertFailsWith<IllegalArgumentException> {
            policy().copy(rules = List(65) { rule }).toDomain()
        }
        assertFailsWith<IllegalArgumentException> {
            policy().copy(rules = listOf(rule, rule)).toDomain()
        }
        val repeated =
            policy()
                .copy(
                    rules =
                        listOf(
                            rule.copy(
                                cidrs = rule.cidrs + rule.cidrs,
                                ssid_ids = rule.ssid_ids + rule.ssid_ids,
                            )
                        )
                )
        assertEquals(policy().toDomain(), repeated.toDomain())
        assertEquals(
            net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess(),
            LocalNetworkAccess().toDomain(),
        )
    }
}
