package net.mullvad.mullvadvpn.lib.model

import java.util.UUID
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class LocalNetworkAccessTest {
    private fun cidr(text: String) = checkNotNull(LocalCidr.parse(text).getOrNull())

    private fun rule() =
        LocalBypassRule(
            UUID(0, 1),
            "private-name",
            true,
            listOf(cidr("192.168.240.0/28")),
            listOf(checkNotNull(SsidIdentity.fromUserText("private-wifi"))),
        )

    @Test
    fun `should accept only prefixes wholly contained in local scopes`() {
        for (text in
            listOf(
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "fc00::/7",
                "fe80::/10",
                "192.168.240.10/32",
                "fd42::10/124",
                "fe80::10/128",
            )) {
            assertEquals(text, cidr(text).toString())
        }
        val prefix = cidr("192.168.240.0/28")
        assertTrue(prefix.contains(checkNotNull(LocalCidr.parseAddress("192.168.240.15"))))
        assertFalse(prefix.contains(checkNotNull(LocalCidr.parseAddress("192.168.240.16"))))
        assertFalse(prefix.contains(checkNotNull(LocalCidr.parseAddress("fe80::10"))))
    }

    @Test
    fun `should reject nonlocal and malformed numeric input without DNS`() {
        for (text in
            listOf(
                "0.0.0.0/0",
                "10.0.0.0/7",
                "100.64.0.0/10",
                "203.0.113.0/24",
                "127.0.0.1/32",
                "224.0.0.0/4",
                "255.255.255.255/32",
                "::/0",
                "::1/128",
                "2001:db8::/32",
                "ff02::/16",
                "::ffff:10.0.0.1/128",
            )) {
            assertEquals(LocalCidrError.OutsideLocalScope, LocalCidr.parse(text).leftOrNull(), text)
        }
        for (text in
            listOf(
                "localhost/32",
                "10.0.0.1",
                " 10.0.0.0/8",
                "10.0.0.0/+8",
                "010.0.0.0/8",
                "10.0.0.0/255.0.0.0",
                "10.0.0.0/33",
                "fe80::%eth0/64",
                "fe80:::1/128",
                "fe80::1::2/128",
                "fe80::/129",
                "fe80:0:0:0:0:0:0::1/128",
            )) {
            assertEquals(LocalCidrError.Malformed, LocalCidr.parse(text).leftOrNull(), text)
        }
    }

    @Test
    fun `should report canonical prefix without silently widening it`() {
        assertEquals(
            LocalCidrError.Noncanonical("192.168.2.0/23"),
            LocalCidr.parse("192.168.3.27/23").leftOrNull(),
        )
        assertEquals(
            LocalCidrError.Noncanonical("fd42::/64"),
            LocalCidr.parse("fd42::1/64").leftOrNull(),
        )
    }

    @Test
    fun `should normalize IPv6 numeric spellings and protect address storage`() {
        val prefix = cidr("FE80:0000:0000:0000:0000:0000:0000:0010/128")
        assertEquals("fe80::10/128", prefix.toString())
        assertEquals(prefix, cidr(prefix.toString()))
        val bytes = prefix.networkBytes()
        bytes.fill(0)
        assertNotEquals(bytes.toList(), prefix.networkBytes().toList())
        assertEquals(cidr("fd42::c0a8:1/128"), cidr("fd42::192.168.0.1/128"))
    }

    @Test
    fun `should preserve immutable exact SSID bytes and reject invalid lengths`() {
        val bytes = byteArrayOf(0, -1, 65, 32)
        val ssid = checkNotNull(SsidIdentity.fromBytes(bytes))
        bytes.fill(0)
        ssid.bytes().fill(1)
        assertEquals("00ff4120", ssid.encodedBytes())
        assertContentEquals(byteArrayOf(0, -1, 65, 32), ssid.bytes())
        assertNull(SsidIdentity.fromBytes(byteArrayOf()))
        assertNull(SsidIdentity.fromBytes(ByteArray(33)))
        assertEquals(32, checkNotNull(SsidIdentity.fromBytes(ByteArray(32))).bytes().size)
    }

    @Test
    fun `should display valid UTF8 or hex while preserving exact text identity`() {
        val text = checkNotNull(SsidIdentity.fromUserText("Ł船 "))
        assertEquals("Ł船 ", text.displayText())
        assertNotEquals(text, SsidIdentity.fromUserText("Ł船"))
        assertEquals(
            "00ff4120",
            checkNotNull(SsidIdentity.fromBytes(byteArrayOf(0, -1, 65, 32))).displayText(),
        )
        assertNull(SsidIdentity.fromUserText("\uD800"))
        assertNull(SsidIdentity.fromUserText("船".repeat(11)))
        assertEquals("SsidIdentity(redacted)", text.toString())
    }

    @Test
    fun `should enforce policy limits before deduplication including disabled rules`() {
        val boundary =
            rule()
                .copy(
                    enabled = false,
                    name = "船".repeat(64),
                    cidrs = List(32) { cidr("10.0.0.0/8") },
                    ssidIds = List(16) { checkNotNull(SsidIdentity.fromBytes(byteArrayOf(0))) },
                )
        assertNull(LocalNetworkAccess(rules = listOf(boundary)).validationError())
        val variants =
            listOf(
                boundary.copy(name = "船".repeat(65)) to LocalPolicyValidationError.NameTooLong,
                boundary.copy(cidrs = boundary.cidrs + boundary.cidrs[0]) to
                    LocalPolicyValidationError.TooManyCidrs,
                boundary.copy(ssidIds = boundary.ssidIds + boundary.ssidIds[0]) to
                    LocalPolicyValidationError.TooManySsids,
            )
        for ((rule, error) in variants) assertEquals(
            error,
            LocalNetworkAccess(rules = listOf(rule)).validationError(),
        )
        val rules = (0L until 64L).map { boundary.copy(id = UUID(0, it)) }
        assertNull(LocalNetworkAccess(rules = rules).validationError())
        assertEquals(
            LocalPolicyValidationError.TooManyRules,
            LocalNetworkAccess(rules = rules + boundary.copy(id = UUID(0, 64))).validationError(),
        )
        assertNull(
            LocalNetworkAccess(rules = listOf(boundary.copy(name = "😀".repeat(64))))
                .validationError()
        )
    }

    @Test
    fun `should reject ambiguous rules without leaking policy contents`() {
        val rule = rule()
        assertEquals(
            LocalPolicyValidationError.DuplicateRuleId,
            LocalNetworkAccess(rules = listOf(rule, rule)).validationError(),
        )
        assertEquals(
            LocalPolicyValidationError.EmptyEnabledRule,
            LocalNetworkAccess(rules = listOf(rule.copy(cidrs = emptyList()))).validationError(),
        )
        assertNull(
            LocalNetworkAccess(rules = listOf(rule.copy(enabled = false, cidrs = emptyList())))
                .validationError()
        )
        assertEquals(LocalNetworkAccess(false, emptyList()), LocalNetworkAccess())
        val diagnostic = "${LocalNetworkAccess(true, listOf(rule))} $rule ${rule.ssidIds}"
        for (secret in
            listOf(
                "private-name",
                "private-wifi",
                "192.168.240",
                rule.ssidIds[0].encodedBytes(),
            )) assertFalse(diagnostic.contains(secret))
    }
}
