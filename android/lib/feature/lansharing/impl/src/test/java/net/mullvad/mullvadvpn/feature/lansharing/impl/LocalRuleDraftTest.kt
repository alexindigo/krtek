package net.mullvad.mullvadvpn.feature.lansharing.impl

import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import org.junit.jupiter.api.Test

class LocalRuleDraftTest {
    private val draft = LocalRuleDraft(UUID.randomUUID().toString(), addresses = "192.168.1.0/24")

    @Test
    fun `should preserve exact spaces commas and unicode in wifi names`() {
        val text = "  café, office  "
        val rule = assertNotNull(draft.copy(wifiNames = listOf(LocalWifiDraft(text))).rule())
        assertEquals(text, rule.ssidIds.single().displayText())
        assertEquals(rule, LocalRuleDraft.from(rule).rule())
    }

    @Test
    fun `should preserve binary identities without interpreting hex as typed text`() {
        val binary = assertNotNull(SsidIdentity.fromBytes(byteArrayOf(-1, 0, -2)))
        val field = LocalWifiDraft.from(binary)
        assertEquals("ff00fe", field.text)
        assertEquals(binary, field.identity())
        assertEquals(
            SsidIdentity.fromUserText("ff00fe"),
            field.copy(originalBytes = null).identity(),
        )
    }

    @Test
    fun `should suggest canonical ranges and reject public or invalid addresses`() {
        assertEquals(
            "192.168.1.0/24",
            draft.copy(addresses = "192.168.1.42/24").canonicalSuggestion(),
        )
        listOf("192.168.1.42/24", "8.8.8.8/32", "not an address", "10.0.0.0/8,,").forEach {
            assertNull(draft.copy(addresses = it).rule())
        }
    }

    @Test
    fun `should reject limits before deduplication and empty wifi fields`() {
        assertNull(draft.copy(addresses = List(33) { "10.0.0.0/8" }.joinToString(",")).rule())
        assertNull(draft.copy(wifiNames = List(17) { LocalWifiDraft("same") }).rule())
        assertNull(draft.copy(name = "x".repeat(65)).rule())
        assertNull(draft.copy(wifiNames = listOf(LocalWifiDraft(""))).rule())
        assertNull(draft.copy(addresses = "").rule())
        assertNotNull(draft.copy(addresses = "", enabled = false).rule())
    }

    @Test
    fun `should round trip disabled rules and redact all draft diagnostics`() {
        val rule =
            LocalBypassRule(
                UUID.randomUUID(),
                "Private",
                false,
                listOf(LocalCidr.parse("10.0.0.0/8").getOrNull()!!),
                listOf(SsidIdentity.fromUserText("Secret")!!),
            )
        val restored = LocalRuleDraft.from(rule)
        assertEquals(rule, restored.rule())
        assertFalse(restored.toString().contains("Private"))
        assertFalse(restored.wifiNames.toString().contains("Secret"))
    }
}
