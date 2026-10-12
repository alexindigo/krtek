package net.mullvad.mullvadvpn.lib.usecase

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import net.mullvad.mullvadvpn.lib.model.BuildVersion
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SupportIssueUseCaseTest {
    private val issuesUrl = "https://example.test/issues"
    private val useCase =
        SupportIssueUseCase(
            issuesUrl = issuesUrl,
            buildVersion = BuildVersion("2026.12-dev-abcdef", 1),
            androidRelease = "16",
            androidSdk = 36,
            manufacturer = "Example",
            model = "Phone",
        )

    @Test
    fun `issue link should encode title and optional message without adding query parameters`() {
        val url = useCase(message = "Wi-Fi & DNS? 中文\nline + two", title = "API & unreachable?")
        assertTrue(url.startsWith("$issuesUrl/new?title="))
        val fields = query(url)
        assertEquals(setOf("title", "body"), fields.keys)
        assertEquals("API & unreachable?", fields["title"])
        assertEquals(
            "Wi-Fi & DNS? 中文\nline + two\n\n" +
                "App version: 2026.12-dev-abcdef\nAndroid: 16 (SDK 36)\n" +
                "Manufacturer: Example\nModel: Phone",
            fields["body"],
        )
    }

    @Test
    fun `empty message should contain only basic device details and no logs or account number`() {
        val body = query(useCase())["body"].orEmpty()
        assertEquals(
            "App version: 2026.12-dev-abcdef\nAndroid: 16 (SDK 36)\n" +
                "Manufacturer: Example\nModel: Phone",
            body,
        )
        assertFalse(body.contains("daemon.log"))
        assertFalse(Regex("[0-9]{16}").containsMatchIn(body))
        assertFalse(body.contains("device ID"))
    }

    @Test
    fun `account numbers in message and title should be removed before encoding`() {
        val url =
            useCase(
                message = "Account 1234567890123456 or 1234 5678 9012 3456 or 1234-5678-9012-3456",
                title = "1234567890123456",
            )
        val decoded = query(url).values.joinToString()
        assertFalse(Regex("[0-9]{16}").containsMatchIn(url))
        assertFalse(decoded.contains("1234"))
        assertTrue(decoded.contains("[account number removed]"))
    }

    @Test
    fun `large unicode message should fit encoded length cap and note truncation`() {
        val url = useCase(message = "🦔 & 中文\n".repeat(2000))
        assertTrue(url.length <= 4096)
        val body = query(url)["body"].orEmpty()
        assertTrue(body.contains("[Message truncated to fit the issue link.]"))
        assertTrue(body.endsWith("Manufacturer: Example\nModel: Phone"))
        assertFalse(body.contains('\uFFFD'))
    }

    @Test
    fun `short message should remain intact without truncation notice`() {
        val body = query(useCase(message = "Please help"))["body"].orEmpty()
        assertTrue(body.startsWith("Please help\n\nApp version:"))
        assertFalse(body.contains("truncated"))
    }

    private fun query(url: String): Map<String, String> =
        url.substringAfter('?').split('&').associate { field ->
            val (key, value) = field.split('=', limit = 2)
            key to URLDecoder.decode(value, StandardCharsets.UTF_8.name())
        }
}
