package net.mullvad.mullvadvpn.lib.usecase

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import net.mullvad.mullvadvpn.lib.model.BuildVersion

class SupportIssueUseCase(
    private val issuesUrl: String,
    private val buildVersion: BuildVersion,
    private val androidRelease: String,
    private val androidSdk: Int,
    private val manufacturer: String,
    private val model: String,
) {
    operator fun invoke(message: String? = null, title: String = "Problem report"): String {
        val safeTitle = title.redactAccountNumbers().takeCodePoints(MAX_DETAIL_LENGTH)
        val details =
            """
            App version: ${buildVersion.name.safeDetail()}
            Android: ${androidRelease.safeDetail()} (SDK $androidSdk)
            Manufacturer: ${manufacturer.safeDetail()}
            Model: ${model.safeDetail()}
            """
                .trimIndent()
        val safeMessage = message.orEmpty().redactAccountNumbers()
        val messageLength = safeMessage.codePointCount(0, safeMessage.length)
        fun url(length: Int): String {
            val body = buildString {
                append(safeMessage.takeCodePoints(length))
                if (length < messageLength) {
                    append("\n[Message truncated to fit the issue link.]")
                }
                if (isNotEmpty()) append("\n\n")
                append(details)
            }
            return "$issuesUrl/new?title=${safeTitle.encode()}&body=${body.encode()}"
        }
        val maximum = minOf(messageLength, MAX_URL_LENGTH)
        val complete = url(maximum)
        if (complete.length <= MAX_URL_LENGTH) return complete
        var low = 0
        var high = maximum
        while (low < high) {
            val middle = (low + high + 1) / 2
            if (url(middle).length <= MAX_URL_LENGTH) {
                low = middle
            } else {
                high = middle - 1
            }
        }
        return url(low)
    }

    private fun String.redactAccountNumbers(): String =
        replace(ACCOUNT_NUMBER, "[account number removed]")

    private fun String.safeDetail(): String =
        redactAccountNumbers().takeCodePoints(MAX_DETAIL_LENGTH)

    private fun String.takeCodePoints(limit: Int): String =
        substring(0, offsetByCodePoints(0, minOf(limit, codePointCount(0, length))))

    private fun String.encode(): String = URLEncoder.encode(this, StandardCharsets.UTF_8.name())

    companion object {
        private const val MAX_URL_LENGTH = 4096
        private const val MAX_DETAIL_LENGTH = 60
        private val ACCOUNT_NUMBER = Regex("(?:[0-9][\\s-]*){16,}")
    }
}
