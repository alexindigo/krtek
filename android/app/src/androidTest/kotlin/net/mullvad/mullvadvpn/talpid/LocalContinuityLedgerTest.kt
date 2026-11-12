package net.mullvad.mullvadvpn.talpid

import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class LocalContinuityLedgerTest {
    private val failure =
        LocalContinuityLedger.UdpSendFailure(
            expectedScheduled = 1_000_000_000,
            scheduled = 1_000_000_000,
            start = 1_001_000_000,
            send = 1_010_000_000,
            returned = 1_020_000_000,
            errorClass = "java.net.SocketException",
            ioException = "java.net.SocketException: sendto failed",
        )

    private fun retired(boundary: Long?, sample: LocalContinuityLedger.UdpSendFailure = failure) =
        LocalContinuityLedger.retirementOutcome(
            "udp",
            "udp-send-error",
            sample.scheduled,
            boundary,
            sample,
        )

    @Test
    fun retirementUsesTheActualSendFailureReturnTime() {
        assertFalse(retired(null))
        // All these deadlines overlap the intent; only actual failure return decides retirement.
        assertTrue(retired(failure.send - 1))
        assertTrue(retired(failure.send + 1))
        assertTrue(retired(failure.returned))
        assertFalse(retired(failure.returned + 1))
        assertFalse(retired(failure.returned + 1_000_000_000))
        assertFails {
            LocalContinuityLedger.retirementOutcome(
                "tcp",
                "udp-send-error",
                failure.scheduled,
                1,
                failure,
            )
        }
        assertFails {
            LocalContinuityLedger.retirementOutcome("udp", "udp-send-error", failure.scheduled, 1)
        }
    }

    @Test
    fun completedPreIntentErrorsStillRequireTheFullMeasuredContinuityPath() {
        val sample = failure.copy(send = 1_195_000_000, returned = 1_198_000_000)
        val boundary = 1_210_000_000L
        assertFalse(retired(boundary, sample))
        assertFails { LocalContinuityWindows.accept(sample.send, emptyList(), mutableSetOf()) }
        val window = LocalContinuityWindows.Window(1_200_000_000, 1_220_000_000, 0)
        val used = mutableSetOf<Int>()
        assertEquals(window, LocalContinuityWindows.accept(sample.send, listOf(window), used))
        assertFails { LocalContinuityWindows.accept(sample.send + 1, listOf(window), used) }
        assertFails {
            LocalContinuityWindows.accept(window.down - 150_000_000, listOf(window), mutableSetOf())
        }
    }

    @Test
    fun malformedSendFailureMetadataNeverBecomesRetirement() {
        assertFails { failure.copy(scheduled = failure.scheduled + 1) }
        assertFails { failure.copy(start = failure.scheduled - 1) }
        assertFails { failure.copy(start = failure.send + 1) }
        assertFails {
            failure.copy(
                start = failure.scheduled + 250_000_000,
                send = failure.scheduled + 250_000_000,
            )
        }
        assertFails { failure.copy(returned = failure.send - 1) }
        assertFails { failure.copy(returned = failure.scheduled + 5_000_000_001) }
        assertFails {
            failure.copy(
                errorClass = "java.lang.IllegalStateException",
                ioException = "java.lang.IllegalStateException: bad",
            )
        }
        assertFails { failure.copy(ioException = "") }
        assertFails { failure.copy(ioException = "java.io.IOException: different class") }
        assertFails { failure.copy(errorClass = "missing.Exception") }
    }

    @Test
    fun inFlightRetirementVocabularyAndStrictOtherOutcomesArePreserved() {
        for (outcome in listOf("error", "cancelled", "udp-reply-missing")) {
            assertTrue(
                LocalContinuityLedger.retirementOutcome(
                    "udp",
                    outcome,
                    1_000_000_000,
                    2_000_000_000,
                )
            )
            assertFalse(
                LocalContinuityLedger.retirementOutcome(
                    "udp",
                    outcome,
                    1_000_000_000,
                    6_000_000_001,
                )
            )
        }
        assertFalse(
            LocalContinuityLedger.retirementOutcome("udp", "reply", 1_000_000_000, 2_000_000_000)
        )
        assertFails {
            LocalContinuityLedger.retirementOutcome(
                "udp",
                "harness-error",
                1_000_000_000,
                2_000_000_000,
            )
        }
    }
}
