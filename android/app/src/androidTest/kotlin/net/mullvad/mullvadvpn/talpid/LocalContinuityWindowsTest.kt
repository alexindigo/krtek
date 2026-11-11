package net.mullvad.mullvadvpn.talpid

import java.io.Reader
import java.io.StringReader
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class LocalContinuityWindowsTest {
    @Test
    fun shellReadsAreBoundedAndRebuildLogsAreSessionScoped() {
        assertEquals("test", LocalContinuityWindows.readBounded(StringReader("test"), 4))
        assertFails { LocalContinuityWindows.readBounded(StringReader("tests"), 4) }
        val huge =
            object : Reader() {
                var consumed = 0

                override fun read(buffer: CharArray, offset: Int, length: Int): Int {
                    if (consumed == 111_545_264) return -1
                    val count = minOf(length, 111_545_264 - consumed)
                    buffer.fill('x', offset, offset + count)
                    consumed += count
                    return count
                }

                override fun close() = Unit
            }
        assertFails { LocalContinuityWindows.readBounded(huge) }
        assertTrue(huge.consumed <= 2 * 1024 * 1024 + 4096)
        val command = LocalContinuityWindows.logCommand(1_794_366_000_000L)
        assertTrue(command.contains(" -T '") && command.endsWith("netd:I '*:S'"))
        assertTrue(
            command.contains("KrtekContinuityClock:I") && command.contains("wpa_supplicant:D")
        )
    }

    private val marks =
        listOf(
            LocalContinuityWindows.ClockMark("begin", 1_000_000_000, 1_000_010_000),
            LocalContinuityWindows.ClockMark("end", 2_000_000_000, 2_000_010_000),
        )
    private val log =
        """
        101.000005  1  1 I KrtekContinuityClock: test begin boottime_ns=1000000000
        101.220000  1  1 I netd: networkAddRouteParcel(188, destination: 10.0.2.2/32, ifName: tun1)
        101.200000  1  1 I NetlinkHandler: RTM_NEWLINK: ifname=tun0 ifi_flags=0x10 ()
        102.000005  1  1 I KrtekContinuityClock: test end boottime_ns=2000000000
        """
            .trimIndent()

    private fun measured(kind: String = "connect", text: String = log) =
        LocalContinuityWindows.measured(
            text,
            "test",
            listOf(LocalContinuityWindows.Intent(kind, 1_100_000_000)),
            marks,
        )

    @Test
    fun exchangeWindowUsesMeasuredRebuildNotIntentName() {
        for (kind in listOf("connect", "disconnect", "reconnect", "error", "app-list-change")) {
            val windows = measured(kind)
            val window = LocalContinuityWindows.accept(1_195_000_000, windows, mutableSetOf())
            assertTrue(window.down >= 1_200_000_000 && window.installed <= 1_220_000_000)
            assertTrue(window.contains(window.down - 100_000_000))
            assertFails {
                LocalContinuityWindows.accept(window.down - 100_000_001, windows, mutableSetOf())
            }
            assertFails {
                LocalContinuityWindows.accept(window.down - 150_000_000, windows, mutableSetOf())
            }
            assertFails {
                LocalContinuityWindows.accept(window.installed + 1, windows, mutableSetOf())
            }
        }
    }

    @Test
    fun atMostOneFailurePerRebuildAndNoAmbiguousAttribution() {
        val windows = measured()
        val used = mutableSetOf<Int>()
        LocalContinuityWindows.accept(1_190_000_000, windows, used)
        assertFails { LocalContinuityWindows.accept(1_210_000_000, windows, used) }
        val later = LocalContinuityWindows.Window(1_500_000_000, 1_520_000_000, 99)
        LocalContinuityWindows.accept(1_510_000_000, windows + later, used)
        assertFails {
            LocalContinuityWindows.accept(
                1_210_000_000,
                windows + windows.single().copy(rebuild = 98),
                mutableSetOf(),
            )
        }
    }

    @Test
    fun missingOrUncorrelatableEvidenceNeverQualifies() {
        assertFails { measured(text = log.substringAfter('\n')) }
        assertFails { measured(text = log.replace("102.000005", "102.100005")) }
        for (text in
            listOf(
                log.replace("ifName: tun1", "ifName: tun0"),
                log.replace("10.0.2.2/32", "10.0.2.3/32"),
                log.replace("101.220000", "101.500000"),
            )) {
            assertEquals(emptyList(), measured(text = text))
            assertFails {
                LocalContinuityWindows.accept(1_195_000_000, measured(text = text), mutableSetOf())
            }
        }
    }

    @Test
    fun realTick26RequestStartsBeforeDownButItsExchangeQualifies() {
        // Saved r10 Error-exit timing, with the actual conservative BOOTTIME hull.
        val window = LocalContinuityWindows.Window(8_088_247_265_908, 8_088_254_645_080, 1)
        val send = 8_088_240_405_770L
        assertTrue(send < window.down)
        assertEquals(window, LocalContinuityWindows.accept(send, listOf(window), mutableSetOf()))
        assertFails {
            LocalContinuityWindows.accept(window.down - 150_000_000, listOf(window), mutableSetOf())
        }
        assertFails { LocalContinuityWindows.accept(send, emptyList(), mutableSetOf()) }
        val used = mutableSetOf<Int>()
        LocalContinuityWindows.accept(send, listOf(window), used)
        assertFails { LocalContinuityWindows.accept(send + 1, listOf(window), used) }
    }
}
