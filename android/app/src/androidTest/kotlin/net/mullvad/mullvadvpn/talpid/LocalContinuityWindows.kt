package net.mullvad.mullvadvpn.talpid

import java.io.Reader
import java.math.BigDecimal

/** Test-only interpretation of Android's actual interface/route log events. */
internal object LocalContinuityWindows {
    private const val MAX_SHELL_CHARS = 2 * 1024 * 1024

    fun readBounded(reader: Reader, limit: Int = MAX_SHELL_CHARS): String {
        require(limit > 0)
        val result = StringBuilder()
        val buffer = CharArray(4096)
        while (true) {
            val count = reader.read(buffer)
            if (count < 0) return result.toString()
            check(count <= limit - result.length) { "Shell output exceeds bounded capture" }
            result.append(buffer, 0, count)
        }
    }

    fun logCommand(sinceMillis: Long): String {
        // Include the begin marker, not the device's entire retained log history.
        // executeShellCommand uses Runtime.exec tokenization, not shell quoting.
        // Keep the fractional part even at a whole second: digits alone mean a line count.
        val since = BigDecimal.valueOf(sinceMillis - 1000, 3).toPlainString()
        return "logcat -d -b all -v epoch -v usec -T $since " +
            "KrtekContinuityClock:I wpa_supplicant:D NetlinkHandler:D netd:I *:S"
    }

    data class Intent(val kind: String, val time: Long)

    data class ClockMark(val kind: String, val before: Long, val after: Long)

    // Observed maximum exchange latency was 35.6 ms. Allow 100 ms before DOWN
    // with margin for a request whose reply crosses the measured rebuild gap.
    private const val EXCHANGE_MARGIN_NS = 100_000_000L

    data class Window(val down: Long, val installed: Long, val rebuild: Int) {
        fun contains(time: Long) = time in (down - EXCHANGE_MARGIN_NS)..installed
    }

    // Log timestamps have microsecond resolution. Clock markers bracket the log write,
    // so only the intersection guaranteed by both markers is eligible for tolerance.
    fun measured(
        log: String,
        marker: String,
        intents: List<Intent>,
        marks: List<ClockMark>,
    ): List<Window> {
        val event = Regex("^\\s*(\\d+)\\.(\\d{3,9})\\s+.*")
        val entries =
            log.lineSequence()
                .mapNotNull { line ->
                    event.matchEntire(line)?.let {
                        val ns =
                            it.groupValues[1].toLong() * 1_000_000_000L +
                                it.groupValues[2].padEnd(9, '0').toLong()
                        ns to line
                    }
                }
                .sortedBy { it.first }
                .toList()
        val anchor = Regex("KrtekContinuityClock: $marker (begin|end) boottime_ns=(\\d+)")
        val anchors = entries.mapNotNull { (time, line) ->
            anchor.find(line)?.let { Triple(it.groupValues[1], time, it.groupValues[2].toLong()) }
        }
        check(anchors.map { it.first }.sorted() == listOf("begin", "end")) {
            "Missing clock markers"
        }
        val bounds = anchors.map { (kind, time, before) ->
            val mark = marks.single { it.kind == kind && it.before == before }
            check(mark.after >= before && mark.after - before <= 2_000_000L) { "Slow clock marker" }
            (time - mark.after - 1_000L) to (time - before + 1_000L)
        }
        check(bounds.maxOf { it.first } <= bounds.minOf { it.second }) {
            "Unstable log/BOOTTIME correlation"
        }
        val low = bounds.minOf { it.first }
        val high = bounds.maxOf { it.second }
        val down = Regex("RTM_NEWLINK:.*ifname=(tun\\d+).*ifi_flags=0x10 \\(\\)")
        val route =
            Regex(
                "networkAddRouteParcel\\((\\d+), .*destination: 10\\.0\\.2\\.2/32, ifName: (tun\\d+)"
            )
        check(intents.zipWithNext().all { (a, b) -> a.time <= b.time }) { "Reordered intents" }
        val sessionEntries = entries.filter {
            it.first in anchors.minOf { a -> a.second }..anchors.maxOf { a -> a.second }
        }
        return sessionEntries.mapIndexedNotNull { index, (time, line) ->
            val old = down.find(line)?.groupValues?.get(1) ?: return@mapIndexedNotNull null
            val installed =
                sessionEntries
                    .drop(index + 1)
                    .takeWhile { it.first - time <= 250_000_000L }
                    .firstOrNull { (_, later) ->
                        route.find(later)?.groupValues?.get(2)?.let { it != old } == true
                    } ?: return@mapIndexedNotNull null
            val start = time + 1_000L - low
            val finish = installed.first - 1_000L - high
            check(start <= finish) { "Rebuild window below clock resolution" }
            // Intent names correlate the evidence; they never create or veto a rebuild.
            Window(start, finish, index)
        }
    }

    fun accept(time: Long, windows: List<Window>, used: MutableSet<Int>): Window {
        val matches = windows.filter { it.contains(time) }
        check(matches.size == 1) {
            "UDP exchange outside one unambiguous measured rebuild"
        }
        return matches.single().also {
            check(used.add(it.rebuild)) { "Second UDP failure in one rebuild" }
        }
    }
}
