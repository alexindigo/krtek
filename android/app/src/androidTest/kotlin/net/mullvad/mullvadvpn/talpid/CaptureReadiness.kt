package net.mullvad.mullvadvpn.talpid

/** Samples from Android and the daemon log converge independently within the caller's deadline. */
internal object CaptureReadiness {
    data class Receipt(val generation: String, val handle: String, val text: String)

    data class PartialReceipt(val generation: String, val session: String, val format: String)

    fun configurationReady(
        addressesReady: Boolean,
        dns: String,
        mtu: Int,
        routes: Set<String>,
        expectedRoutes: Set<String>,
        requiredMtu: Int? = null,
    ): Boolean =
        addressesReady &&
            dns.isNotEmpty() &&
            mtu >= 1280 &&
            (requiredMtu == null || mtu == requiredMtu) &&
            routes.containsAll(expectedRoutes)

    fun partialReceipt(tail: String, previousGeneration: String?): PartialReceipt? {
        val current =
            tail
                .lineSequence()
                .lastOrNull { it.contains("router-authority ") }
                ?.substringAfter(" current=") ?: return null
        if (!current.contains("capture_ready: true") || !current.contains("ordinary_ready: false"))
            return null
        val generation =
            checkNotNull(Regex("capture_generation: Some\\(([0-9]+)\\)").find(current))
                .groupValues[1]
        val session =
            checkNotNull(Regex("session_generation: Some\\(([0-9]+)\\)").find(current))
                .groupValues[1]
        check(generation.toULong() > 0uL && session.toULong() > 0uL)
        if (previousGeneration != null && generation.toULong() <= previousGeneration.toULong())
            return null
        val format =
            tail.lineSequence().lastOrNull { it.contains("capture-format generation=$generation ") }
                ?: return null
        check(format.contains("representation=plain-ip"))
        val flags = format.substringAfter("flags=0x").trim().toInt(16)
        check(flags and 0x5003 == 0x1001) { "TUN/NO_PI without TAP or VNET_HDR" }
        return PartialReceipt(generation, session, format)
    }

    fun receipt(
        tail: String,
        iface: String,
        netId: String,
        routes: Set<String>,
        mtu: Int,
        ownerUid: Int,
        previousGeneration: String?,
        canonicalPrefix: (String) -> String,
    ): Receipt? {
        val line =
            tail.lineSequence().lastOrNull {
                (it.contains("capture-ready ") || it.contains("capture-lost ")) &&
                    it.contains(" network=$netId interface=$iface ")
            } ?: return null
        if (line.contains("capture-lost ")) return null
        val ready = line.substringAfter("capture-ready ")
        fun token(marker: String): String? =
            ready.substringAfter(marker, "").substringBefore(' ').takeIf { it.isNotEmpty() }
        val generation = checkNotNull(token("generation: ") ?: token("generation="))
        val handle = checkNotNull(token("handle="))
        check(generation.toULong() > 0uL && handle.toULong() > 0uL)
        check(
            ready.contains("requested_routes=") &&
                ready.contains(" observed_routes=") &&
                ready.contains(" api=")
        )
        val requested =
            ready.substringAfter("requested_routes=").substringBefore(" observed_routes=")
        val observed = ready.substringAfter("observed_routes=").substringBefore(" api=")
        check(requested == observed) { "Exact pushed route receipt, never a superset" }
        // CaptureExpectation projects complete routes, not a bare list of prefixes.
        // Consume the entire debug representation so missing/extra fields cannot pass.
        val routePattern =
            Regex(
                """CaptureRoute \{ destination: CapturePrefix \{ address: ([0-9a-fA-F:.]+), prefix_length: ([0-9]+) \}, gateway: None, interface_name: "([^"\\]+)", route_type: (?:None|Some\([17]\)) \}"""
            )
        val routeMatches = routePattern.findAll(observed).toList()
        check(routeMatches.joinToString(", ", "[", "]") { it.value } == observed) {
            "Malformed observed route receipt"
        }
        val prefixes =
            routeMatches
                .map { canonicalPrefix("${it.groupValues[1]}/${it.groupValues[2]}") }
                .toSet()
        if (previousGeneration != null && generation.toULong() <= previousGeneration.toULong())
            return null
        if (
            !ready.contains("owner_uid=Some($ownerUid)") ||
                !ready.contains("mtu=Some($mtu)") ||
                routeMatches.any { it.groupValues[3] != iface } ||
                prefixes != routes
        )
            return null
        return Receipt(generation, handle, ready)
    }
}
