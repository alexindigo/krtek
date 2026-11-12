package net.mullvad.mullvadvpn.talpid

import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class CaptureReadinessTest {
    private val routes = setOf("10.0.2.2/32")
    private val encoded =
        "[CaptureRoute { destination: CapturePrefix { address: 10.0.2.2, prefix_length: 32 }, gateway: None, interface_name: \"tun0\", route_type: Some(1) }]"

    private fun ready(generation: String = "12", observed: String = encoded): String =
        "capture-ready generation=$generation handle=99 network=42 interface=tun0 owner_uid=Some(10181) mtu=Some(1380) requested_routes=$encoded observed_routes=$observed api=33 representation=plain-ip tun_flags=0x1001"

    private fun sample(tail: String, previous: String? = "11") =
        CaptureReadiness.receipt(tail, "tun0", "42", routes, 1380, 10181, previous) { it }

    @Test
    fun incompleteConfigurationIsNotReady() {
        assertFalse(CaptureReadiness.configurationReady(false, "1.1.1.1", 1380, routes, routes))
        assertFalse(CaptureReadiness.configurationReady(true, "", 1380, routes, routes))
        assertFalse(CaptureReadiness.configurationReady(true, "1.1.1.1", 0, routes, routes))
        assertFalse(CaptureReadiness.configurationReady(true, "1.1.1.1", 1380, emptySet(), routes))
        assertTrue(CaptureReadiness.configurationReady(true, "1.1.1.1", 1380, routes, routes))
        assertFalse(
            CaptureReadiness.configurationReady(true, "1.1.1.1", 1380, routes, routes, 1280)
        )
        assertTrue(CaptureReadiness.configurationReady(true, "1.1.1.1", 1280, routes, routes, 1280))
    }

    private fun partial(generation: String = "12"): String =
        "router-authority current=Capture { capture_ready: true, ordinary_ready: false, capture_generation: Some($generation), session_generation: Some(1) }\n" +
            "capture-format generation=$generation representation=plain-ip flags=0x1001"

    @Test
    fun partialSamplesConvergeWithoutRequiringManagedReceipt() {
        assertNull(CaptureReadiness.partialReceipt("", "11"))
        assertNull(CaptureReadiness.partialReceipt(partial("10"), "11"))
        assertNull(CaptureReadiness.partialReceipt(partial("11"), "11"))
        assertNull(CaptureReadiness.partialReceipt(partial().substringBefore('\n'), "11"))
        assertNull(
            CaptureReadiness.partialReceipt(
                partial().replace("capture_ready: true", "capture_ready: false"),
                "11",
            )
        )
        assertNull(
            CaptureReadiness.partialReceipt(
                partial().replace("ordinary_ready: false", "ordinary_ready: true"),
                "11",
            )
        )
        val receipt = assertNotNull(CaptureReadiness.partialReceipt(partial(), "11"))
        assertEquals("12", receipt.generation)
        assertEquals("1", receipt.session)
    }

    @Test
    fun malformedPartialFormatStillFailsStrictly() {
        assertFails { CaptureReadiness.partialReceipt(partial("0"), null) }
        assertFails {
            CaptureReadiness.partialReceipt(partial().replace("Some(1)", "Some(0)"), null)
        }
        assertFails { CaptureReadiness.partialReceipt(partial().replace("plain-ip", "vnet"), null) }
        assertFails { CaptureReadiness.partialReceipt(partial().replace("0x1001", "0x5001"), null) }
        assertFails {
            CaptureReadiness.partialReceipt(partial().replace("0x1001", "0xinvalid"), null)
        }
    }

    @Test
    fun missingLostAndOlderReceiptsAreNotReady() {
        assertNull(sample(""))
        assertNull(sample(ready().replace("network=42", "network=41")))
        assertNull(sample(ready() + "\ncapture-lost network=42 interface=tun0 reason=gone"))
        assertNull(sample(ready("11")))
        assertNull(sample(ready("10")))
        assertNotNull(sample(ready()))
    }

    @Test
    fun staleConfigurationReceiptsAreNotReady() {
        assertNull(sample(ready().replace("owner_uid=Some(10181)", "owner_uid=Some(10180)")))
        assertNull(sample(ready().replace("mtu=Some(1380)", "mtu=Some(1280)")))
        assertNull(sample(ready().replace("10.0.2.2", "10.0.2.3")))
    }

    @Test
    fun malformedReadyDataStillFailsStrictly() {
        assertFails { sample(ready("invalid")) }
        assertFails { sample(ready("0")) }
        assertFails { sample(ready().replace("handle=99", "handle=0")) }
        assertFails { sample(ready(observed = "[]")) }
        assertFails { sample(ready().replace(encoded, "[malformed]")) }
    }

    // Exact Connected receipt retained from the first run-05 item-5 phone failure.
    private val actualRoutes =
        "[CaptureRoute { destination: CapturePrefix { address: 0.0.0.0, prefix_length: 0 }, gateway: None, interface_name: \"tun0\", route_type: Some(1) }, CaptureRoute { destination: CapturePrefix { address: 10.0.2.2, prefix_length: 32 }, gateway: None, interface_name: \"tun0\", route_type: Some(1) }, CaptureRoute { destination: CapturePrefix { address: 10.64.0.1, prefix_length: 32 }, gateway: None, interface_name: \"tun0\", route_type: Some(1) }, CaptureRoute { destination: CapturePrefix { address: 192.0.2.2, prefix_length: 32 }, gateway: None, interface_name: \"tun0\", route_type: Some(1) }, CaptureRoute { destination: CapturePrefix { address: ::, prefix_length: 0 }, gateway: None, interface_name: \"tun0\", route_type: Some(1) }, CaptureRoute { destination: CapturePrefix { address: 2001:db8::2, prefix_length: 128 }, gateway: None, interface_name: \"tun0\", route_type: Some(1) }, CaptureRoute { destination: CapturePrefix { address: fc00:bbbb:bbbb:bb01::1, prefix_length: 128 }, gateway: None, interface_name: \"tun0\", route_type: Some(1) }]"

    private fun actual(
        receiptRoutes: String = actualRoutes,
        format: String = "representation=plain-ip tun_flags=0x1001",
    ) =
        CaptureReadiness.receipt(
            "capture-ready generation=3 handle=789384712205 network=183 interface=tun0 requested_routes=$receiptRoutes observed_routes=$receiptRoutes api=37 owner_uid=Some(10181) mtu=Some(1280) route_types_reported=true $format",
            "tun0",
            "183",
            setOf(
                "0.0.0.0/0",
                "10.0.2.2/32",
                "10.64.0.1/32",
                "192.0.2.2/32",
                "::/0",
                "2001:db8::2/128",
                "fc00:bbbb:bbbb:bb01::1/128",
            ),
            1280,
            10181,
            null,
        ) {
            it
        }

    @Test
    fun realCaptureRouteReceiptIsAcceptedExactly() {
        val receipt = assertNotNull(actual())
        assertEquals("3", receipt.generation)
        assertEquals("789384712205", receipt.handle)
        assertNotNull(sample(ready().replace("Some(1)", "None")))
        assertNull(sample(ready().replace("interface_name: \"tun0\"", "interface_name: \"tun1\"")))
    }

    @Test
    fun malformedCaptureRouteRecordsAreRejectedEvenWhenBothCopiesMatch() {
        for (bad in
            listOf(
                actualRoutes.replace("gateway: None, ", ""),
                actualRoutes.replace("gateway: None", "gateway: invalid"),
                actualRoutes.replace("route_type: Some(1)", "route_type: Some(invalid)"),
                actualRoutes.replace("route_type: Some(1)", "route_type: Some(1), extra: true"),
                actualRoutes.replace("}, CaptureRoute", "} CaptureRoute"),
                actualRoutes + " trailing",
                "[CapturePrefix { address: 10.0.2.2, prefix_length: 32 }]",
            )) {
            assertFails { actual(bad) }
        }
    }

    @Test
    fun independentSamplesConvergeWithoutAcceptingStaleData() {
        val samples =
            listOf(
                "",
                ready("10"),
                ready("11"),
                ready() + "\ncapture-lost network=42 interface=tun0 reason=gone",
                ready(),
            )
        val accepted = samples.map { sample(it) }
        assertEquals(listOf(null, null, null, null), accepted.take(4))
        assertEquals("12", assertNotNull(accepted.last()).generation)
        assertEquals("99", accepted.last()?.handle)
    }

    @Test
    fun emptyPacketFormatFieldsCannotHideBesideAValidValue() {
        val valid = "representation=plain-ip flags=0x1001"
        for (bad in
            listOf(
                "flags= $valid",
                "$valid flags=",
                "representation= $valid",
                "$valid representation=",
                valid.replace("flags=0x1001", "flags="),
                valid.replace("representation=plain-ip", "representation="),
            )) {
            assertFails("Connected accepted $bad") {
                actual(format = bad.replace("flags=", "tun_flags="))
            }
            assertFails("Partial accepted $bad") {
                CaptureReadiness.partialReceipt(
                    partial().substringBeforeLast("representation=") + bad,
                    null,
                )
            }
        }
    }

    @Test
    fun bothReceiptSchemasRequireTheSameExactPacketFormat() {
        val valid = "representation=plain-ip flags=0x1001"
        for (format in listOf(valid, valid.replace("1001", "9001"))) {
            assertNotNull(actual(format = format.replace("flags=", "tun_flags=")))
            assertNotNull(
                CaptureReadiness.partialReceipt(
                    partial().substringBeforeLast("representation=") + format,
                    null,
                )
            )
        }
        for (bad in
            listOf(
                valid.replace("plain-ip", "vnet"),
                valid.replace("plain-ip", "plain-ip-extra"),
                valid.replace("0x1001", "0x5001"),
                valid.replace("0x1001", "0x1002"),
                valid.replace("0x1001", "0x0001"),
                valid.replace("0x1001", "0x1003"),
                valid.replace("representation=plain-ip ", ""),
                valid.substringBefore(" flags="),
                valid.replace("0x1001", "0xinvalid"),
                valid.replace("0x1001", "1001"),
                valid.replace("0x1001", "0x100000000"),
                valid.replace("representation=", "other_representation="),
                "$valid representation=plain-ip",
                "$valid flags=0x1001",
            )) {
            assertFails("Connected accepted $bad") {
                actual(format = bad.replace("flags=", "tun_flags="))
            }
            assertFails("Partial accepted $bad") {
                CaptureReadiness.partialReceipt(
                    partial().substringBeforeLast("representation=") + bad,
                    null,
                )
            }
        }
        // A stale sample stays pending, rather than turning convergence into corruption.
        assertNull(sample(ready("11").replace("plain-ip", "vnet")))
        assertNull(
            sample(
                ready()
                    .replace("owner_uid=Some(10181)", "owner_uid=Some(10180)")
                    .replace("plain-ip", "vnet")
            )
        )
    }
}
