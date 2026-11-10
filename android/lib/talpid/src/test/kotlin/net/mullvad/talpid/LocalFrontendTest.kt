package net.mullvad.talpid

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import net.mullvad.talpid.model.CaptureHandoverResult
import net.mullvad.talpid.model.CaptureNetworkObservation
import net.mullvad.talpid.model.CaptureRoute
import net.mullvad.talpid.model.CreateTunResult
import net.mullvad.talpid.model.TunConfig
import org.junit.jupiter.api.Test

class LocalFrontendTest {
    @Test
    fun `should refuse both overlaps and retain revoked native ownership until finish`() {
        val owner = LocalFrontendOwnership()
        assertTrue(owner.tryUpstream())
        assertTrue(owner.tryUpstream())
        assertFalse(owner.tryFrontend(11))
        owner.upstreamClosed()
        assertTrue(owner.tryFrontend(11))
        assertFalse(owner.tryFrontend(12))
        assertFalse(owner.tryUpstream())
        assertTrue(owner.canPrepare)
        owner.revoke()
        assertTrue(owner.frontendActive)
        assertFalse(owner.canPrepare)
        owner.upstreamClosed()
        assertFalse(owner.tryUpstream())
        owner.frontendFinished(11)
        assertTrue(owner.tryFrontend(12))
        assertTrue(owner.canPrepare)
        owner.frontendFinished(12)
        assertTrue(owner.tryUpstream())
    }

    @Test
    fun `should preserve exact local routes and both interface families on replacement`() {
        for (routes in
            listOf(
                listOf("10.0.2.2/32"),
                listOf("fd42::/64"),
                listOf("169.254.0.0/16", "fe80::/10"),
            )) {
            val addresses = mutableListOf<Pair<String, Int>>()
            val announced = mutableListOf<String>()
            val config = assertNotNull(LocalFrontendConfig.parse(routes.toTypedArray()))
            config.configure(
                { address, bits -> addresses += address to bits },
                { announced += it.toString() },
            )
            assertEquals(routes, announced)
            assertEquals(listOf("192.0.2.2" to 32, "2001:db8::2" to 128), addresses)
        }
    }

    @Test
    fun `should retain one session with at most two exact cleanup epochs and never undo revocation`() {
        val owner = LocalFrontendOwnership()
        assertTrue(owner.tryFrontend(11))
        assertFalse(owner.tryHandover(10, 12))
        assertFalse(owner.tryHandover(11, 11))
        assertTrue(owner.tryHandover(11, 12))
        assertTrue(owner.predecessorCurrent(11))
        assertFalse(owner.tryHandover(11, 13))
        owner.establishing(12)
        assertFalse(owner.predecessorCurrent(11))
        owner.frontendFinished(11)
        owner.frontendFinished(11)
        assertTrue(owner.predecessorCurrent(12))
        assertFalse(owner.tryUpstream())
        assertTrue(owner.tryHandover(12, 13))
        owner.revoke()
        owner.frontendFinished(13)
        assertFalse(owner.canPrepare)
        assertFalse(owner.tryHandover(12, 14))
        assertTrue(owner.frontendActive)
        owner.frontendFinished(12)
        assertTrue(owner.tryUpstream())
    }

    @Test
    fun `should match Rust local scope boundaries and numeric canonical contract`() {
        for (route in
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
            assertNotNull(LocalFrontendConfig.parse(arrayOf(route)), route)
        }
        for (route in
            listOf(
                "0.0.0.0/0",
                "10.0.0.0/7",
                "172.0.0.0/8",
                "192.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.1/32",
                "203.0.113.0/24",
                "224.0.0.0/4",
                "255.255.255.255/32",
                "::/0",
                "::1/128",
                "2001:db8::/32",
                "ff02::/16",
                "localhost/32",
                "10.0.2.2/24",
                "10.01.0.0/16",
                "fe80::1%wlan0/128",
                "10.0.0.0/-1",
                "10.0.0.0/33",
            )) {
            assertNull(LocalFrontendConfig.parse(arrayOf(route)), route)
        }
        assertNull(LocalFrontendConfig.parse(emptyArray()))
        assertNull(LocalFrontendConfig.parse(arrayOf("10.0.0.0/8", "::/0")))
    }

    @Test
    fun `should retain exact frontend JNI signatures`() {
        for (getter in listOf("getOwnerUid", "getMtu")) {
            assertEquals(
                Int::class.javaObjectType,
                CaptureNetworkObservation::class.java.getDeclaredMethod(getter).returnType,
            )
        }
        assertEquals(
            Int::class.javaObjectType,
            CaptureRoute::class.java.getDeclaredMethod("getRouteType").returnType,
        )
        assertEquals(
            Int::class.javaPrimitiveType,
            CaptureNetworkObservation::class.java.getDeclaredMethod("getApiLevel").returnType,
        )
        val type = TalpidVpnService::class.java
        assertEquals(
            Int::class.javaPrimitiveType,
            type
                .getDeclaredMethod("takeLocalFrontendDescriptor", Long::class.javaPrimitiveType)
                .returnType,
        )
        assertEquals(
            CreateTunResult::class.java,
            type
                .getDeclaredMethod(
                    "openLocalFrontend",
                    Long::class.javaPrimitiveType,
                    Array<String>::class.java,
                    Array<String>::class.java,
                )
                .returnType,
        )
        assertEquals(
            Void.TYPE,
            type.getDeclaredMethod("finishLocalFrontend", Long::class.javaPrimitiveType).returnType,
        )
        for ((name, configType) in
            listOf(
                "handoverLocalFrontend" to Array<String>::class.java,
                "handoverSecuredFrontend" to TunConfig::class.java,
            )) {
            assertEquals(
                CaptureHandoverResult::class.java,
                type
                    .getDeclaredMethod(
                        name,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        configType,
                        *if (name == "handoverLocalFrontend") arrayOf(Array<String>::class.java)
                        else emptyArray(),
                    )
                    .returnType,
            )
        }
        assertEquals(
            CreateTunResult::class.java,
            CaptureHandoverResult::class.java.getDeclaredMethod("getResult").returnType,
        )
        assertEquals(
            Boolean::class.javaPrimitiveType,
            CaptureHandoverResult::class
                .java
                .getDeclaredMethod("getPredecessorRetained")
                .returnType,
        )
        assertEquals(
            CreateTunResult::class.java,
            type
                .getDeclaredMethod(
                    "openSecuredFrontend",
                    Long::class.javaPrimitiveType,
                    TunConfig::class.java,
                )
                .returnType,
        )
        assertEquals(
            Boolean::class.javaPrimitiveType,
            type
                .getDeclaredMethod(
                    "bindLocalFrontend",
                    Long::class.javaPrimitiveType,
                    String::class.java,
                )
                .returnType,
        )
        for (name in listOf("attachCaptureNetwork", "detachCaptureNetwork")) {
            assertEquals(
                Boolean::class.javaPrimitiveType,
                type.getDeclaredMethod(name, Long::class.javaPrimitiveType).returnType,
            )
        }
        val publication =
            LocalCaptureNetworkBridge::class
                .java
                .getDeclaredMethod(
                    "published",
                    Long::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType,
                    CaptureNetworkObservation::class.java,
                )
        assertEquals(Void.TYPE, publication.returnType)
        assertTrue(java.lang.reflect.Modifier.isNative(publication.modifiers))
        assertTrue(java.lang.reflect.Modifier.isStatic(publication.modifiers))
        assertEquals(
            Boolean::class.javaPrimitiveType,
            type.getDeclaredMethod("isLocalFrontendActive").returnType,
        )
        assertEquals(
            Int::class.javaPrimitiveType,
            type
                .getDeclaredMethod(
                    "prepareLocalSocket",
                    Int::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType,
                    Boolean::class.javaPrimitiveType,
                )
                .returnType,
        )
    }
}
