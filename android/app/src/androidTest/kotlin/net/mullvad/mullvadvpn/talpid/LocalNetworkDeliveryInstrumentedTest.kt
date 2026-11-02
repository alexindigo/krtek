package net.mullvad.mullvadvpn.talpid

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.InetAddresses
import android.net.IpPrefix
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.mullvad.mullvadvpn.app.MullvadApplication
import net.mullvad.mullvadvpn.lib.model.DisconnectReason
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.TunnelState
import net.mullvad.mullvadvpn.lib.repository.ConnectionProxy
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.koin.android.ext.android.getKoin

/** Restart-safe observations and ordinary-app probes; consumerProbe never writes policy. */
class LocalNetworkDeliveryInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val target = instrumentation.targetContext
    private val testPackage = instrumentation.context.packageName
    private val args = InstrumentationRegistry.getArguments()
    private val peer
        get() = args.getString("krtek_peer", "10.0.2.2")

    private fun report(key: String, value: Any) {
        instrumentation.sendStatus(0, Bundle().apply { putString("krtek_$key", value.toString()) })
    }

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand("toybox timeout 5 $command").use {
            descriptor ->
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use {
                it.readBytes().toString(Charsets.UTF_8).trim()
            }
        }

    private fun grant(packageName: String, permission: String = LOCAL_PERMISSION): Boolean =
        target.packageManager.checkPermission(permission, packageName) ==
            PackageManager.PERMISSION_GRANTED

    private fun permissionState(packageName: String, permission: String): Pair<Boolean, String> {
        val line =
            shell("dumpsys package $packageName")
                .lineSequence()
                .map { it.trim() }
                .single {
                    it.startsWith("$permission: granted=")
                }
        return grant(packageName, permission) to
            (delimitedField(line, "flags=[", ']')?.trim() ?: "")
    }

    private fun withConsumer(
        expectation: ForwardingAvailability?,
        block: (Consumer, SettingsRepository, ConnectionProxy) -> Unit,
    ) {
        LocalNetworkEditorInstrumentedTest().withLocalAccessScreen {
            val koin = (target.applicationContext as MullvadApplication).getKoin()
            val repository = koin.get<SettingsRepository>()
            val connection = koin.get<ConnectionProxy>()
            runBlocking {
                withTimeout(30_000) { repository.settingsUpdates.filterNotNull().first() }
                val expectedTunnel = args.getString("krtek_expect_tunnel", "Disconnected")
                check(expectedTunnel in setOf("Disconnected", "Connected"))
                val initial = withTimeout(30_000) { connection.tunnelState.first() }
                report("initial_tunnel", initial.javaClass.simpleName)
                val autoConnected =
                    expectedTunnel == "Disconnected" &&
                        (initial is TunnelState.Connecting || initial is TunnelState.Connected)
                report("auto_connected", autoConnected)
                if (autoConnected)
                    assertTrue(
                        connection
                            .disconnect(DisconnectReason.USER_INITIATED_DISCONNECT_BUTTON)
                            .isRight()
                    )
                val tunnel =
                    withTimeout(if (expectedTunnel == "Connected") 60_000 else 30_000) {
                        connection.tunnelState.first {
                            if (expectedTunnel == "Connected") it is TunnelState.Connected
                            else it is TunnelState.Disconnected
                        }
                    }
                report("tunnel", tunnel.javaClass.simpleName)
            }
            val lockdown = args.getString("krtek_expect_lockdown", "1")
            check(lockdown in setOf("0", "1"))
            val alwaysOn = shell("settings get secure always_on_vpn_app")
            val observedLockdown = shell("settings get secure always_on_vpn_lockdown")
            report("always_on", alwaysOn)
            report("lockdown", observedLockdown)
            assertEquals(target.packageName, alwaysOn)
            assertEquals(lockdown, observedLockdown)
            val required =
                listOf(target.packageName to LOCAL_PERMISSION) +
                    LocalNetworkConsumerService.requiredPermissions().map { testPackage to it }
            val before = required.associateWith { (name, permission) ->
                permissionState(name, permission)
            }
            before.forEach { (key, value) ->
                val (name, permission) = key
                report("permission_before_${name}_$permission", value)
                if (permission == LOCAL_PERMISSION) report("grant_before_$name", value.first)
            }
            try {
                before
                    .filterValues { !it.first }
                    .forEach { (key, _) ->
                        val (name, permission) = key
                        instrumentation.uiAutomation.grantRuntimePermission(name, permission)
                    }
                before.keys.forEach { (name, permission) ->
                    assertTrue(grant(name, permission))
                    report("permission_granted_${name}_$permission", true)
                    if (permission == LOCAL_PERMISSION) report("grant_$name", true)
                }
                Consumer().use { consumer ->
                    consumer.identity()
                    val configured =
                        checkNotNull(repository.settingsUpdates.value).localNetworkAccess
                    val forwarding =
                        expectation
                            ?: if (
                                args.getString("krtek_expect_tunnel", "Disconnected") == "Connected"
                            )
                                ForwardingAvailability.PausedWhileConnected
                            else if (
                                configured.enabled &&
                                    configured.rules.any { it.enabled && it.cidrs.isNotEmpty() }
                            )
                                ForwardingAvailability.Active
                            else ForwardingAvailability.Off
                    // Answer r02: observe the daemon's consequence, not a fabricated target read.
                    awaitState(repository, connection, forwarding, null)
                    block(consumer, repository, connection)
                }
            } finally {
                var restoreError: Throwable? = null
                before.forEach { (key, value) ->
                    val (name, permission) = key
                    try {
                        if (!value.first)
                            instrumentation.uiAutomation.revokeRuntimePermission(
                                name,
                                permission,
                            )
                    } catch (error: Exception) {
                        if (restoreError == null) restoreError = error
                        else restoreError.addSuppressed(error)
                    } finally {
                        report(
                            "permission_after_${name}_$permission",
                            permissionState(name, permission),
                        )
                        if (permission == LOCAL_PERMISSION) report("grant_after_$name", grant(name))
                    }
                }
                restoreError?.let { throw it }
                assertEquals(
                    before,
                    before.keys.associateWith { (name, permission) ->
                        permissionState(name, permission)
                    },
                    "Restore every staged grant and preserve its permission flags",
                )
            }
        }
    }

    private fun awaitState(
        repository: SettingsRepository,
        connection: ConnectionProxy,
        forwarding: ForwardingAvailability,
        ruleState: LocalRuleState?,
    ): LocalNetworkStatus = runBlocking {
        val policy = checkNotNull(repository.settingsUpdates.value).localNetworkAccess
        val peerRuleIds =
            policy.rules
                .filter { it.enabled && it.cidrs.any { cidr -> cidr.toString() == "$peer/32" } }
                .map { it.id }
        if (ruleState != null) assertTrue(peerRuleIds.isNotEmpty(), "Expected enabled peer rule")
        val expectedTunnel = args.getString("krtek_expect_tunnel", "Disconnected")
        val status =
            withTimeout(30_000) {
                combine(connection.tunnelState, repository.localNetworkStatus.filterNotNull()) {
                        tunnel,
                        sample ->
                        tunnel to sample
                    }
                    .first { (tunnel, sample) ->
                        val tunnelMatches =
                            if (expectedTunnel == "Connected") tunnel is TunnelState.Connected
                            else tunnel is TunnelState.Disconnected
                        tunnelMatches &&
                            sample.forwarding == forwarding &&
                            (ruleState == null ||
                                peerRuleIds.all { id ->
                                    sample.rules.any { it.id == id && it.state == ruleState }
                                }) &&
                            (ruleState !=
                                LocalRuleState.Inactive(
                                    LocalRuleInactiveReason.ObserverUnavailable
                                ) || !sample.observerAvailable)
                    }
                    .second
            }
        report("forwarding", status.forwarding)
        report("observer_available", status.observerAvailable)
        report(
            "rule_state",
            status.rules.filter { it.id in peerRuleIds }.joinToString { it.state.toString() },
        )
        assertEquals(
            forwarding,
            status.forwarding,
            "Daemon reports forwarding $forwarding while $expectedTunnel",
        )
        if (expectedTunnel == "Connected")
            assertEquals(ForwardingAvailability.PausedWhileConnected, forwarding)
        if (ruleState != null)
            assertTrue(
                peerRuleIds.all { id -> status.rules.any { it.id == id && it.state == ruleState } }
            )
        if (ruleState == LocalRuleState.Inactive(LocalRuleInactiveReason.ObserverUnavailable))
            assertTrue(status.rules.none { it.state == LocalRuleState.Forwarding })
        status
    }

    @Test fun consumerRunsAsAnotherApp() = withConsumer(null) { _, _, _ -> }

    @Test
    fun consumerProbe() {
        val transport = args.getString("krtek_probe_transport")
        val expect = args.getString("krtek_probe_expect")
        val state = args.getString("krtek_probe_forwarding")
        assumeTrue(transport != null && expect != null && state != null, "Probe arguments required")
        check(transport in setOf("tcp", "udp", "tcp-connect", "lookup"))
        val forwarding = ForwardingAvailability.valueOf(checkNotNull(state))
        check(
            forwarding in
                setOf(
                    ForwardingAvailability.Active,
                    ForwardingAvailability.Off,
                    ForwardingAvailability.PausedWhileConnected,
                )
        )
        check(
            if (transport == "lookup")
                expect == "record" && forwarding != ForwardingAvailability.PausedWhileConnected
            else expect in setOf("reply", "connected", "blocked")
        )
        val explicitReason =
            args.getString("krtek_probe_rule_state")?.let {
                check(it in setOf("DifferentWifi", "ObserverUnavailable"))
                LocalRuleState.Inactive(LocalRuleInactiveReason.valueOf(it))
            }
        val ruleState =
            explicitReason
                ?: if (forwarding == ForwardingAvailability.Active && expect == "reply")
                    LocalRuleState.Forwarding
                else null
        withConsumer(forwarding) { consumer, repository, connection ->
            consumer.identity()
            awaitState(repository, connection, forwarding, ruleState)
            appliedConfiguration(
                checkNotNull(repository.settingsUpdates.value).localNetworkAccess,
                forwarding,
            )
            if (transport == "lookup") {
                val hostname = args.getString("krtek_lookup_host", "example.com")
                assertEquals("example.com", hostname)
                val result =
                    consumer.request(
                        Bundle().apply {
                            putString("transport", "lookup")
                            putString("hostname", hostname)
                        }
                    )
                assertEquals(
                    "lookup",
                    result.getString("outcome"),
                    "Lookup must complete, not a harness/IPC/deadline failure",
                )
                val outcome = result.getString("lookup_outcome")
                check(outcome == "resolved" || outcome == "failed")
                if (outcome == "resolved") assertTrue(result.getInt("address_count") > 0)
                else {
                    assertTrue(checkNotNull(result.getString("error_class")).contains('.'))
                    assertEquals(0, result.getInt("address_count"))
                }
                report("lookup_hostname", hostname)
                report("lookup_outcome", checkNotNull(outcome))
                report("lookup_address_count", result.getInt("address_count"))
                result.getString("error_class")?.let { report("lookup_error_class", it) }
                report("lookup_elapsed_ms", result.getLong("elapsed_ms"))
            } else {
                val nonce = "krtek-m3-" + UUID.randomUUID()
                if (transport != "tcp-connect")
                    report(
                        if (expect == "reply") "expect_hit_0" else "expect_none_0",
                        "$transport:$nonce",
                    )
                val destination =
                    if (transport == "tcp-connect") args.getString("krtek_public", "1.1.1.1")
                    else peer
                val port =
                    if (transport == "tcp-connect") 443
                    else
                        args
                            .getString(
                                if (transport == "tcp") "krtek_tcp_port" else "krtek_udp_port",
                                if (transport == "tcp") "18080" else "18081",
                            )
                            .toInt()
                val result =
                    consumer.request(
                        Bundle().apply {
                            putString("transport", transport)
                            putString("destination", destination)
                            putInt("port", port)
                            putString("nonce", nonce)
                            putInt("timeout_ms", 5_000)
                        }
                    )
                report("probe_transport", checkNotNull(transport))
                report("probe_outcome", checkNotNull(result.getString("outcome")))
                result.getString("error_class")?.let { report("probe_error_class", it) }
                result.getString("socket_report")?.let { report("socket_report", it) }
                assertEquals(
                    when (expect) {
                        "reply" -> "reply"
                        "connected" -> "connected"
                        else -> "failed"
                    },
                    result.getString("outcome"),
                )
                if (expect == "reply")
                    assertContentEquals(
                        nonce.toByteArray(Charsets.US_ASCII),
                        result.getByteArray("reply"),
                    )
                if (expect == "blocked")
                    assertTrue(checkNotNull(result.getString("error_class")).contains('.'))
            }
        }
    }

    private fun canonicalPrefix(text: String): String =
        IpPrefix(
                InetAddresses.parseNumericAddress(text.substringBefore('/')),
                text.substringAfter('/').toInt(),
            )
            .toString()

    // Dumpsys punctuation is literal, not a pattern in Android's ICU regex dialect.
    private fun delimitedField(text: String, marker: String, end: Char): String? {
        val markerStart = text.indexOf(marker)
        if (markerStart < 0) return null
        val start = markerStart + marker.length
        val finish = text.indexOf(end, start)
        if (finish < 0) return null
        return text.substring(start, finish)
    }

    private fun tokenField(text: String, marker: String): String? =
        delimitedField(text, marker, ' ')?.takeIf { it.isNotEmpty() }

    private fun appliedConfiguration(
        policy: LocalNetworkAccess,
        forwarding: ForwardingAvailability,
    ) = runBlocking {
        val expected =
            policy.rules
                .filter { policy.enabled && it.enabled }
                .flatMap { it.cidrs }
                .map { canonicalPrefix(it.toString()) }
                .toSet()
        val id = UUID.randomUUID().toString()
        val directory =
            File(target.filesDir, "krtek-probes").apply { check(isDirectory || mkdir()) }
        withTimeout(30_000) {
            while (true) {
                val vpn = shell("dumpsys vpn_management")
                val connectivity = shell("dumpsys connectivity")
                File(directory, "$id-vpn.txt").writeText(vpn)
                File(directory, "$id-connectivity.txt").writeText(connectivity)
                report("config_dump_id", id)
                check(vpn.contains("Active package name: ${target.packageName}"))
                // Vpn.dump does not print VpnConfig. Read the active VPN's actual
                // LinkProperties from ConnectivityService, not a physical network
                // or a historical route/configuration record.
                val agents =
                    connectivity
                        .lineSequence()
                        .filter {
                            it.contains("NetworkAgentInfo{") &&
                                tokenField(it, "Transports: ")?.split('|')?.contains("VPN") ==
                                    true &&
                                tokenField(it, "OwnerUid: ") ==
                                    target.applicationInfo.uid.toString()
                        }
                        .toList()
                val agent = agents.singleOrNull()
                val active = vpn.contains("Active vpn type: 1")
                if (forwarding == ForwardingAvailability.Off) {
                    if (vpn.contains("Active vpn type: -1") && agents.isEmpty()) {
                        report("frontend", "absent")
                        return@withTimeout
                    }
                } else if (active && agent != null) {
                    val addressText = checkNotNull(delimitedField(agent, "LinkAddresses: [", ']'))
                    val addresses =
                        addressText
                            .split(',')
                            .filter { it.isNotBlank() }
                            .map { canonicalPrefix(it.trim()) }
                            .toSet()
                    val bookkeeping =
                        setOf(canonicalPrefix("192.0.2.2/32"), canonicalPrefix("2001:db8::2/128"))
                    val frontend = addresses == bookkeeping
                    if (forwarding == ForwardingAvailability.PausedWhileConnected) {
                        assertTrue(!frontend, "Upstream tunnel, not local frontend, must own VPN")
                        report("frontend", "absent-upstream-tunnel")
                        report("vpn_config", agent)
                        return@withTimeout
                    }
                    val routeText = checkNotNull(delimitedField(agent, "Routes: [", ']'))
                    val dns = checkNotNull(delimitedField(agent, "DnsAddresses: [", ']')).trim()
                    val allRoutes =
                        routeText
                            .split(',')
                            .filter { it.isNotBlank() }
                            .map { canonicalPrefix(it.substringBefore(" ->").trim()) }
                            .toSet()
                    val routes = allRoutes - bookkeeping
                    val iface = tokenField(agent, "InterfaceName: ")
                    val netId =
                        delimitedField(agent, "network{", '}')?.takeIf { value ->
                            value.isNotEmpty() && value.all { it in '0'..'9' }
                        }
                    if (
                        frontend &&
                            routes == expected &&
                            dns.isEmpty() &&
                            iface != null &&
                            netId != null
                    ) {
                        assertTrue(routes.none { it.endsWith("/0") })
                        report("frontend", "present")
                        report("frontend_interface", iface)
                        report("frontend_net_id", netId)
                        report("frontend_routes", routes.sorted().joinToString(","))
                        report("frontend_dns", "[]")
                        report(
                            "frontend_bookkeeping_routes",
                            (allRoutes intersect bookkeeping).sorted().joinToString(","),
                        )
                        report("frontend_addresses", addresses.sorted().joinToString(","))
                        return@withTimeout
                    }
                }
                delay(500)
            }
        }
    }

    private inner class Consumer : AutoCloseable {
        private val service = CompletableFuture<Messenger>()
        @Volatile private var pending: Pair<String, CompletableFuture<Bundle>>? = null
        private val reply =
            Messenger(
                object : Handler(Looper.getMainLooper()) {
                    override fun handleMessage(message: Message) {
                        val result = Bundle(message.data)
                        pending
                            ?.takeIf { it.first == result.getString("request_id") }
                            ?.second
                            ?.complete(result)
                    }
                }
            )
        private val intent =
            Intent()
                .setComponent(
                    ComponentName(
                        instrumentation.context,
                        LocalNetworkConsumerService::class.java,
                    )
                )
        private val connection =
            object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    service.complete(Messenger(binder))
                }

                override fun onServiceDisconnected(name: ComponentName) {
                    pending
                        ?.second
                        ?.completeExceptionally(IllegalStateException("Consumer disconnected"))
                }
            }
        private val bound = target.bindService(intent, connection, Context.BIND_AUTO_CREATE)

        init {
            check(bound)
        }

        fun request(command: Bundle): Bundle {
            val id = UUID.randomUUID().toString()
            val result = CompletableFuture<Bundle>()
            pending = id to result
            try {
                command.putString("request_id", id)
                service
                    .get(10, TimeUnit.SECONDS)
                    .send(
                        Message.obtain().apply {
                            data = command
                            replyTo = reply
                        }
                    )
                return result.get(35, TimeUnit.SECONDS).also {
                    assertEquals(testPackage, it.getString("package"))
                    assertNotEquals(Process.myUid(), it.getInt("uid"))
                    LocalNetworkConsumerService.requiredPermissions().forEach { permission ->
                        val granted = it.getBoolean("permission_$permission")
                        report("consumer_permission_$permission", granted)
                        assertTrue(
                            granted,
                            "Consumer UID requires $permission before any network result",
                        )
                    }
                }
            } finally {
                pending = null
            }
        }

        fun identity() {
            val result = request(Bundle().apply { putString("transport", "identity") })
            assertEquals("identity", result.getString("outcome"))
            assertEquals("android.app.Application", result.getString("application_class"))
            assertEquals(
                target.packageManager.getApplicationInfo(testPackage, 0).uid,
                result.getInt("uid"),
            )
            assertEquals(target.applicationInfo.uid, Process.myUid())
            report("consumer_uid", result.getInt("uid"))
            report("consumer_package", checkNotNull(result.getString("package")))
            report("krtek_uid", Process.myUid())
        }

        override fun close() {
            if (bound) target.unbindService(connection)
            target.stopService(intent)
        }
    }

    private companion object {
        const val LOCAL_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
    }
}
