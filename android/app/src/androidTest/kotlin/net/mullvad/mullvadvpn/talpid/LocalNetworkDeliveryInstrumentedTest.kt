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
import java.io.RandomAccessFile
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
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.mullvad.mullvadvpn.app.MullvadApplication
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi
import net.mullvad.mullvadvpn.lib.model.DisconnectReason
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.PackageName
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import net.mullvad.mullvadvpn.lib.model.TunnelState
import net.mullvad.mullvadvpn.lib.repository.ConnectionProxy
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import net.mullvad.mullvadvpn.lib.repository.SplitTunnelingRepository
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

    private var probeIndex = 0

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
            assertTrue(before.values.all { it.first }, "Guest runner must stage permissions")
            try {
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
                before.forEach { (key, _) ->
                    val (name, permission) = key
                    report(
                        "permission_after_${name}_$permission",
                        permissionState(name, permission),
                    )
                    if (permission == LOCAL_PERMISSION) report("grant_after_$name", grant(name))
                }
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
        expectedTunnel: String = args.getString("krtek_expect_tunnel", "Disconnected"),
    ): LocalNetworkStatus = runBlocking {
        val policy = checkNotNull(repository.settingsUpdates.value).localNetworkAccess
        val peerRuleIds =
            policy.rules
                .filter { it.enabled && it.cidrs.any { cidr -> cidr.toString() == "$peer/32" } }
                .map { it.id }
        if (ruleState != null) assertTrue(peerRuleIds.isNotEmpty(), "Expected enabled peer rule")
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
        if (forwarding == ForwardingAvailability.Active) {
            assertTrue(policy.enabled && policy.rules.any { it.enabled && it.cidrs.isNotEmpty() })
        }
        if (ruleState != null)
            assertTrue(
                peerRuleIds.all { id -> status.rules.any { it.id == id && it.state == ruleState } }
            )
        if (ruleState == LocalRuleState.Inactive(LocalRuleInactiveReason.ObserverUnavailable))
            assertTrue(status.rules.none { it.state == LocalRuleState.Forwarding })
        status
    }

    @Test fun consumerRunsAsAnotherApp() = withConsumer(null) { _, _, _ -> }

    private fun peerPolicy(
        enabled: Boolean = true,
        ruleEnabled: Boolean = true,
        cidr: String = "$peer/32",
        wifi: List<SsidIdentity> = emptyList(),
    ) =
        LocalNetworkAccess(
            enabled,
            listOf(
                LocalBypassRule(
                    UUID.randomUUID(),
                    "Krtek delivery fixture",
                    ruleEnabled,
                    listOf(checkNotNull(LocalCidr.parse(cidr).getOrNull())),
                    wifi,
                )
            ),
        )

    private fun withPolicy(
        repository: SettingsRepository,
        policy: LocalNetworkAccess,
        block: () -> Unit,
    ) = runBlocking {
        val original = checkNotNull(repository.settingsUpdates.value).localNetworkAccess
        try {
            assertTrue(repository.setLocalNetworkAccess(policy, original).isRight())
            withTimeout(10_000) {
                repository.settingsUpdates.first { it?.localNetworkAccess == policy }
            }
            block()
        } finally {
            val current = checkNotNull(repository.settingsUpdates.value).localNetworkAccess
            check(current == original || current == policy) { "Concurrent configuration retained" }
            if (current != original)
                assertTrue(repository.setLocalNetworkAccess(original, current).isRight())
            withTimeout(10_000) {
                repository.settingsUpdates.first { it?.localNetworkAccess == original }
            }
            report("policy_restored", true)
        }
    }

    private fun deliveryCase(
        policy: LocalNetworkAccess,
        forwarding: ForwardingAvailability,
        expect: String,
        ruleState: LocalRuleState? = null,
        transports: List<String> = listOf("tcp", "udp"),
    ) =
        withConsumer(null) { consumer, repository, connection ->
            withPolicy(repository, policy) {
                awaitState(repository, connection, forwarding, ruleState)
                transports.forEach { transport ->
                    consumer.identity()
                    appliedConfiguration(policy, forwarding)
                    probeSocket(consumer, transport, expect)
                }
            }
        }

    @Test
    fun approvedPeerAnswersTcpAndUdpWhileDisconnected() =
        deliveryCase(
            peerPolicy(),
            ForwardingAvailability.Active,
            "reply",
            LocalRuleState.Forwarding,
        )

    @Test
    fun unapprovedAddressStaysBlocked() =
        deliveryCase(
            peerPolicy(cidr = args.getString("krtek_unapproved_rule", "10.0.2.99/32")),
            ForwardingAvailability.Active,
            "blocked",
        )

    @Test
    fun disabledRuleStaysBlocked() =
        deliveryCase(peerPolicy(ruleEnabled = false), ForwardingAvailability.Off, "blocked")

    @Test
    fun policyOffStaysBlocked() =
        deliveryCase(peerPolicy(enabled = false), ForwardingAvailability.Off, "blocked")

    @Test
    fun publicAddressStaysBlocked() =
        deliveryCase(
            peerPolicy(),
            ForwardingAvailability.Active,
            "blocked",
            transports = listOf("tcp-connect"),
        )

    @Test
    fun announcedRuleWithUnmetConditionsIsDropped() =
        withConsumer(null) { consumer, repository, connection ->
            // Revocation kills this process. The guest runner owns staging and exact
            // restoration, with separate invocations around revoke and re-grant.
            val stage = args.getString("krtek_location_stage", "granted")
            check(stage in setOf("granted", "denied", "regranted"))
            val granted = stage != "denied"
            assertEquals("3", shell("settings get secure location_mode"))
            listOf(
                    "android.permission.ACCESS_COARSE_LOCATION",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_BACKGROUND_LOCATION",
                )
                .forEach { permission ->
                    val observed = permissionState(target.packageName, permission)
                    report("location_$permission", observed)
                    assertEquals(
                        granted,
                        observed.first,
                        "Location permissions must be staged externally",
                    )
                }
            report("location_stage", stage)
            val synthetic = checkNotNull(SsidIdentity.fromUserText("krtek-m3-different-wifi"))
            if (granted) {
                val known = runBlocking {
                    withTimeout(30_000) {
                            repository.localNetworkStatus.filterNotNull().first {
                                it.currentWifi is ConnectedWifi.Known
                            }
                        }
                        .currentWifi as ConnectedWifi.Known
                }
                assertNotEquals(known.ssid, synthetic)
                report("location_wifi", "Known")
            }
            val policy = peerPolicy(wifi = listOf(synthetic))
            withPolicy(repository, policy) {
                awaitState(
                    repository,
                    connection,
                    ForwardingAvailability.Active,
                    LocalRuleState.Inactive(
                        if (granted) LocalRuleInactiveReason.DifferentWifi
                        else LocalRuleInactiveReason.LocationPermissionMissing
                    ),
                )
                listOf("tcp", "udp").forEach { transport ->
                    consumer.identity()
                    appliedConfiguration(policy, ForwardingAvailability.Active)
                    probeSocket(consumer, transport, "blocked")
                }
            }
        }

    @Test
    fun connectDeliversAndDisconnectResumes() =
        withConsumer(null) { consumer, repository, connection ->
            val policy = peerPolicy()
            withPolicy(repository, policy) {
                try {
                    awaitState(
                        repository,
                        connection,
                        ForwardingAvailability.Active,
                        LocalRuleState.Forwarding,
                    )
                    appliedConfiguration(policy, ForwardingAvailability.Active)
                    runBlocking {
                        assertTrue(connection.connect().isRight())
                        withTimeout(60_000) {
                            connection.tunnelState.first { it is TunnelState.Connected }
                        }
                    }
                    report("cycle_tunnel", "Connected")
                    awaitState(
                        repository,
                        connection,
                        ForwardingAvailability.Active,
                        LocalRuleState.Forwarding,
                        "Connected",
                    )
                    listOf("tcp", "udp").forEach { transport ->
                        consumer.identity()
                        appliedConfiguration(policy, ForwardingAvailability.Active, "Connected")
                        probeSocket(consumer, transport, "reply")
                    }
                    probeExit(consumer, "mullvad")
                    probeIcmp(consumer, "echo")
                } finally {
                    runBlocking {
                        assertTrue(
                            connection
                                .disconnect(DisconnectReason.USER_INITIATED_DISCONNECT_BUTTON)
                                .isRight()
                        )
                        withTimeout(30_000) {
                            connection.tunnelState.first { it is TunnelState.Disconnected }
                        }
                    }
                    report("cycle_tunnel", "Disconnected")
                }
                awaitState(
                    repository,
                    connection,
                    ForwardingAvailability.Active,
                    LocalRuleState.Forwarding,
                )
                listOf("tcp", "udp").forEach { transport ->
                    consumer.identity()
                    appliedConfiguration(policy, ForwardingAvailability.Active)
                    probeSocket(consumer, transport, "reply")
                }
            }
        }

    @Test
    fun consumerProbe() {
        val transport = args.getString("krtek_probe_transport")
        val expect = args.getString("krtek_probe_expect")
        val state = args.getString("krtek_probe_forwarding")
        assumeTrue(transport != null && expect != null && state != null, "Probe arguments required")
        check(transport in setOf("tcp", "udp", "tcp-connect", "lookup", "exit-check", "icmp-check"))
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
            when (transport) {
                "lookup" ->
                    expect == "record" && forwarding != ForwardingAvailability.PausedWhileConnected
                "exit-check" -> expect in setOf("mullvad", "direct", "record")
                "icmp-check" -> expect in setOf("echo", "record", "blocked")
                else -> expect in setOf("reply", "connected", "blocked")
            }
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
            if (transport == "exit-check") {
                probeExit(consumer, checkNotNull(expect))
            } else if (transport == "icmp-check") {
                probeIcmp(consumer, checkNotNull(expect))
            } else if (transport == "lookup") {
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
                probeSocket(consumer, checkNotNull(transport), checkNotNull(expect))
            }
        }
    }

    private fun setPolicy(repository: SettingsRepository, policy: LocalNetworkAccess) =
        runBlocking {
            val current = checkNotNull(repository.settingsUpdates.value).localNetworkAccess
            val revision = checkNotNull(repository.localNetworkStatus.value).revision
            assertTrue(repository.setLocalNetworkAccess(policy, current).isRight())
            withTimeout(10_000) {
                repository.settingsUpdates.first { it?.localNetworkAccess == policy }
            }
            if (current != policy)
                withTimeout(30_000) {
                    repository.localNetworkStatus.filterNotNull().first { it.revision > revision }
                }
        }

    private fun disconnect(connection: ConnectionProxy) = runBlocking {
        assertTrue(
            connection.disconnect(DisconnectReason.USER_INITIATED_DISCONNECT_BUTTON).isRight()
        )
        withTimeout(60_000) { connection.tunnelState.first { it is TunnelState.Disconnected } }
        report("cycle_tunnel", "Disconnected")
    }

    private fun connectedCase(
        block: (Consumer, SettingsRepository, ConnectionProxy, LocalNetworkAccess) -> Unit
    ) =
        withConsumer(null) { consumer, repository, connection ->
            val original = checkNotNull(repository.settingsUpdates.value).localNetworkAccess
            val policy = peerPolicy()
            try {
                setPolicy(repository, policy)
                runBlocking {
                    assertTrue(connection.connect().isRight())
                    withTimeout(90_000) {
                        connection.tunnelState.first { it is TunnelState.Connected }
                    }
                }
                report("cycle_tunnel", "Connected")
                awaitState(
                    repository,
                    connection,
                    ForwardingAvailability.Active,
                    LocalRuleState.Forwarding,
                    "Connected",
                )
                block(consumer, repository, connection, policy)
            } finally {
                // Disconnect first so restoration never reconnects after instrumentation exits.
                disconnect(connection)
                setPolicy(repository, original)
                awaitState(
                    repository,
                    connection,
                    if (
                        original.enabled &&
                            original.rules.any { it.enabled && it.cidrs.isNotEmpty() }
                    )
                        ForwardingAvailability.Active
                    else ForwardingAvailability.Off,
                    null,
                    "Disconnected",
                )
                report("policy_restored", true)
            }
        }

    private fun connectedProof(
        consumer: Consumer,
        repository: SettingsRepository,
        connection: ConnectionProxy,
        previousGeneration: String? = null,
    ): AppliedCapture {
        val policy = checkNotNull(repository.settingsUpdates.value).localNetworkAccess
        awaitState(
            repository,
            connection,
            ForwardingAvailability.Active,
            LocalRuleState.Forwarding,
            "Connected",
        )
        consumer.identity()
        val config =
            appliedConfiguration(
                policy,
                ForwardingAvailability.Active,
                "Connected",
                previousGeneration,
            )
        listOf("tcp", "udp").forEach { probeSocket(consumer, it, "reply") }
        probeExit(consumer, "mullvad")
        return config
    }

    private fun nativeProof(
        consumer: Consumer,
        repository: SettingsRepository,
        connection: ConnectionProxy,
    ): AppliedCapture {
        val policy = checkNotNull(repository.settingsUpdates.value).localNetworkAccess
        awaitState(repository, connection, ForwardingAvailability.Off, null, "Connected")
        consumer.identity()
        val config = appliedConfiguration(policy, ForwardingAvailability.Off, "Connected")
        probeExit(consumer, "mullvad")
        return config
    }

    private fun normalConfiguration(
        native: AppliedCapture,
        managed: AppliedCapture,
        policy: LocalNetworkAccess,
    ) {
        assertEquals(native.addresses, managed.addresses, "Assigned addresses must match Native")
        assertEquals(native.dns, managed.dns, "Normal DNS must match Native")
        assertEquals(native.mtu, managed.mtu, "Normal MTU must match Native")
        val local =
            policy.rules
                .filter { policy.enabled && it.enabled }
                .flatMap { it.cidrs }
                .map { canonicalPrefix(it.toString()) }
                .toSet()
        assertEquals(
            native.routes + local,
            managed.routes,
            "Only announced local routes augment Native",
        )
        assertEquals(native.uids, managed.uids, "Normal app exclusions must match Native")
        report("normal_configuration_equal", true)
    }

    private fun withNativeControl(
        consumer: Consumer,
        repository: SettingsRepository,
        connection: ConnectionProxy,
        policy: LocalNetworkAccess,
    ): AppliedCapture {
        setPolicy(repository, policy.copy(enabled = false))
        val native = nativeProof(consumer, repository, connection)
        setPolicy(repository, policy)
        val managed = connectedProof(consumer, repository, connection)
        normalConfiguration(native, managed, policy)
        return managed
    }

    @Test
    fun approvedPeerAnswersWhileConnectedThroughMullvad() =
        connectedCase { consumer, repository, connection, policy ->
            withNativeControl(consumer, repository, connection, policy)
        }

    @Test
    fun unmetConnectedRuleDoesNotFallThroughToRelay() =
        connectedCase { consumer, repository, connection, policy ->
            val before = connectedProof(consumer, repository, connection)
            val known = runBlocking {
                withTimeout(30_000) {
                        repository.localNetworkStatus.filterNotNull().first {
                            it.currentWifi is ConnectedWifi.Known
                        }
                    }
                    .currentWifi as ConnectedWifi.Known
            }
            val different = checkNotNull(SsidIdentity.fromUserText("krtek-m3-different-wifi"))
            assertNotEquals(known.ssid, different)
            val unmet =
                policy.copy(rules = policy.rules.map { it.copy(ssidIds = listOf(different)) })
            setPolicy(repository, unmet)
            awaitState(
                repository,
                connection,
                ForwardingAvailability.Active,
                LocalRuleState.Inactive(LocalRuleInactiveReason.DifferentWifi),
                "Connected",
            )
            assertEquals(
                before,
                appliedConfiguration(unmet, ForwardingAvailability.Active, "Connected"),
                "Condition changes retain capture identity",
            )
            listOf("tcp", "udp").forEach { probeSocket(consumer, it, "blocked") }
            probeExit(consumer, "mullvad")
            setPolicy(repository, policy)
            assertEquals(
                before,
                connectedProof(consumer, repository, connection),
                "Recovery occurs before instrumentation restarts",
            )
            report("condition_identity_retained", true)
        }

    @Test
    fun connectedPolicyOffKeepsNativeVpnWorking() =
        connectedCase { consumer, repository, connection, policy ->
            connectedProof(consumer, repository, connection)
            withNativeControl(consumer, repository, connection, policy)
        }

    @Test
    fun lastEnabledDestinationSwitchesCaptureMode() =
        connectedCase { consumer, repository, connection, policy ->
            connectedProof(consumer, repository, connection)
            val disabled = policy.copy(rules = policy.rules.map { it.copy(enabled = false) })
            setPolicy(repository, disabled)
            val disabledNative = nativeProof(consumer, repository, connection)
            setPolicy(repository, policy)
            normalConfiguration(
                disabledNative,
                connectedProof(consumer, repository, connection),
                policy,
            )
            // Deleting the rule is the valid way to remove its last destination.
            setPolicy(repository, policy.copy(rules = emptyList()))
            val emptyNative = nativeProof(consumer, repository, connection)
            setPolicy(repository, policy)
            normalConfiguration(
                emptyNative,
                connectedProof(consumer, repository, connection),
                policy,
            )
            report("last_destination_controls", "disabled,deleted")
        }

    @Test
    fun disconnectRestoresPartialRoutesAndBlocking() =
        connectedCase { consumer, repository, connection, policy ->
            connectedProof(consumer, repository, connection)
            disconnect(connection)
            awaitState(
                repository,
                connection,
                ForwardingAvailability.Active,
                LocalRuleState.Forwarding,
                "Disconnected",
            )
            appliedConfiguration(policy, ForwardingAvailability.Active, "Disconnected")
            listOf("tcp", "udp").forEach { probeSocket(consumer, it, "reply") }
            probeSocket(consumer, "tcp-connect", "blocked")
        }

    @Test
    fun connectedConfigurationChangesReconcileBeforeDelivery() =
        connectedCase { consumer, repository, connection, policy ->
            val original = checkNotNull(repository.settingsUpdates.value)
            val split =
                (target.applicationContext as MullvadApplication)
                    .getKoin()
                    .get<SplitTunnelingRepository>()
            val excluded =
                PackageName(args.getString("krtek_exclusion_package", "com.android.deskclock"))
            val excludedUid = target.packageManager.getApplicationInfo(excluded.value, 0).uid
            assertNotEquals(target.applicationInfo.uid, excludedUid)
            assertNotEquals(
                target.packageManager.getApplicationInfo(testPackage, 0).uid,
                excludedUid,
            )
            assertTrue(PackageName(testPackage) !in original.splitTunnelSettings.excludedApps)
            assertTrue(excluded !in original.splitTunnelSettings.excludedApps)
            val before = connectedProof(consumer, repository, connection)
            try {
                val announced =
                    policy.copy(
                        rules =
                            policy.rules.map {
                                it.copy(
                                    cidrs =
                                        it.cidrs +
                                            checkNotNull(
                                                LocalCidr.parse("10.0.2.99/32").getOrNull()
                                            )
                                )
                            }
                    )
                setPolicy(repository, announced)
                val added = connectedProof(consumer, repository, connection, before.generation)
                assertNotEquals(before.generation, added.generation)
                assertEquals(before.routes + "10.0.2.99/32", added.routes)
                setPolicy(repository, policy)
                val restoredRoutes =
                    connectedProof(consumer, repository, connection, added.generation)
                assertEquals(before.routes, restoredRoutes.routes)

                runBlocking {
                    assertTrue(repository.setLocalNetworkSharing(!original.allowLan).isRight())
                }
                runBlocking {
                    withTimeout(10_000) {
                        repository.settingsUpdates.first { it?.allowLan == !original.allowLan }
                    }
                }
                val legacy =
                    connectedProof(consumer, repository, connection, restoredRoutes.generation)
                assertNotEquals(
                    restoredRoutes.routes,
                    legacy.routes,
                    "Legacy bypass changes the effective route set",
                )
                val legacyControl = withNativeControl(consumer, repository, connection, policy)
                assertEquals(legacy.routes, legacyControl.routes)
                runBlocking {
                    assertTrue(repository.setLocalNetworkSharing(original.allowLan).isRight())
                }
                runBlocking {
                    withTimeout(10_000) {
                        repository.settingsUpdates.first { it?.allowLan == original.allowLan }
                    }
                }
                val restoredLegacy =
                    connectedProof(consumer, repository, connection, legacyControl.generation)
                assertEquals(before.routes, restoredLegacy.routes)

                runBlocking {
                    assertTrue(split.excludeApp(excluded).isRight())
                    assertTrue(split.enableSplitTunneling(true).isRight())
                    withTimeout(10_000) {
                        repository.settingsUpdates.first {
                            it?.splitTunnelSettings?.let { settings ->
                                settings.enabled && excluded in settings.excludedApps
                            } == true
                        }
                    }
                }
                val exclusions =
                    connectedProof(consumer, repository, connection, restoredLegacy.generation)
                assertNotEquals(
                    restoredLegacy.uids,
                    exclusions.uids,
                    "Applied UID ranges must change",
                )
                assertTrue(
                    uidIncluded(
                        exclusions.uids,
                        target.packageManager.getApplicationInfo(testPackage, 0).uid,
                    )
                )
                assertTrue(!uidIncluded(exclusions.uids, excludedUid))
                report("excluded_uid", excludedUid)
                report("consumer_included", true)
                val exclusionControl = withNativeControl(consumer, repository, connection, policy)
                assertEquals(exclusions.uids, exclusionControl.uids)
            } finally {
                runBlocking {
                    assertTrue(split.includeApp(excluded).isRight())
                    assertTrue(
                        split.enableSplitTunneling(original.splitTunnelSettings.enabled).isRight()
                    )
                    assertTrue(repository.setLocalNetworkSharing(original.allowLan).isRight())
                    withTimeout(10_000) {
                        repository.settingsUpdates.first {
                            it?.allowLan == original.allowLan &&
                                it.splitTunnelSettings == original.splitTunnelSettings
                        }
                    }
                }
                setPolicy(repository, policy)
                val restored = connectedProof(consumer, repository, connection)
                assertEquals(before.routes, restored.routes)
                assertEquals(before.uids, restored.uids)
                report("settings_restored", true)
            }
        }

    @Test
    fun connectedRawRelayCarriesPublicIcmp() =
        connectedCase { consumer, repository, connection, policy ->
            setPolicy(repository, policy.copy(enabled = false))
            val native = nativeProof(consumer, repository, connection)
            probeIcmp(consumer, "echo")
            setPolicy(repository, policy)
            val managed = connectedProof(consumer, repository, connection)
            normalConfiguration(native, managed, policy)
            probeIcmp(consumer, "echo")
        }

    private data class AppliedCapture(
        val addresses: Set<String>,
        val routes: Set<String>,
        val dns: String,
        val mtu: Int,
        val uids: String,
        val generation: String?,
        val handle: String?,
        val interfaceName: String,
        val netId: String,
    )

    private fun uidIncluded(ranges: String, uid: Int): Boolean =
        ranges.split(',').any { range ->
            val bounds = range.trim().split('-').map { it.toInt() }
            uid >= bounds.first() && uid <= bounds.last()
        }

    private fun probeExit(consumer: Consumer, expect: String) {
        val result = consumer.request(Bundle().apply { putString("transport", "exit-check") })
        report("exit_outcome", checkNotNull(result.getString("outcome")))
        report("exit_elapsed_ms", result.getLong("elapsed_ms"))
        result.getString("error_kind")?.let { report("exit_error_kind", it) }
        result.getString("error_class")?.let { report("exit_error_class", it) }
        assertEquals(
            "exit-check",
            result.getString("outcome"),
            "Exit response, not harness failure",
        )
        assertEquals(200, result.getInt("http_status"))
        assertTrue(result.containsKey("mullvad_exit_ip"))
        val exit = result.getBoolean("mullvad_exit_ip")
        val ip = checkNotNull(result.getString("ip"))
        assertTrue(InetAddresses.isNumericAddress(ip))
        assertEquals(if (ip.contains(':')) 6 else 4, result.getInt("family"))
        report("exit_mullvad", exit)
        report("exit_ip", ip)
        report("exit_family", result.getInt("family"))
        if (expect != "record") assertEquals(expect == "mullvad", exit)
    }

    private fun probeIcmp(consumer: Consumer, expect: String) {
        val result = consumer.request(Bundle().apply { putString("transport", "icmp-check") })
        report("icmp_outcome", checkNotNull(result.getString("outcome")))
        report("icmp_elapsed_ms", result.getLong("elapsed_ms"))
        result.getString("error_class")?.let { report("icmp_error_class", it) }
        result.getString("error_reason")?.let { report("icmp_error_reason", it) }
        assertEquals(
            "icmp-check",
            result.getString("outcome"),
            "Parsed result, not harness failure",
        )
        assertEquals("icmp-dgram", result.getString("socket_kind"))
        assertEquals(2, result.getInt("attempted"))
        val nonce = checkNotNull(result.getByteArray("request_payload"))
        assertEquals(32, nonce.size)
        report("icmp_socket_uid", result.getInt("uid"))
        report("icmp_socket_kind", checkNotNull(result.getString("socket_kind")))
        report("icmp_request_payload", nonce.joinToString("") { "%02x".format(it) })
        val received = result.getInt("received")
        assertTrue(received in 0..2)
        assertEquals(received.toLong(), result.getLong("echo_replies"))
        var verified = 0
        for (sequence in 1..2) {
            result.getByteArray("reply_$sequence")?.let { reply ->
                assertContentEquals(nonce, reply, "Echo must carry this request's nonce")
                val packet = checkNotNull(result.getByteArray("packet_$sequence"))
                assertEquals(40, packet.size)
                assertEquals(0, packet[0].toInt())
                assertEquals(0, packet[1].toInt())
                assertEquals(
                    sequence,
                    (packet[6].toInt() and 255) * 256 + (packet[7].toInt() and 255),
                )
                assertContentEquals(nonce, packet.copyOfRange(8, packet.size))
                report("icmp_reply_$sequence", reply.joinToString("") { "%02x".format(it) })
                report("icmp_packet_$sequence", packet.joinToString("") { "%02x".format(it) })
                verified++
            }
            result
                .getInt("network_errno_$sequence")
                .takeIf { it != 0 }
                ?.let { report("icmp_errno_$sequence", it) }
        }
        assertEquals(received, verified)
        report("icmp_attempted", result.getInt("attempted"))
        report("icmp_transmitted", result.getInt("transmitted"))
        report("icmp_received", received)
        assertTrue(result.getInt("transmitted") in 0..2)
        if (received > 0 || expect == "echo") assertEquals(2, result.getInt("transmitted"))
        if (expect == "echo") assertTrue(received > 0, "Actual public ICMP echo replies required")
        if (expect == "blocked") assertEquals(0, received, "Public ICMP must remain blocked")
    }

    private fun probeSocket(consumer: Consumer, transport: String, expect: String) {
        val nonce = "krtek-m3-" + UUID.randomUUID()
        val index = probeIndex++
        if (transport != "tcp-connect")
            report(
                if (expect == "reply") "expect_hit_$index" else "expect_none_$index",
                "$transport:$nonce",
            )
        val destination =
            if (transport == "tcp-connect") args.getString("krtek_public", "1.1.1.1") else peer
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
        expectedTunnel: String = args.getString("krtek_expect_tunnel", "Disconnected"),
        previousGeneration: String? = null,
    ): AppliedCapture = runBlocking {
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
            while (isActive) {
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
                if (forwarding == ForwardingAvailability.Off && expectedTunnel == "Disconnected") {
                    if (vpn.contains("Active vpn type: -1") && agents.isEmpty()) {
                        report("frontend", "absent")
                        return@withTimeout AppliedCapture(
                            emptySet(),
                            emptySet(),
                            "[]",
                            0,
                            "",
                            null,
                            null,
                            "",
                            "",
                        )
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
                    if (expectedTunnel == "Connected" && iface != null && netId != null) {
                        assertTrue(!frontend, "Connected capture must use assigned addresses")
                        assertTrue(addresses.isNotEmpty() && dns.isNotEmpty())
                        val mtu = checkNotNull(tokenField(agent, "MTU: ")).toInt()
                        assertTrue(mtu >= 1280)
                        var identity: Pair<String, String>? = null
                        if (forwarding == ForwardingAvailability.Active) {
                            assertTrue(policy.enabled && expected.isNotEmpty())
                            assertTrue(allRoutes.containsAll(expected))
                            identity = captureReceipt(iface, netId, allRoutes, mtu)
                            if (identity.first == previousGeneration) {
                                delay(100)
                                continue
                            }
                            report("frontend", "present-managed")
                        } else {
                            assertEquals(ForwardingAvailability.Off, forwarding)
                            assertTrue(expected.isEmpty())
                            report("frontend", "native")
                        }
                        report("frontend_interface", iface)
                        report("frontend_net_id", netId)
                        report("frontend_routes", allRoutes.sorted().joinToString(","))
                        report("frontend_addresses", addresses.sorted().joinToString(","))
                        report("frontend_dns", dns)
                        report("frontend_mtu", mtu)
                        report("vpn_config", agent)
                        val uids = checkNotNull(delimitedField(agent, "Uids: <{", '}'))
                        report("frontend_uids", uids)
                        return@withTimeout AppliedCapture(
                            addresses,
                            allRoutes,
                            dns,
                            mtu,
                            uids,
                            identity?.first,
                            identity?.second,
                            iface,
                            netId,
                        )
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
                        return@withTimeout AppliedCapture(
                            addresses,
                            routes,
                            "[]",
                            1280,
                            "",
                            null,
                            null,
                            iface,
                            netId,
                        )
                    }
                }
                delay(500)
            }
            error("Configuration deadline")
        }
    }

    private fun captureReceipt(
        iface: String,
        netId: String,
        routes: Set<String>,
        mtu: Int,
    ): Pair<String, String> {
        val tail =
            RandomAccessFile(File(target.filesDir, "daemon.log"), "r").use { log ->
                val size = minOf(log.length(), 256 * 1024L).toInt()
                log.seek(log.length() - size)
                ByteArray(size).also { log.readFully(it) }.toString(Charsets.UTF_8)
            }
        val line =
            tail.lineSequence().last {
                (it.contains("capture-ready ") || it.contains("capture-lost ")) &&
                    it.contains(" network=$netId interface=$iface ")
            }
        assertTrue(line.contains("capture-ready "), "Current capture must not have been lost")
        val ready = line.substringAfter("capture-ready ")
        val generation =
            checkNotNull(tokenField(ready, "generation: ") ?: tokenField(ready, "generation="))
        val handle = checkNotNull(tokenField(ready, "handle="))
        assertTrue(generation.toULong() > 0uL && handle.toULong() > 0uL)
        assertTrue(ready.contains("owner_uid=Some(${target.applicationInfo.uid})"))
        assertTrue(ready.contains("mtu=Some($mtu)"))
        val requested =
            ready.substringAfter("requested_routes=").substringBefore(" observed_routes=")
        val observed = ready.substringAfter("observed_routes=").substringBefore(" api=")
        assertEquals(requested, observed, "Exact pushed route receipt, never a superset")
        val prefixes =
            Regex("""CapturePrefix \{ address: ([^,]+), prefix_length: ([0-9]+) \}""")
                .findAll(observed)
                .map { canonicalPrefix("${it.groupValues[1]}/${it.groupValues[2]}") }
                .toSet()
        assertEquals(routes, prefixes, "Capture-owned receipt must match current Android routes")
        report("capture_generation", generation)
        report("capture_handle", handle)
        report("capture_receipt", ready)
        return generation to handle
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
