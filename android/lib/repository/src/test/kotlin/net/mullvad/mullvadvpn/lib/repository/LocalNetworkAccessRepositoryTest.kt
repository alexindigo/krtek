package net.mullvad.mullvadvpn.lib.repository

import arrow.core.left
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlin.test.assertEquals
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.grpc.ManagementService
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SetLocalNetworkAccessError
import org.junit.jupiter.api.Test

class LocalNetworkAccessRepositoryTest {
    @Test
    fun `should forward expected policy and retain typed command failures`() = runTest {
        val policy = LocalNetworkAccess(enabled = true)
        val expected = LocalNetworkAccess()
        val service =
            mockk<ManagementService> {
                every { settings } returns emptyFlow()
                coEvery { setLocalNetworkAccess(policy, expected) } returns
                    SetLocalNetworkAccessError.Conflict.left()
            }
        val repository = SettingsRepository(service, StandardTestDispatcher(testScheduler))
        assertEquals(
            SetLocalNetworkAccessError.Conflict.left(),
            repository.setLocalNetworkAccess(policy, expected),
        )
        coVerify(exactly = 1) { service.setLocalNetworkAccess(policy, expected) }
    }
}
