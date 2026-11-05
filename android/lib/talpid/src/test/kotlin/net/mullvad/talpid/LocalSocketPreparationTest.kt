package net.mullvad.talpid

import android.net.Network
import android.os.ParcelFileDescriptor
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verifyOrder
import java.io.FileDescriptor
import java.io.IOException
import kotlin.test.assertEquals
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

class LocalSocketPreparationTest {
    @AfterEach fun cleanup() = unmockkAll()

    @Test
    fun `should protect before binding a duplicate and close only the duplicate`() {
        mockkStatic(ParcelFileDescriptor::class)
        val network = mockk<Network>(relaxed = true)
        val duplicate = mockk<ParcelFileDescriptor>(relaxed = true)
        val descriptor = FileDescriptor()
        every { ParcelFileDescriptor.fromFd(7) } returns duplicate
        every { duplicate.fileDescriptor } returns descriptor
        val protect = mockk<(Int) -> Boolean>()
        every { protect(7) } returns true
        assertEquals(
            LocalSocketPreparation.READY,
            LocalSocketPreparation.prepare(7, network, protect),
        )
        verifyOrder {
            protect(7)
            ParcelFileDescriptor.fromFd(7)
            network.bindSocket(descriptor)
            duplicate.close()
        }
    }

    @Test
    fun `should never bind on protect failure and report duplicate failure`() {
        val network = mockk<Network>()
        assertEquals(
            LocalSocketPreparation.PROTECT_FAILED,
            LocalSocketPreparation.prepare(7, network) { false },
        )
        mockkStatic(ParcelFileDescriptor::class)
        every { ParcelFileDescriptor.fromFd(7) } throws IOException()
        assertEquals(
            LocalSocketPreparation.BIND_FAILED,
            LocalSocketPreparation.prepare(7, network) { true },
        )
    }
}
