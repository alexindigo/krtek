package net.mullvad.mullvadvpn.lib.grpc.mapper

import com.squareup.wire.GrpcException
import com.squareup.wire.GrpcStatus
import io.mockk.every
import io.mockk.mockk
import java.io.IOException
import kotlin.test.assertEquals
import net.mullvad.mullvadvpn.lib.model.SetLocalNetworkAccessError
import org.junit.jupiter.api.Test

class LocalNetworkAccessErrorMapperTest {
    @Test
    fun `should distinguish conflicts and invalid input from transport failures`() {
        val conflict = mockk<GrpcException> { every { grpcStatus } returns GrpcStatus.ABORTED }
        val invalid =
            mockk<GrpcException> { every { grpcStatus } returns GrpcStatus.INVALID_ARGUMENT }
        assertEquals(SetLocalNetworkAccessError.Conflict, conflict.toSetLocalNetworkAccessError())
        assertEquals(SetLocalNetworkAccessError.Invalid, invalid.toSetLocalNetworkAccessError())
        assertEquals(
            SetLocalNetworkAccessError.Invalid,
            IllegalArgumentException().toSetLocalNetworkAccessError(),
        )
        val transport = IOException("transport error")
        assertEquals(
            SetLocalNetworkAccessError.Unknown(transport),
            transport.toSetLocalNetworkAccessError(),
        )
    }
}
