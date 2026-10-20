package net.mullvad.mullvadvpn.lib.grpc.mapper

import com.squareup.wire.GrpcException
import com.squareup.wire.GrpcStatus
import net.mullvad.mullvadvpn.lib.model.SetLocalNetworkAccessError

internal fun Throwable.toSetLocalNetworkAccessError(): SetLocalNetworkAccessError =
    when {
        this is GrpcException && grpcStatus == GrpcStatus.ABORTED ->
            SetLocalNetworkAccessError.Conflict
        this is GrpcException && grpcStatus == GrpcStatus.INVALID_ARGUMENT ->
            SetLocalNetworkAccessError.Invalid
        this is IllegalArgumentException -> SetLocalNetworkAccessError.Invalid
        else -> SetLocalNetworkAccessError.Unknown(this)
    }
