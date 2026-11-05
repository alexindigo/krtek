package net.mullvad.mullvadvpn.feature.lansharing.impl

import android.os.Build
import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import net.mullvad.mullvadvpn.lib.common.constant.LOCAL_NETWORK_PERMISSION_API

internal data class LocalPermissionGrants(
    val sdk: Int,
    val local: Boolean,
    val coarse: Boolean,
    val fine: Boolean,
    val background: Boolean,
    val location: Boolean,
) {
    val localFailure: LocalPermissionFailure?
        get() =
            if (sdk >= LOCAL_NETWORK_PERMISSION_API && !local) LocalPermissionFailure.LocalMissing
            else null

    val fineFailure: LocalPermissionFailure?
        get() =
            when {
                fine && coarse -> null
                coarse -> LocalPermissionFailure.ApproximateOnly
                else -> LocalPermissionFailure.FineDenied
            }

    val backgroundFailure: LocalPermissionFailure?
        get() =
            if (sdk >= Build.VERSION_CODES.Q && !background)
                LocalPermissionFailure.BackgroundMissing
            else null
}

internal enum class LocalPermissionStep {
    Idle,
    ExplainFine,
    Fine,
    ExplainBackground,
    ExplainBackgroundFallback,
    Background,
    AppSettings,
    LocationSettings,
    Local,
}

internal enum class LocalPermissionFailure {
    LocalMissing,
    FineDenied,
    ApproximateOnly,
    BackgroundMissing,
    LocationOff,
    SettingsUnavailable,
}

/** One explicit request owns its flight, including across rotation and cancellation. */
@Parcelize
internal data class LocalPermissionRequestState(
    val token: Long = 0,
    val wifi: Boolean = false,
    val active: Boolean = false,
    val step: LocalPermissionStep = LocalPermissionStep.Idle,
    val flight: LocalPermissionStep? = null,
    val flightToken: Long? = null,
    val leftForeground: Boolean = false,
    val failure: LocalPermissionFailure? = null,
) : Parcelable {
    fun begin(needsWifi: Boolean, grants: LocalPermissionGrants): LocalPermissionRequestState =
        if (active || flight != null) this
        else copy(token = token + 1, wifi = needsWifi, active = true, failure = null).next(grants)

    fun confirm(): LocalPermissionRequestState =
        when (step) {
            LocalPermissionStep.ExplainFine -> copy(step = LocalPermissionStep.Fine)
            LocalPermissionStep.ExplainBackground -> copy(step = LocalPermissionStep.Background)
            LocalPermissionStep.ExplainBackgroundFallback ->
                copy(step = LocalPermissionStep.AppSettings)
            else -> this
        }

    fun launched(actual: LocalPermissionStep = step): LocalPermissionRequestState =
        if (!active || flight != null) this
        else
            copy(
                step = LocalPermissionStep.Idle,
                flight = actual,
                flightToken = token,
                leftForeground = false,
            )

    fun foregroundLeft(requestToken: Long): LocalPermissionRequestState =
        if (
            active &&
                token == requestToken &&
                flightToken == requestToken &&
                flight == LocalPermissionStep.Background
        )
            copy(leftForeground = true)
        else this

    fun result(resultToken: Long, grants: LocalPermissionGrants): LocalPermissionRequestState {
        if (flightToken != resultToken) return this
        val drained = copy(flight = null, flightToken = null, leftForeground = false)
        return if (!active || token != resultToken) drained
        else {
            val denied = flightFailure(grants)
            when {
                denied == null -> drained.next(grants)
                flight == LocalPermissionStep.Background &&
                    grants.sdk >= Build.VERSION_CODES.R &&
                    !leftForeground ->
                    drained.copy(step = LocalPermissionStep.ExplainBackgroundFallback)
                else -> drained.finish(denied)
            }
        }
    }

    fun cancel(): LocalPermissionRequestState =
        copy(token = token + 1, active = false, step = LocalPermissionStep.Idle, failure = null)

    fun unavailable(): LocalPermissionRequestState =
        copy(flight = null, flightToken = null, leftForeground = false)
            .finish(LocalPermissionFailure.SettingsUnavailable)

    fun settings(): LocalPermissionRequestState =
        if (active || flight != null) this
        else
            copy(
                token = token + 1,
                active = true,
                failure = null,
                step =
                    if (failure == LocalPermissionFailure.LocationOff)
                        LocalPermissionStep.LocationSettings
                    else LocalPermissionStep.AppSettings,
            )

    private fun flightFailure(grants: LocalPermissionGrants): LocalPermissionFailure? =
        when (flight) {
            LocalPermissionStep.Fine -> grants.fineFailure
            LocalPermissionStep.Background -> grants.backgroundFailure
            LocalPermissionStep.AppSettings ->
                if (wifi) grants.fineFailure ?: grants.backgroundFailure else grants.localFailure
            LocalPermissionStep.LocationSettings ->
                if (!grants.location) LocalPermissionFailure.LocationOff else null
            LocalPermissionStep.Local -> grants.localFailure
            else -> null
        }

    private fun next(grants: LocalPermissionGrants): LocalPermissionRequestState =
        when {
            wifi && grants.fineFailure != null -> copy(step = LocalPermissionStep.ExplainFine)
            wifi && grants.backgroundFailure != null ->
                copy(step = LocalPermissionStep.ExplainBackground)
            wifi && !grants.location -> finish(LocalPermissionFailure.LocationOff)
            grants.localFailure != null -> copy(step = LocalPermissionStep.Local)
            else -> finish(null)
        }

    private fun finish(reason: LocalPermissionFailure?): LocalPermissionRequestState =
        copy(active = false, step = LocalPermissionStep.Idle, failure = reason)
}
