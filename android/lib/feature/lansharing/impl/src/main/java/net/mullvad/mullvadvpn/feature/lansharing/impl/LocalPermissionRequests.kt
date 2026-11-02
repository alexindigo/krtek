package net.mullvad.mullvadvpn.feature.lansharing.impl

import android.Manifest.permission.ACCESS_BACKGROUND_LOCATION
import android.Manifest.permission.ACCESS_COARSE_LOCATION
import android.Manifest.permission.ACCESS_FINE_LOCATION
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import net.mullvad.mullvadvpn.lib.common.constant.LOCAL_NETWORK_PERMISSION
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryTextButton

/** Android prompts are effects of user intent; they never change or remove a rule. */
@Composable
internal fun localPermissionRequester(): (Boolean) -> Unit {
    val context = LocalContext.current
    val activity = LocalActivity.current as ComponentActivity
    var state by rememberSaveable { mutableStateOf(LocalPermissionRequestState()) }
    DisposableEffect(activity) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_PAUSE) {
                state.flightToken?.let { state = state.foregroundLeft(it) }
            }
        }
        activity.lifecycle.addObserver(observer)
        onDispose { activity.lifecycle.removeObserver(observer) }
    }
    fun result() {
        state.flightToken?.let { state = state.result(it, context.localGrants()) }
    }
    val multiple =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
            result()
        }
    val single =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { result() }
    val settings =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            result()
        }
    val launch: (LocalPermissionStep) -> Unit = { step ->
        when (step) {
            LocalPermissionStep.Fine ->
                multiple.launch(arrayOf(ACCESS_COARSE_LOCATION, ACCESS_FINE_LOCATION))
            LocalPermissionStep.Background ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                    single.launch(ACCESS_BACKGROUND_LOCATION)
            LocalPermissionStep.Local -> single.launch(LOCAL_NETWORK_PERMISSION)
            LocalPermissionStep.AppSettings ->
                settings.launch(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                        .setData(Uri.fromParts("package", context.packageName, null))
                )
            LocalPermissionStep.LocationSettings ->
                settings.launch(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
            else -> Unit
        }
    }
    LocalPermissionLaunch(state, { state = it }, launch)
    LocalPermissionExplanation(state.step, { state = state.confirm() }, { state = state.cancel() })
    state.failure?.let { failure ->
        LocalPermissionRecovery(
            failure,
            { state = state.settings() },
            { state = state.begin(state.wifi, context.localGrants()) },
            { state = state.cancel() },
        )
    }
    return { state = state.begin(it, context.localGrants()) }
}

@Composable
private fun LocalPermissionLaunch(
    state: LocalPermissionRequestState,
    onState: (LocalPermissionRequestState) -> Unit,
    launch: (LocalPermissionStep) -> Unit,
) {
    LaunchedEffect(state.token, state.step) {
        if (
            state.step == LocalPermissionStep.Idle ||
                state.step == LocalPermissionStep.ExplainFine ||
                state.step == LocalPermissionStep.ExplainBackground ||
                state.step == LocalPermissionStep.ExplainBackgroundFallback
        )
            return@LaunchedEffect
        val actual = state.step
        val requested = state.launched(actual)
        onState(requested)
        if (requested.flight == actual) {
            try {
                launch(actual)
            } catch (_: ActivityNotFoundException) {
                onState(requested.unavailable())
            } catch (_: SecurityException) {
                onState(requested.unavailable())
            }
        }
    }
}

private fun Context.localGrants(): LocalPermissionGrants {
    fun granted(permission: String) =
        checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
    return LocalPermissionGrants(
        Build.VERSION.SDK_INT,
        granted(LOCAL_NETWORK_PERMISSION),
        granted(ACCESS_COARSE_LOCATION),
        granted(ACCESS_FINE_LOCATION),
        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || granted(ACCESS_BACKGROUND_LOCATION),
        getSystemService(LocationManager::class.java).isLocationEnabled,
    )
}

@Composable
private fun LocalPermissionExplanation(
    step: LocalPermissionStep,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
) {
    step.explanation(Build.VERSION.SDK_INT)?.let { (title, help, action) ->
        AlertDialog(
            onDismissRequest = onCancel,
            title = { Text(stringResource(title)) },
            text = { Text(stringResource(help, stringResource(R.string.app_name))) },
            confirmButton = {
                PrimaryTextButton(
                    onClick = onConfirm,
                    text = stringResource(action),
                )
            },
            dismissButton = {
                PrimaryTextButton(
                    onClick = onCancel,
                    text = stringResource(android.R.string.cancel),
                )
            },
        )
    }
}

internal data class LocalPermissionExplanationContent(
    val title: Int,
    val help: Int,
    val action: Int,
)

internal fun LocalPermissionStep.explanation(sdk: Int): LocalPermissionExplanationContent? =
    when (this) {
        LocalPermissionStep.ExplainFine ->
            LocalPermissionExplanationContent(
                R.string.local_access_fine_title,
                R.string.local_access_fine_help,
                R.string.local_access_request_location,
            )
        LocalPermissionStep.ExplainBackground ->
            LocalPermissionExplanationContent(
                R.string.local_access_background_title,
                if (sdk >= Build.VERSION_CODES.R) R.string.local_access_background_help
                else R.string.local_access_background_dialog_help,
                if (sdk >= Build.VERSION_CODES.R) R.string.local_access_location_permission
                else R.string.local_access_request_location,
            )
        LocalPermissionStep.ExplainBackgroundFallback ->
            LocalPermissionExplanationContent(
                R.string.local_access_background_title,
                R.string.local_access_background_settings_help,
                R.string.local_access_app_settings,
            )
        else -> null
    }

@Composable
private fun LocalPermissionRecovery(
    failure: LocalPermissionFailure,
    onSettings: () -> Unit,
    onRetry: () -> Unit,
    onCancel: () -> Unit,
) {
    val message =
        when (failure) {
            LocalPermissionFailure.LocalMissing -> R.string.local_access_local_missing
            LocalPermissionFailure.FineDenied -> R.string.local_access_fine_missing
            LocalPermissionFailure.ApproximateOnly -> R.string.local_access_approximate
            LocalPermissionFailure.BackgroundMissing ->
                R.string.local_access_background_settings_help
            LocalPermissionFailure.LocationOff -> R.string.local_access_location_off
            LocalPermissionFailure.SettingsUnavailable -> R.string.local_access_settings_unavailable
        }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.local_access_title)) },
        text = { Text(stringResource(message, stringResource(R.string.app_name))) },
        confirmButton = {
            PrimaryTextButton(
                onClick = onSettings,
                text =
                    stringResource(
                        if (failure == LocalPermissionFailure.LocationOff)
                            R.string.local_access_location_settings
                        else R.string.local_access_app_settings
                    ),
            )
        },
        dismissButton = {
            PrimaryTextButton(onClick = onRetry, text = stringResource(R.string.local_access_retry))
        },
    )
}
