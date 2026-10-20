package net.mullvad.talpid

import android.Manifest.permission.ACCESS_BACKGROUND_LOCATION
import android.Manifest.permission.ACCESS_COARSE_LOCATION
import android.Manifest.permission.ACCESS_FINE_LOCATION
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.os.Process

internal data class LocalIdentityAccess(
    val local: Boolean,
    val fine: Boolean,
    val background: Boolean,
    val location: Boolean,
    val operations: Boolean,
) {
    val identity: Boolean
        get() = fine && background && location && operations
}

/** Own-UID permission facts; reading them never requests permission or scans for networks. */
internal class LocalIdentityAccessReader(private val context: Context) {
    private val appOps = context.getSystemService(AppOpsManager::class.java)

    fun read(): LocalIdentityAccess =
        LocalIdentityAccess(
            local =
                Build.VERSION.SDK_INT < LOCAL_PERMISSION_API ||
                    (granted(LOCAL_PERMISSION) &&
                        (AppOpsManager.permissionToOp(LOCAL_PERMISSION)?.let(::allowed) ?: true)),
            fine = granted(ACCESS_FINE_LOCATION) && granted(ACCESS_COARSE_LOCATION),
            background =
                Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
                    granted(ACCESS_BACKGROUND_LOCATION),
            location = context.getSystemService(LocationManager::class.java).isLocationEnabled,
            operations =
                allowed(AppOpsManager.OPSTR_FINE_LOCATION) &&
                    allowed(AppOpsManager.OPSTR_COARSE_LOCATION),
        )

    private fun granted(permission: String): Boolean =
        context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    @Suppress("DEPRECATION") // Raw own-UID query for API 28–35.
    private fun allowed(operation: String): Boolean =
        try {
            val mode =
                when {
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA ->
                        appOps.checkOpRawNoThrow(
                            operation,
                            Process.myUid(),
                            context.packageName,
                            null,
                        )
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
                        appOps.unsafeCheckOpRawNoThrow(
                            operation,
                            Process.myUid(),
                            context.packageName,
                        )
                    else -> appOps.checkOpNoThrow(operation, Process.myUid(), context.packageName)
                }
            mode == AppOpsManager.MODE_ALLOWED
        } catch (_: SecurityException) {
            false
        }

    companion object {
        const val LOCAL_PERMISSION_API = 37
        const val LOCAL_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
    }
}
