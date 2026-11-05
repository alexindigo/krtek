package net.mullvad.talpid

import android.net.Network
import android.os.ParcelFileDescriptor
import java.io.IOException

/** Integer ABI shared with talpid-tunnel's JNI seam. Originals always remain native-owned. */
internal object LocalSocketPreparation {
    const val READY = 0
    const val STALE = 1
    const val PROTECT_FAILED = 2
    const val BIND_FAILED = 3
    const val INACTIVE = 4

    fun prepare(fd: Int, network: Network, protect: (Int) -> Boolean): Int {
        if (!protect(fd)) return PROTECT_FAILED
        return try {
            ParcelFileDescriptor.fromFd(fd).use { network.bindSocket(it.fileDescriptor) }
            READY
        } catch (_: IOException) {
            BIND_FAILED
        } catch (_: RuntimeException) {
            BIND_FAILED
        }
    }
}
