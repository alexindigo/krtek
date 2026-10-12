@file:JvmName("ProblemReportRepositoryKt")

package net.mullvad.mullvadvpn.lib.repository

import android.content.Context
import java.io.File
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import net.mullvad.mullvadvpn.lib.payment.model.PaymentStatus

const val PROBLEM_REPORT_LOGS_FILE = "problem_report.txt"

class ProblemReportRepository(
    context: Context,
    kermitFileLogDirName: String,
    private val paymentLogic: PaymentLogic,
    val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    init {
        System.loadLibrary("mullvad_jni")
    }

    private val logDirectory = File(context.filesDir.toURI())
    private val problemReportOutputPath = File(logDirectory, PROBLEM_REPORT_LOGS_FILE)
    private val kermitFileLogDirPath = File(logDirectory, kermitFileLogDirName)
    private val collectReportMutex = Mutex()

    suspend fun collectLogs(): Boolean =
        withContext(dispatcher) {

            // Lock to avoid potential truncation of the log file that the daemon creates
            collectReportMutex.withLock {
                // Delete any old report
                deleteLogs()

                val availableProducts = paymentLogic.allAvailableProducts()

                collectReport(
                    logDirectory = logDirectory.absolutePath,
                    kermitFileLogDir = kermitFileLogDirPath.absolutePath,
                    problemReportOutputPath = problemReportOutputPath.absolutePath,
                    unverifiedPurchases =
                        availableProducts?.count { it.status == PaymentStatus.PURCHASED_UNVERIFIED }
                            ?: 0,
                    pendingPurchases =
                        availableProducts?.count { it.status == PaymentStatus.PENDING } ?: 0,
                )
            }
        }

    suspend fun readLogs(): List<String> {
        if (!logsExists()) {
            collectLogs()
        }

        return if (logsExists()) {
            problemReportOutputPath.readLines()
        } else {
            listOf("Failed to collect logs for problem report")
        }
    }

    private fun logsExists() = problemReportOutputPath.exists()

    fun deleteLogs() {
        problemReportOutputPath.delete()
    }

    // TODO We should remove the external functions from this class and migrate it to the service
    private external fun collectReport(
        logDirectory: String,
        kermitFileLogDir: String,
        problemReportOutputPath: String,
        unverifiedPurchases: Int,
        pendingPurchases: Int,
    ): Boolean
}
