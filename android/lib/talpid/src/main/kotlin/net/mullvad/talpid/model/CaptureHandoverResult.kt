package net.mullvad.talpid.model

/**
 * Retention is attested only before Builder.establish is entered, never inferred from an error.
 * Success reports a borrowed descriptor number; JNI takes ownership only after decoding this
 * result.
 */
data class CaptureHandoverResult(
    val result: CreateTunResult,
    val predecessorRetained: Boolean,
)
