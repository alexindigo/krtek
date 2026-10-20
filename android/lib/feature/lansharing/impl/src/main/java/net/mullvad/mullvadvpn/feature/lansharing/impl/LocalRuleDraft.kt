package net.mullvad.mullvadvpn.feature.lansharing.impl

import android.os.Parcelable
import java.util.UUID
import kotlinx.parcelize.Parcelize
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalCidrError
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SsidIdentity

/** A field is either editable text or an unchanged, non-text identity. */
@Parcelize
data class LocalWifiDraft(val text: String, val originalBytes: ByteArray? = null) : Parcelable {
    fun identity(): SsidIdentity? =
        originalBytes?.let(SsidIdentity::fromBytes) ?: SsidIdentity.fromUserText(text)

    override fun toString(): String = "LocalWifiDraft(redacted)"

    override fun equals(other: Any?): Boolean =
        other is LocalWifiDraft &&
            text == other.text &&
            (originalBytes?.contentEquals(other.originalBytes) ?: (other.originalBytes == null))

    override fun hashCode(): Int = text.hashCode() + (originalBytes?.contentHashCode() ?: 0)

    companion object {
        fun from(identity: SsidIdentity): LocalWifiDraft {
            val text = identity.displayText()
            return LocalWifiDraft(
                text,
                identity.bytes().takeUnless { SsidIdentity.fromUserText(text) == identity },
            )
        }
    }
}

@Parcelize
data class LocalRuleDraft(
    val id: String,
    val name: String = "",
    val enabled: Boolean = true,
    val addresses: String = "",
    val wifiNames: List<LocalWifiDraft> = emptyList(),
) : Parcelable {
    fun canonicalSuggestion(): String? =
        addresses.split(',').firstNotNullOfOrNull {
            (LocalCidr.parse(it.trim()).leftOrNull() as? LocalCidrError.Noncanonical)?.suggested
        }

    fun rule(): LocalBypassRule? {
        val parts = addresses.split(',').map(String::trim)
        val cidrs = parts.filter(String::isNotEmpty).map { LocalCidr.parse(it).getOrNull() }
        val identities = wifiNames.map { it.identity() }
        val invalidAddresses =
            parts.size > LocalNetworkAccess.MAX_CIDRS_PER_RULE ||
                (addresses.isNotBlank() && parts.any(String::isEmpty)) ||
                cidrs.any { it == null }
        if (invalidAddresses || identities.any { it == null }) return null
        val rule =
            LocalBypassRule(
                UUID.fromString(id),
                name,
                enabled,
                cidrs.filterNotNull(),
                identities.filterNotNull(),
            )
        return rule.takeIf { LocalNetworkAccess(rules = listOf(it)).validationError() == null }
    }

    override fun toString(): String = "LocalRuleDraft(redacted)"

    companion object {
        fun from(rule: LocalBypassRule): LocalRuleDraft =
            LocalRuleDraft(
                rule.id.toString(),
                rule.name,
                rule.enabled,
                rule.cidrs.joinToString(", "),
                rule.ssidIds.map(LocalWifiDraft::from),
            )
    }
}

@Parcelize
data class LocalEditorState(
    val draft: LocalRuleDraft? = null,
    val baseline: LocalRuleDraft? = null,
    val confirmDiscard: Boolean = false,
    val waitingForWifi: Boolean = false,
    val wifiMessage: Int? = null,
) : Parcelable {
    val dirty: Boolean
        get() = draft != null && draft != baseline

    override fun toString(): String = "LocalEditorState(dirty=$dirty)"
}
