package net.mullvad.mullvadvpn.lib.model

import java.util.UUID

/** Configured policy only; missing observations never remove Wi-Fi conditions. */
data class LocalNetworkAccess(
    val enabled: Boolean = false,
    val rules: List<LocalBypassRule> = emptyList(),
) {
    fun validationError(): LocalPolicyValidationError? =
        when {
            rules.size > MAX_RULES -> LocalPolicyValidationError.TooManyRules
            rules.map { it.id }.distinct().size != rules.size ->
                LocalPolicyValidationError.DuplicateRuleId
            rules.any { it.name.codePointCount(0, it.name.length) > MAX_NAME_CHARACTERS } ->
                LocalPolicyValidationError.NameTooLong
            rules.any { it.cidrs.size > MAX_CIDRS_PER_RULE } ->
                LocalPolicyValidationError.TooManyCidrs
            rules.any { it.ssidIds.size > MAX_SSIDS_PER_RULE } ->
                LocalPolicyValidationError.TooManySsids
            rules.any { it.enabled && it.cidrs.isEmpty() } ->
                LocalPolicyValidationError.EmptyEnabledRule
            else -> null
        }

    override fun toString(): String =
        "LocalNetworkAccess(enabled=$enabled rule-count=${rules.size})"

    companion object {
        const val MAX_RULES = 64
        const val MAX_NAME_CHARACTERS = 64
        const val MAX_CIDRS_PER_RULE = 32
        const val MAX_SSIDS_PER_RULE = 16
    }
}

data class LocalBypassRule(
    val id: UUID,
    val name: String,
    val enabled: Boolean,
    val cidrs: List<LocalCidr>,
    val ssidIds: List<SsidIdentity> = emptyList(),
) {
    override fun toString(): String =
        "LocalBypassRule(id=$id enabled=$enabled cidr-count=${cidrs.size} ssid-count=${ssidIds.size})"
}

enum class LocalPolicyValidationError {
    DuplicateRuleId,
    EmptyEnabledRule,
    TooManyRules,
    TooManyCidrs,
    TooManySsids,
    NameTooLong,
}
