package net.mullvad.mullvadvpn.feature.lansharing.impl

import java.util.UUID
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule

/** Callbacks are supplied by the consumer; controls never access repositories or navigation. */
data class LocalPolicyActions(
    val onEnabled: (Boolean) -> Unit = {},
    val onEdit: (LocalBypassRule?) -> Unit = {},
    val onUpdate: ((LocalRuleDraft) -> LocalRuleDraft) -> Unit = {},
    val onSave: () -> Unit = {},
    val onClose: () -> Unit = {},
    val onDiscard: () -> Unit = {},
    val onKeep: () -> Unit = {},
    val onDelete: (UUID) -> Unit = {},
)
