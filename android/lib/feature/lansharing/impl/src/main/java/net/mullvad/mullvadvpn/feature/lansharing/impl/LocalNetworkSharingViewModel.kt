package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.WhileSubscribed
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.lib.common.Lc
import net.mullvad.mullvadvpn.lib.common.constant.VIEW_MODEL_STOP_TIMEOUT
import net.mullvad.mullvadvpn.lib.common.toLc
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SetLocalNetworkAccessError
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository

class LocalNetworkSharingViewModel(
    private val isModal: Boolean,
    private val settingsRepository: SettingsRepository,
    private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val editor = savedStateHandle.getStateFlow("local-rule-editor", LocalEditorState())
    private val saving = MutableStateFlow(false)
    private val error = MutableStateFlow<Int?>(null)

    val uiState =
        combine(
                settingsRepository.settingsUpdates.filterNotNull(),
                settingsRepository.localNetworkStatus,
                editor,
                saving,
                error,
            ) { settings, status, edit, busy, failure ->
                LocalNetworkSharingUiState(
                        lanSharingEnabled = settings.allowLan,
                        isModal = isModal,
                        policy = settings.localNetworkAccess,
                        status = status,
                        editor = edit,
                        saving = busy,
                        error = failure,
                    )
                    .toLc<Boolean, LocalNetworkSharingUiState>()
            }
            .stateIn(
                scope = viewModelScope,
                started = SharingStarted.WhileSubscribed(VIEW_MODEL_STOP_TIMEOUT),
                initialValue = Lc.Loading(isModal),
            )

    fun setLocalNetworkSharingEnabled(enable: Boolean) {
        viewModelScope.launch { settingsRepository.setLocalNetworkSharing(enable) }
    }

    fun edit(rule: LocalBypassRule?) {
        if (saving.value || editor.value.draft != null) return
        val draft = rule?.let(LocalRuleDraft::from) ?: LocalRuleDraft(UUID.randomUUID().toString())
        setEditor(LocalEditorState(draft, draft))
        error.value = null
    }

    fun updateDraft(update: (LocalRuleDraft) -> LocalRuleDraft) {
        if (saving.value) return
        editor.value.draft?.let { setEditor(editor.value.copy(draft = update(it))) }
        error.value = null
    }

    fun closeEditor() {
        if (!saving.value) {
            setEditor(
                if (editor.value.dirty) editor.value.copy(confirmDiscard = true)
                else LocalEditorState()
            )
            error.value = null
        }
    }

    fun discard() = setEditor(LocalEditorState())

    fun keepEditing() = setEditor(editor.value.copy(confirmDiscard = false))

    fun save() {
        val rule = editor.value.draft?.rule()
        if (rule == null) {
            error.value = R.string.local_access_invalid_rule
            return
        }
        changePolicy(closeEditor = true) { current ->
            current.copy(
                rules =
                    if (current.rules.any { it.id == rule.id })
                        current.rules.map { if (it.id == rule.id) rule else it }
                    else current.rules + rule
            )
        }
    }

    fun setPolicyEnabled(enabled: Boolean) = changePolicy { it.copy(enabled = enabled) }

    fun delete(id: UUID) = changePolicy {
        it.copy(rules = it.rules.filterNot { rule -> rule.id == id })
    }

    private fun changePolicy(
        closeEditor: Boolean = false,
        update: (LocalNetworkAccess) -> LocalNetworkAccess,
    ) {
        val current = settingsRepository.settingsUpdates.value?.localNetworkAccess
        if (saving.value || current == null) return
        val replacement = update(current)
        if (replacement.validationError() != null) {
            error.value = R.string.local_access_invalid_rule
            return
        }
        saving.value = true
        error.value = null
        viewModelScope.launch {
            try {
                settingsRepository
                    .setLocalNetworkAccess(replacement, expected = current)
                    .fold(
                        { error.value = it.message() },
                        { if (closeEditor) setEditor(LocalEditorState()) },
                    )
            } finally {
                saving.value = false
            }
        }
    }

    private fun setEditor(value: LocalEditorState) {
        savedStateHandle["local-rule-editor"] = value
    }
}

internal fun SetLocalNetworkAccessError.message(): Int =
    when (this) {
        SetLocalNetworkAccessError.Conflict -> R.string.local_access_conflict
        SetLocalNetworkAccessError.Invalid -> R.string.local_access_invalid_rule
        is SetLocalNetworkAccessError.Unknown -> R.string.local_access_save_failed
    }
