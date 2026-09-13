package chatapp.app.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import chatapp.android.net.ChatApiClient
import chatapp.android.repo.ConversationRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** Phase 5 (design §4/§8) — conversation list + sync banner state. */
class ConversationsViewModel(private val repo: ConversationRepository) : ViewModel() {

    data class UiState(
        val conversations: List<ConversationRepository.Conversation> = emptyList(),
        val loading: Boolean = true,
        val syncLabel: String = "",
        val error: String? = null,
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state

    private val _newChatError = MutableStateFlow<String?>(null)
    val newChatError: StateFlow<String?> = _newChatError

    init {
        viewModelScope.launch {
            repo.syncState.collect { s ->
                _state.value = _state.value.copy(
                    syncLabel = when (s) {
                        is ConversationRepository.SyncState.Syncing -> "در حال همگام‌سازی…"
                        is ConversationRepository.SyncState.Backoff -> "اتصال برقرار نشد؛ تلاش مجدد خودکار"
                        is ConversationRepository.SyncState.Error -> when (s.kind) {
                            ConversationRepository.SyncState.Error.Kind.NETWORK -> "آفلاین — تلاش خودکار ادامه دارد"
                            ConversationRepository.SyncState.Error.Kind.AUTH -> "خطای احراز هویت"
                            else -> "خطای سرور"
                        }
                        else -> ""
                    },
                )
            }
        }
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            try {
                repo.pullAndAck()
            } catch (_: Exception) {
                // poller state banner already communicates failures; list must render anyway
            }
            val list = runCatching { repo.conversations() }.getOrDefault(emptyList())
            _state.value = _state.value.copy(conversations = list, loading = false)
        }
    }

    /** Peer key for navigation: username for a brand-new chat (§4 first-send discovery). */
    fun startNewChat(username: String, onValid: (String) -> Unit) {
        if (!OnboardingViewModel.validUsername(username)) {
            _newChatError.value = "نام کاربری نامعتبر است"
            return
        }
        _newChatError.value = null
        onValid(username)
    }

    fun clearNewChatError() { _newChatError.value = null }

    class Factory(private val repo: ConversationRepository) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T =
            ConversationsViewModel(repo) as T
    }
}
