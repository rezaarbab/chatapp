package chatapp.app.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import chatapp.android.repo.ConversationRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** Phase 5 (design §5/§8) — one chat thread: send, states, live refresh. */
class ChatViewModel(
    private val repo: ConversationRepository,
    val peerKey: String,
) : ViewModel() {

    data class UiState(
        val items: List<ConversationRepository.ThreadItem> = emptyList(),
        val sending: Boolean = false,
        val inputEnabled: Boolean = true,
        val banner: String? = null,
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state

    init {
        reload()
        viewModelScope.launch {
            repo.syncState.collect {
                // any completed sync re-reads the thread so new messages appear
                if (it is ConversationRepository.SyncState.Idle) reload()
            }
        }
    }

    fun reload() {
        viewModelScope.launch {
            val items = runCatching { repo.thread(peerKey) }.getOrDefault(emptyList())
            _state.value = _state.value.copy(items = items)
        }
    }

    fun send(text: String) {
        if (text.isBlank()) return
        _state.value = _state.value.copy(sending = true)
        viewModelScope.launch {
            val result = repo.send(peerKey, text)
            _state.value = when (result) {
                is ConversationRepository.SendResult.Ok ->
                    _state.value.copy(sending = false, banner = null)
                is ConversationRepository.SendResult.Rejected ->
                    _state.value.copy(sending = false, banner = "ارسال نشد: ${result.reason}")
                is ConversationRepository.SendResult.Retryable ->
                    _state.value.copy(sending = false, banner = "ارسال نشد (${result.reason}) — دوباره تلاش کنید")
            }
            reload()
        }
    }

    fun retry(localId: String) {
        viewModelScope.launch {
            repo.retry(localId)
            reload()
        }
    }

    class Factory(private val repo: ConversationRepository, private val peerKey: String) :
        ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T =
            ChatViewModel(repo, peerKey) as T
    }
}
