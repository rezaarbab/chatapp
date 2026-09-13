package chatapp.app.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import chatapp.android.repo.ConversationRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** Phase 5 (design §11) — devices list, revoke, add-device entry point. */
class DevicesViewModel(private val repo: ConversationRepository) : ViewModel() {

    data class UiState(
        val devices: List<ConversationRepository.DeviceRow> = emptyList(),
        val myDeviceId: String = "",
        val loading: Boolean = true,
        val banner: String? = null,
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state

    init { refresh() }

    fun refresh() {
        viewModelScope.launch {
            try {
                val devices = repo.devices()
                _state.value = UiState(
                    devices = devices,
                    myDeviceId = repo.myDeviceId(),
                    loading = false,
                )
            } catch (e: Exception) {
                _state.value = UiState(
                    devices = emptyList(),
                    myDeviceId = repo.myDeviceId(),
                    loading = false,
                    banner = "دریافت فهرست دستگاه‌ها ناموفق بود",
                )
            }
        }
    }

    fun revoke(deviceId: String, confirmed: Boolean) {
        if (!confirmed) return
        viewModelScope.launch {
            val ok = repo.revokeDevice(deviceId)
            _state.value = _state.value.copy(
                banner = if (ok) "دستگاه حذف شد" else "حذف ناموفق بود",
            )
            refresh()
        }
    }

    class Factory(private val repo: ConversationRepository) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T =
            DevicesViewModel(repo) as T
    }
}
