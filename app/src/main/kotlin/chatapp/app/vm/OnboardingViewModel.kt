package chatapp.app.vm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import chatapp.android.net.ChatApiClient
import chatapp.android.repo.ConversationRepository
import chatapp.app.AppContainer
import chatapp.app.ChatApplication
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** Phase 5 (design §3/§8) — onboarding: register / addDevice / refresh. */
class OnboardingViewModel(private val repo: ConversationRepository) : ViewModel() {

    sealed interface State {
        data object Choose : State
        data object RegisterForm : State
        data object AddDeviceForm : State
        data object Working : State
        data object Done : State
        data class Failure(val message: String, val retryable: Boolean) : State
    }

    private val _state = MutableStateFlow<State>(State.Choose)
    val state: StateFlow<State> = _state

    fun chooseRegister() { _state.value = State.RegisterForm }
    fun chooseAddDevice() { _state.value = State.AddDeviceForm }
    fun back() { _state.value = State.Choose }

    fun register(username: String) {
        if (!validUsername(username)) {
            _state.value = State.Failure("نام کاربری فقط حروف/اعداد/_/- (حداکثر ۶۴)", false)
            return
        }
        _state.value = State.Working
        viewModelScope.launch {
            _state.value = try {
                repo.register(username)
                State.Done
            } catch (e: ChatApiClient.ApiException) {
                when (e.status) {
                    409 -> State.Failure("این نام کاربری قبلاً گرفته شده", false)
                    429 -> State.Failure("تعداد ثبت زیاد است؛ کمی بعد تلاش کنید", true)
                    else -> State.Failure("خطای سرور (${e.status})", true)
                }
            } catch (e: java.io.IOException) {
                State.Failure("خطای شبکه", true)
            } catch (e: IllegalArgumentException) {
                State.Failure(e.message ?: "خطا", false)
            }
        }
    }

    fun addDevice(username: String, accountId: String, authorizerDeviceId: String) {
        if (!validUsername(username) || accountId.isBlank() || authorizerDeviceId.isBlank()) {
            _state.value = State.Failure("همه فیلدها لازم است", false)
            return
        }
        _state.value = State.Working
        viewModelScope.launch {
            _state.value = try {
                repo.addDevice(username, accountId, authorizerDeviceId)
                State.Done
            } catch (e: ChatApiClient.ApiException) {
                when (e.status) {
                    404 -> State.Failure("حساب یا دستگاه مجازدهنده پیدا نشد", false)
                    403 -> State.Failure("امضای مجازدهنده نامعتبر است", false)
                    429 -> State.Failure("تعداد زیاد است؛ کمی بعد تلاش کنید", true)
                    else -> State.Failure("خطای سرور (${e.status})", true)
                }
            } catch (e: java.io.IOException) {
                State.Failure("خطای شبکه", true)
            } catch (e: IllegalArgumentException) {
                State.Failure(e.message ?: "خطا", false)
            }
        }
    }

    fun retry() { _state.value = State.Choose }

    companion object {
        fun validUsername(u: String): Boolean = Regex("^[A-Za-z0-9_-]{1,64}$").matches(u)
    }

    class Factory(private val repo: ConversationRepository) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T =
            OnboardingViewModel(repo) as T
    }
}
