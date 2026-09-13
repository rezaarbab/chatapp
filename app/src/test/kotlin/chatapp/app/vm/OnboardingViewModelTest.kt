package chatapp.app.vm

import chatapp.android.net.ChatApiClient
import chatapp.android.repo.ConversationRepository
import chatapp.android.runtime.ClientRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Phase 5 (design Â§13) â€” pure-JVM ViewModel state tests. Error-mapping (Â§8)
 * is exercised by overriding the repository's open network entry points;
 * no SQLCipher, no Android. The fake runtime is never touched because the
 * overridden methods do not use it.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OnboardingViewModelTest {

    private val dispatcher = StandardTestDispatcher()
    private val scope = TestScope(dispatcher)

    private fun idle() = scope.advanceUntilIdle()

    private fun vm(failing: (() -> Unit)?): OnboardingViewModel {
        val runtime = ClientRuntime.forJvmTest()
        val repo = object : ConversationRepository(runtime) {
            override suspend fun register(username: String) {
                failing?.invoke()
            }
        }
        return OnboardingViewModel(repo)
    }

    @Before fun setUp() { Dispatchers.setMain(dispatcher) }
    @After fun tearDown() { Dispatchers.resetMain() }

    @Test
    fun `invalid username rejected client-side`() {
        val v = vm(null)
        v.register("has space!")
        val s = v.state.value
        assertTrue(s is OnboardingViewModel.State.Failure && !s.retryable)
    }

    @Test
    fun `username taken maps to non-retryable failure`() {
        val v = vm { throw ChatApiClient.ApiException(409, "USERNAME_TAKEN", "c", null) }
        v.register("u_valid")
        idle()
        val s = v.state.value
        assertTrue(s is OnboardingViewModel.State.Failure && !s.retryable)
    }

    @Test
    fun `rate limit maps to retryable failure`() {
        val v = vm { throw ChatApiClient.ApiException(429, "RATE_LIMITED", "c", null) }
        v.register("u_valid")
        idle()
        val s = v.state.value
        assertTrue(s is OnboardingViewModel.State.Failure && s.retryable)
    }

    @Test
    fun `network error maps to retryable failure`() {
        val v = vm { throw java.io.IOException("offline") }
        v.register("u_valid")
        idle()
        val s = v.state.value
        assertTrue(s is OnboardingViewModel.State.Failure && s.retryable)
    }

    @Test
    fun `success reaches Done`() {
        val v = vm(null)
        v.register("u_valid")
        idle()
        assertTrue(v.state.value is OnboardingViewModel.State.Done)
    }
}
