package chatapp.app

import android.app.Application
import chatapp.android.repo.ConversationRepository

/**
 * Phase 5 (design §9) — owns the process-lifetime runtime. The container is
 * opened lazily on first access; a KeyStore/DB failure is surfaced as
 * [FatalError] which MainActivity renders as the honest reset-or-exit screen
 * (wipe is a user decision, never automatic — §9).
 */
class ChatApplication : Application() {

    class FatalError(cause: Throwable) : Exception(cause)

    @Volatile
    private var container: AppContainer? = null
    private val lock = Any()

    /** Public staging URL is not a secret (Phase 4 §2); no config channel yet. */
    private val stagingUrl = "https://chatapp-staging.aacc32351.workers.dev"

    fun container(): AppContainer = container ?: synchronized(lock) {
        container ?: run {
            try {
                AppContainer.create(this, stagingUrl).also { created ->
                    container = created
                }
            } catch (t: Throwable) {
                throw FatalError(t)
            }
        }
    }

    override fun onTerminate() {
        container?.close()
        super.onTerminate()
    }
}
