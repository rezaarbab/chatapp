package chatapp.app

import android.content.Context
import chatapp.android.net.ChatApiClient
import chatapp.android.repo.ConversationRepository
import chatapp.android.runtime.ClientRuntime

/**
 * Phase 5 (design §1/§2) — manual DI: the entire object graph is five
 * collaborators, so a container object is all the wiring needed (no Hilt).
 * ChatApplication owns the single instance for the process.
 */
class AppContainer private constructor(
    val runtime: ClientRuntime,
    val repository: ConversationRepository,
) {
    companion object {
        /**
         * Opens the encrypted store and builds the stack. Can fail only if the
         * KeyStore/db open fails (§9) — the caller routes that to the honest
         * error screen; nothing is silently retried here.
         */
        fun create(context: Context, stagingUrl: String): AppContainer {
            val runtime = ClientRuntime.open(context, stagingUrl)
            return AppContainer(runtime, ConversationRepository(runtime))
        }
    }

    fun close() = runtime.close()
}
