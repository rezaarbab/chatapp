package chatapp.android.runtime

import android.content.Context
import chatapp.android.account.AccountManager
import chatapp.android.crypto.DatabaseKeyManager
import chatapp.android.crypto.SqlCipherProtocolStore
import chatapp.android.net.ChatApiClient
import chatapp.android.protocol.Messaging
import chatapp.android.protocol.PreKeyManager
import java.io.File

/**
 * Phase 5 (design §1/§9) — owns the process-lifetime protocol stack: one
 * SQLCipher store opened via the AndroidKeyStore-wrapped app passphrase, plus
 * the four collaborators built on it. Nothing UI-specific lives here; the app
 * layer holds a single instance in its Application.
 *
 * Security: the token and every key stay inside this layer; callers receive
 * only the typed facades. The staging URL is a public constant (Phase 4 §2).
 */
/**
 * Internal visibility keeps the constructor a test seam only (same module +
 * friend tests), while the public API stays `open()`.
 */
class ClientRuntime internal constructor(
    val store: SqlCipherProtocolStore?,
    val client: ChatApiClient?,
    val accounts: AccountManager?,
    val preKeys: PreKeyManager?,
    val messaging: Messaging?,
) {
    companion object {
        /** The one and only app-level passphrase alias (not a per-test alias). */
        private const val KEY_ALIAS = "chatapp_main_db"

        fun open(context: Context, baseUrl: String): ClientRuntime {
            val passphrase = DatabaseKeyManager.getOrCreatePassphrase(context, KEY_ALIAS)
            val dbStore = SqlCipherProtocolStore.open(
                context.getDatabasePath("chatapp_main.db"),
                passphrase,
            )
            val apiClient = ChatApiClient(baseUrl)
            return ClientRuntime(
                store = dbStore,
                client = apiClient,
                accounts = AccountManager(apiClient, dbStore),
                preKeys = PreKeyManager(apiClient, dbStore),
                messaging = Messaging(apiClient, dbStore),
            )
        }
    }

    fun close() = store?.close()
}
