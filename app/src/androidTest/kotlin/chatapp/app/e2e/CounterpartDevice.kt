package chatapp.app.e2e

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import chatapp.android.account.AccountManager
import chatapp.android.crypto.SqlCipherProtocolStore
import chatapp.android.net.ChatApiClient
import chatapp.android.protocol.Messaging
import chatapp.android.protocol.PreKeyManager
import java.io.File
import java.security.SecureRandom

/**
 * Phase 5 e2e acceptance (design §13) — the counterpart "user B" device:
 * the Phase-4-proven TestDevice pattern, rebuilt around the app's own library
 * classes so the outside driver is a fully real protocol stack (register,
 * prekeys, messaging) talking to the real staging backend WITHOUT any UI.
 * Assertions about what the APP sent/received are made from this side.
 */
class CounterpartDevice(val label: String) {

    companion object {
        fun stagingUrl(): String =
            InstrumentationRegistry.getArguments().getString("stagingUrl")
                ?: "https://chatapp-staging.aacc32351.workers.dev"
    }

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dir: File = context.getDir("e2e_counterparts", Context.MODE_PRIVATE)

    lateinit var store: SqlCipherProtocolStore
        private set
    lateinit var client: ChatApiClient
        private set
    lateinit var accounts: AccountManager
        private set
    lateinit var preKeys: PreKeyManager
        private set
    lateinit var messaging: Messaging
        private set

    /** Wipes any previous counterpart DB and opens a fresh stack. */
    fun openFresh() {
        val f = File(dir, "cp_$label.db")
        if (f.exists()) f.delete()
        f.parentFile?.mkdirs()
        // Direct random passphrase (no KeyStore wrap): a test device whose key
        // material is wiped together with its DB file — never the app's own DB.
        val rnd = SecureRandom()
        val passphrase = ByteArray(32).also { for (i in it.indices) it[i] = rnd.nextInt(256).toByte() }
        store = SqlCipherProtocolStore.open(f, passphrase)
        client = ChatApiClient(stagingUrl())
        accounts = AccountManager(client, store)
        preKeys = PreKeyManager(client, store)
        messaging = Messaging(client, store)
    }

    fun close() {
        if (this::store.isInitialized && store.isOpen) store.close()
    }
}
