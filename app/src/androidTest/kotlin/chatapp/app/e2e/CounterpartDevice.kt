package chatapp.app.e2e

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import chatapp.android.crypto.SqlCipherProtocolStore
import chatapp.android.net.ChatApiClient
import chatapp.android.protocol.Messaging
import chatapp.android.protocol.PreKeyManager
import chatapp.android.runtime.ClientRuntime
import java.io.File

/**
 * Phase 5 e2e acceptance (design §13) — the counterpart "user B" device.
 * This is the Phase-4-proven pattern (Phase4E2ETest.TestDevice) reused for
 * driving the UI test: a second, fully-real protocol stack that talks to the
 * real staging backend WITHOUT any UI, so assertions about what the APP
 * received/sent can be made from the outside.
 */
class CounterpartDevice(val label: String) {

    companion object {
        fun stagingUrl(): String =
            InstrumentationRegistry.getArguments().getString("stagingUrl")
                ?: "https://chatapp-staging.aacc32351.workers.dev"
    }

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dir: File = context.getDir("e2e_counterparts", Context.MODE_PRIVATE)

    private var _store: SqlCipherProtocolStore? = null

    val store: SqlCipherProtocolStore
        get() = _store ?: error("counterpart not opened")

    val client = ChatApiClient(stagingUrl())

    private fun freshRuntime(): ClientRuntime {
        val f = File(dir, "cp_$label.db")
        if (f.exists()) f.delete()
        f.parentFile?.mkdirs()
        // fresh store: per-test DB, app-scoped KeyStore alias is not shared with
        // the app's own DB; we use a direct random passphrase (no KeyStore wrap)
        // because this counterpart is a TEST device, wiped with its DB file.
        val rnd = java.security.SecureRandom()
        val passphrase = ByteArray(32) { rnd.nextByte().toByte() }
        val st = SqlCipherProtocolStore.open(f, passphrase)
        _store = st
        return ClientRuntime.forOpenStore(st, client)
    }

    lateinit var runtime: ClientRuntime

    fun openFresh() {
        runtime = freshRuntime()
    }

    fun close() {
        _store?.close()
        _store = null
    }
}
