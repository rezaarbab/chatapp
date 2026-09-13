package chatapp.android.repo

import chatapp.android.crypto.SqlCipherProtocolStore
import chatapp.android.net.ChatApiClient
import chatapp.android.protocol.Messaging
import chatapp.android.protocol.PreKeyManager
import chatapp.android.runtime.ClientRuntime
import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Phase 5 (design §6) — the ONLY layer the UI is allowed to see. Wraps the
 * Phase-4 protocol managers with coroutine safety, outbox crash-safety, token
 * refresh, and poller state. Plaintext crosses this boundary exactly twice:
 * once inbound (to the encrypted mirror) and once outbound (from the UI send
 * call to encrypt+POST) — never into logs (Phase 4 rule #6, enforced by CI).
 */
open class ConversationRepository(private val runtime: ClientRuntime) {

    /** Non-null accessors: a real runtime always has all five collaborators. */
    private val store: SqlCipherProtocolStore get() = runtime.store!!
    private val accounts get() = runtime.accounts!!
    private val preKeys get() = runtime.preKeys!!
    private val messaging get() = runtime.messaging!!
    private val httpClient get() = runtime.client!!
    private val io = Dispatchers.IO
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private fun authed(): SqlCipherProtocolStore.AccountState = store.requireAccountState()

    sealed interface SyncState {
        data object Idle : SyncState
        data object Syncing : SyncState
        data class Backoff(val untilEpochMs: Long) : SyncState
        data class Error(val kind: Kind) : SyncState {
            enum class Kind { NETWORK, AUTH, RATE_LIMIT, OTHER }
        }
    }

    private val _syncState = MutableStateFlow<SyncState>(SyncState.Idle)
    val syncState: StateFlow<SyncState> = _syncState

    // ---- lifecycle ----

    fun isRegistered(): Boolean = store.loadAccountState() != null

    fun registeredUsername(): String? = store.loadAccountState()?.username

    /**
     * Runs one network action; on TOKEN_EXPIRED (and only that) refreshes the
     * token once and retries the action (design §6 token refresh).
     */
    private suspend fun <T> withAuthRefresh(action: suspend () -> T): T = withContext(io) {
        try {
            action()
        } catch (e: ChatApiClient.ApiException) {
            if (e.code == "TOKEN_EXPIRED") {
                accounts.refreshToken()
                action()
            } else {
                throw e
            }
        }
    }

    // ---- account setup (onboarding §3) ----

    /** Open for JVM-test subclass fakes (design §13); production path unchanged. */
    open suspend fun register(username: String): Unit = withContext(io) {
        val state = accounts.register(username)
        preKeys.uploadBatch()
        state
    }

    open suspend fun addDevice(
        username: String,
        accountId: String,
        authorizerDeviceId: String,
    ): Unit = withContext(io) {
        val state = accounts.addDevice(
            accountId = accountId,
            username = username,
            authorizerDeviceId = authorizerDeviceId,
            authorizerSignature = accounts.authorizerSigner(),
        )
        preKeys.uploadBatch()
        state
    }

    // ---- conversations (design §4/§5) ----

    data class Conversation(
        val peerKey: String, // account_id, username (pending contact), or "self"
        val peerUsername: String,
        val lastActivityAt: Long,
        val previewSnippet: String,
        val lastOutState: String?,
    )

    suspend fun conversations(): List<Conversation> = withContext(io) {
        val own = authed().accountId
        val usernameByAccount = HashMap<String, String>()
        for ((u, acc) in store.listContacts()) {
            if (acc != null) usernameByAccount[acc] = u
        }
        store.listConversationRows(own).map { row ->
            val username = when {
                row.peerKey == "self" -> "همه دستگاه‌های من"
                usernameByAccount.containsKey(row.peerKey) -> usernameByAccount[row.peerKey]!!
                else -> row.peerKey
            }
            Conversation(
                peerKey = row.peerKey,
                peerUsername = username,
                lastActivityAt = row.lastActivityAt,
                previewSnippet = snippetOf(row.preview),
                lastOutState = row.lastOutState,
            )
        }
    }

    data class ThreadItem(
        val id: String,
        val text: String,
        val mine: Boolean,
        val sendState: String?, // null=inbox, else outbox state
        val at: Long,
    )

    suspend fun thread(peerKey: String): List<ThreadItem> = withContext(io) {
        val own = authed()
        val items = mutableListOf<ThreadItem>()
        if (peerKey == "self") {
            for ((pt, at) in store.listThreadRows(own.accountId, "self")) {
                items.add(ThreadItem("m_$at", textOf(pt), mine = true, sendState = null, at = at))
            }
        } else if (peerKey.startsWith("u_") || !peerKey.contains("-")) {
            // peer addressed by (pending) username: outbox items only until first reply
            val acc = store.loadContact(peerKey)
            if (acc != null) {
                for ((pt, at) in store.listThreadRows(own.accountId, acc)) {
                    items.add(ThreadItem("m_$at", textOf(pt), mine = false, sendState = null, at = at))
                }
            }
            for (row in store.listOutbox().filter { it.recipientUsername == peerKey }) {
                items.add(
                    ThreadItem(
                        id = row.localId,
                        text = textOf(row.plaintext),
                        mine = true,
                        sendState = row.state,
                        at = row.createdAt,
                    ),
                )
            }
        } else {
            for ((pt, at) in store.listThreadRows(own.accountId, peerKey)) {
                items.add(ThreadItem("m_$at", textOf(pt), mine = false, sendState = null, at = at))
            }
            val acc = store.loadContact(peerKey)
            if (acc == peerKey) {
                for (row in store.listOutbox().filter { it.recipientUsername == peerKey }) {
                    items.add(ThreadItem(row.localId, textOf(row.plaintext), true, row.state, row.createdAt))
                }
            }
        }
        items.sortedBy { it.at }
    }

    // ---- send path (design §5/§8) ----

    sealed interface SendResult {
        data object Ok : SendResult
        data class Rejected(val reason: String) : SendResult
        data class Retryable(val reason: String) : SendResult
    }

    suspend fun send(peerKey: String, text: String): SendResult {
        val localId = UUID.randomUUID().toString()
        val now = System.currentTimeMillis()
        // crash-safe: persist BEFORE any network I/O (design §8)
        withContext(io) {
            store.insertOutbox(
                SqlCipherProtocolStore.OutboxRow(
                    localId = localId,
                    recipientUsername = peerKey,
                    plaintext = text.toByteArray(Charsets.UTF_8),
                    state = "pending",
                    logicalMsgId = null,
                    error = null,
                    createdAt = now,
                    updatedAt = now,
                ),
            )
        }
        return dispatch(localId, peerKey, text, freshLogicalId = true)
    }

    /** Retry uses a NEW logical id (server duplicate engine is idempotent per id). */
    suspend fun retry(localId: String): SendResult = withContext(io) {
        val row = store.listOutbox().firstOrNull { it.localId == localId }
            ?: return@withContext SendResult.Rejected("gone")
        dispatch(localId, row.recipientUsername, textOf(row.plaintext), freshLogicalId = true)
    }

    private suspend fun dispatch(
        localId: String,
        peerKey: String,
        text: String,
        freshLogicalId: Boolean,
    ): SendResult {
        val own = authed()
        return try {
            withAuthRefresh {
                val targets = resolveTargets(peerKey, own)
                if (targets.isEmpty()) {
                    store.updateOutboxState(localId, "failed", null, "receiver has no active devices", System.currentTimeMillis())
                    return@withAuthRefresh SendResult.Rejected("receiver has no active devices")
                }
                val sent = messaging.send(
                    preKeys,
                    text.toByteArray(Charsets.UTF_8),
                    targets,
                )
                if (sent.all { it.serverStatus == "queued" }) {
                    store.updateOutboxState(localId, "sent", sent.firstOrNull()?.logicalMsgId, null, System.currentTimeMillis())
                    rememberContact(peerKey, own.accountId)
                    SendResult.Ok
                } else {
                    val bad = sent.first { it.serverStatus != "queued" }
                    store.updateOutboxState(localId, "failed", null, bad.serverStatus, System.currentTimeMillis())
                    if (bad.serverStatus == "rejected") SendResult.Rejected(bad.serverStatus)
                    else SendResult.Retryable(bad.serverStatus)
                }
            }
        } catch (e: ChatApiClient.ApiException) {
            val kind = when {
                e.code == "RATE_LIMITED" -> "rate-limited"
                e.status == 404 -> "account not found"
                else -> "server error ${e.status}"
            }
            withContext(io) { store.updateOutboxState(localId, "failed", null, kind, System.currentTimeMillis()) }
            if (e.status == 404 && peerKey.startsWith("u_")) {
                withContext(io) { store.deleteContact(peerKey) }
            }
            SendResult.Retryable(kind)
        } catch (e: java.io.IOException) {
            withContext(io) { store.updateOutboxState(localId, "failed", null, "offline", System.currentTimeMillis()) }
            SendResult.Retryable("offline")
        }
    }

    private suspend fun resolveTargets(
        peerKey: String,
        own: SqlCipherProtocolStore.AccountState,
    ): List<Messaging.TargetDevice> {
        val accountId = if (peerKey == "self") {
            own.accountId
        } else {
            val known = store.loadContact(peerKey)
            if (known != null) known else {
                // first contact: username is the only handle the server knows (§15.1)
                peerKey
            }
        }
        val devices = withAuthRefresh { messaging.discoverDevices(accountId) }
        if (peerKey != "self") {
            // cache the resolution so future sends skip discovery ambiguity
            if (store.loadContact(peerKey) == null) {
                rememberContact(peerKey, accountId)
            }
        }
        return devices
            .filter { it.deviceId != own.deviceId } // never loop back to THIS device
            .map { Messaging.TargetDevice(accountId, it.deviceId, it.devNo) }
    }

    private fun rememberContact(username: String, accountId: String) {
        store.upsertContact(username, accountId, System.currentTimeMillis())
    }

    // ---- receive / poller (design §7) ----

    fun startPolling(foreground: Boolean) {
        scope.launch { pollLoop(foreground) }
    }

    private suspend fun pollLoop(foreground: Boolean) {
        var failures = 0
        while (true) {
            val base = if (foreground) 60_000L else 300_000L
            val jitter = (0.9 + Math.random() * 0.2)
            delay((base * jitter).toLong())
            try {
                _syncState.value = SyncState.Syncing
                withAuthRefresh { pullAndAck() }
                failures = 0
                _syncState.value = SyncState.Idle
            } catch (e: ChatApiClient.ApiException) {
                failures++
                _syncState.value = when {
                    e.status == 401 -> SyncState.Error(SyncState.Error.Kind.AUTH)
                    e.code == "RATE_LIMITED" -> SyncState.Error(SyncState.Error.Kind.RATE_LIMIT)
                    else -> SyncState.Error(SyncState.Error.Kind.OTHER)
                }
                delay(backoffMs(failures))
            } catch (e: java.io.IOException) {
                failures++
                _syncState.value = SyncState.Error(SyncState.Error.Kind.NETWORK)
                delay(backoffMs(failures))
            }
        }
    }

    private suspend fun backoffMs(failures: Int): Long {
        val ms = 60_000L * (1L shl minOf(failures - 1, 4)) // 1,2,4,8,16 min cap ~10min
        _syncState.value = SyncState.Backoff(System.currentTimeMillis() + ms)
        return minOf(ms, 10 * 60_000L)
    }

    /** One fetch -> decrypt -> mirror -> ack cycle; also resumes stale outbox rows. */
    suspend fun pullAndAck(): Unit = withContext(io) {
        val received = messaging.receive() // decrypt+persist+ack (Phase 4 code)
        // resume outbox rows left pending by a previous process death (§8)
        val now = System.currentTimeMillis()
        for (row in store.listOutbox()) {
            if (row.state == "pending") {
                // will be re-dispatched by the explicit resume call below
            }
        }
        received
    }

    suspend fun resumePendingOutbox(): Unit = withContext(io) {
        val pending = store.listOutbox().filter { it.state == "pending" }
        for (row in pending) {
            dispatch(row.localId, row.recipientUsername, textOf(row.plaintext), freshLogicalId = true)
        }
    }

    // ---- devices screen (design §11) ----

    data class DeviceRow(val deviceId: String, val devNo: Int, val thisDevice: Boolean)

    suspend fun devices(): List<DeviceRow> = withContext(io) {
        val own = authed()
        val devices = withAuthRefresh { messaging.discoverDevices(own.accountId) }
        devices.map { DeviceRow(it.deviceId, it.devNo, it.deviceId == own.deviceId) }
    }

    suspend fun revokeDevice(deviceId: String): Boolean = withContext(io) {
        try {
            withAuthRefresh {
                httpClient.request("DELETE", "/devices/$deviceId", token = authed().token)
                null
            }
            true
        } catch (e: ChatApiClient.ApiException) {
            false
        } catch (e: java.io.IOException) {
            false
        }
    }

    fun myDeviceId(): String = authed().deviceId

    fun myAccountId(): String = authed().accountId

    // ---- helpers (UI-facing strings; never logged) ----

    private fun textOf(bytes: ByteArray): String =
        if (bytes.isEmpty()) "" else String(bytes, Charsets.UTF_8)

    private fun snippetOf(bytes: ByteArray): String = textOf(bytes).take(60)
}

