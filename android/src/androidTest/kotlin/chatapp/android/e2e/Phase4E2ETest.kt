package chatapp.android.e2e

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import chatapp.android.account.AccountManager
import chatapp.android.crypto.DatabaseKeyManager
import chatapp.android.crypto.SqlCipherProtocolStore
import chatapp.android.net.ChatApiClient
import chatapp.android.protocol.Messaging
import chatapp.android.protocol.PreKeyManager
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.signal.libsignal.protocol.message.CiphertextMessage

/**
 * Phase 4 — REAL end-to-end vertical slice on a real Android emulator against
 * the REAL Cloudflare staging backend (user mandate steps 5..8; design §10).
 *
 * Coverage:
 *  - T1 fullLifecycle: register → prekey upload → discovery → bundle → session
 *    → encrypt → send → Cloudflare queue → receive → decrypt → ACK → whisper
 *    transition after acknowledgement
 *  - T2 multiDeviceSelfSync: real add_device (dual signatures) → one logical
 *    message to [B1, A2] → both devices decrypt
 *  - T3 restartPersistence: stores closed and reopened (AndroidKeyStore unwrap)
 *    → session, token, and the local plaintext mirror survive
 *  - T4 redeliveryAfterCrashBeforeAck: fetch-without-ACK → restart →
 *    redelivery → DuplicateMessageException treated as processed → ACK
 *
 * Security (user mandate #6/#10): plaintexts in these tests are public test
 * constants; no real user content. No token/key material is ever printed or
 * persisted outside the encrypted stores. Test logs carry assertions only.
 */
@RunWith(AndroidJUnit4::class)
class Phase4E2ETest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val stagingUrl: String = requireNotNull(
        InstrumentationRegistry.getArguments().getString("stagingUrl"),
    ) { "stagingUrl instrumentation argument missing" }

    /** One logical "device": its own encrypted store, API client, and helpers. */
    private inner class TestDevice(val label: String) {
        private var _store: SqlCipherProtocolStore = SqlCipherProtocolStore.open(
            context.getDatabasePath("phase4_$label.db"),
            DatabaseKeyManager.getOrCreatePassphrase(context, "phase4_alias_$label"),
        )
        val store: SqlCipherProtocolStore get() = _store
        val client = ChatApiClient(stagingUrl)
        val accounts: AccountManager get() = AccountManager(client, _store)
        val preKeys: PreKeyManager get() = PreKeyManager(client, _store)
        val messaging: Messaging get() = Messaging(client, _store)

        fun close() = _store.close()

        /** Simulates a process restart: close + reopen with a fresh KeyStore unwrap. */
        fun reopenStore() {
            _store.close()
            _store = SqlCipherProtocolStore.open(
                context.getDatabasePath("phase4_$label.db"),
                DatabaseKeyManager.getOrCreatePassphrase(context, "phase4_alias_$label"),
            )
            check(_store.isOpen)
        }
    }

    private fun freshA1B1(): Pair<TestDevice, TestDevice> {
        val a = TestDevice("a_${System.nanoTime()}")
        val b = TestDevice("b_${System.nanoTime()}")
        a.accounts.register(AccountManager.randomUsername())
        b.accounts.register(AccountManager.randomUsername())
        a.preKeys.uploadBatch()
        b.preKeys.uploadBatch()
        return a to b
    }

    private fun targetOf(device: TestDevice): Messaging.TargetDevice {
        val state = device.accounts.requireState()
        return Messaging.TargetDevice(state.accountId, state.deviceId, state.devNo)
    }

    @Test
    fun t1_fullLifecycle_registerToAckOnRealBackend() {
        val (a, b) = freshA1B1()
        try {
            val aState = a.accounts.requireState()
            val bState = b.accounts.requireState()

            // device discovery (real API): A sees B's active device
            val discovered = a.messaging.discoverDevices(bState.accountId)
            assertEquals(listOf(bState.deviceId), discovered.map { it.deviceId })
            assertEquals(bState.devNo, discovered[0].devNo)

            // send: session build (bundle fetch) + per-device encrypt + queue
            val plaintext = "phase4 e2e: hello from A to B".toByteArray(Charsets.UTF_8)
            val sent = a.messaging.send(b.preKeys, plaintext, listOf(targetOf(b)))
            assertEquals(1, sent.size)
            assertEquals("queued", sent[0].serverStatus)
            assertEquals(CiphertextMessage.PREKEY_TYPE, sent[0].ciphertextType)

            // receive on B: real queue fetch → Gate-4 decryptAny → persist → ACK
            val received = b.messaging.receive()
            assertEquals(1, received.size)
            assertEquals(aState.accountId, received[0].senderAccountId)
            assertEquals(aState.devNo, received[0].senderDevNo)
            assertTrue(plaintext.contentEquals(received[0].plaintext))

            // after ACK the queue is empty (redelivery stops)
            assertTrue(b.messaging.receive().isEmpty())

            // B replies → decrypts on A → A's session becomes acknowledged
            val reply = b.messaging.send(a.preKeys, "phase4 e2e: reply from B".toByteArray(), listOf(targetOf(a)))
            assertEquals("queued", reply[0].serverStatus)
            val receivedOnA = a.messaging.receive()
            assertEquals(1, receivedOnA.size)
            assertEquals("phase4 e2e: reply from B", String(receivedOnA[0].plaintext))

            // the next A→B message must now be WHISPER type (Gate3-A behavior)
            val second = a.messaging.send(b.preKeys, "phase4 e2e: second message".toByteArray(), listOf(targetOf(b)))
            assertEquals(CiphertextMessage.WHISPER_TYPE, second[0].ciphertextType)
            val received2 = b.messaging.receive()
            assertEquals("phase4 e2e: second message", String(received2[0].plaintext))
        } finally {
            a.close()
            b.close()
        }
    }

    @Test
    fun t2_multiDeviceSelfSync_realAddDeviceBothTargetsDecrypt() {
        val (a, b) = freshA1B1()
        var a2: TestDevice? = null
        try {
            val aState = a.accounts.requireState()
            val bState = b.accounts.requireState()

            // A2 joins the account via the REAL add_device flow: A2 signs its
            // challenge, A1 (authorizer) co-signs the same context.
            a2 = TestDevice("a2_${System.nanoTime()}")
            val a2State = a2.accounts.addDevice(
                accountId = aState.accountId,
                username = aState.username,
                authorizerDeviceId = aState.deviceId,
                authorizerSignature = a.accounts.authorizerSigner(),
            )
            assertEquals(2, a2State.devNo)
            a2.preKeys.uploadBatch()

            // one logical message to [B1, A2] — cross-account + self-sync
            val plaintext = "phase4 e2e: multi-device fan-out".toByteArray(Charsets.UTF_8)
            val sent = a.messaging.send(
                b.preKeys,
                plaintext,
                listOf(
                    targetOf(b),
                    Messaging.TargetDevice(a2State.accountId, a2State.deviceId, a2State.devNo),
                ),
            )
            assertEquals(2, sent.size)
            assertTrue(sent.all { it.serverStatus == "queued" })
            assertEquals("both ciphertexts are PREKEY on fresh sessions",
                CiphertextMessage.PREKEY_TYPE, sent[0].ciphertextType)
            assertEquals(CiphertextMessage.PREKEY_TYPE, sent[1].ciphertextType)

            // both target devices decrypt the SAME logical message
            val onB = b.messaging.receive()
            val onA2 = a2.messaging.receive()
            assertEquals(1, onB.size)
            assertEquals(1, onA2.size)
            assertEquals(onB[0].logicalMsgId, onA2[0].logicalMsgId)
            assertTrue(plaintext.contentEquals(onB[0].plaintext))
            assertTrue(plaintext.contentEquals(onA2[0].plaintext))
            assertEquals(aState.accountId, onB[0].senderAccountId)
            assertEquals(aState.devNo, onB[0].senderDevNo)

            // A2 is visible in account discovery
            val devices = a.messaging.discoverDevices(aState.accountId)
            assertEquals(setOf(1, 2), devices.map { it.devNo }.toSet())
        } finally {
            a.close()
            b.close()
            a2?.close()
        }
    }

    @Test
    fun t3_restartPersistence_sessionTokenMirrorSurvive() {
        val (a, b) = freshA1B1()
        try {
            val plaintext = "phase4 e2e: pre-restart message".toByteArray(Charsets.UTF_8)
            a.messaging.send(b.preKeys, plaintext, listOf(targetOf(b)))
            val received = b.messaging.receive()
            assertEquals(1, received.size)
            val mirrorCountBefore = b.store.countMessages()

            // simulated restart: close + reopen every store (fresh KeyStore unwrap)
            a.reopenStore()
            b.reopenStore()

            // account state (incl. token) survived — API still authorizes B
            val stillB = b.messaging.receive()
            assertTrue(stillB.isEmpty()) // queue was acked; empty proves token works

            // session survived on A: the next message is WHISPER (no new bundle)
            val after = a.messaging.send(b.preKeys, "phase4 e2e: post-restart whisper".toByteArray(), listOf(targetOf(b)))
            assertEquals(CiphertextMessage.WHISPER_TYPE, after[0].ciphertextType)

            // local plaintext mirror survived the restart
            assertEquals(mirrorCountBefore, b.store.countMessages())

            val receivedAfter = b.messaging.receive()
            assertEquals("phase4 e2e: post-restart whisper", String(receivedAfter[0].plaintext))
        } finally {
            a.close()
            b.close()
        }
    }

    @Test
    fun t4_redeliveryAfterCrashBeforeAck_duplicateTreatedAsProcessed() {
        val (a, b) = freshA1B1()
        try {
            val plaintext = "phase4 e2e: crash-before-ack".toByteArray(Charsets.UTF_8)
            a.messaging.send(b.preKeys, plaintext, listOf(targetOf(b)))

            // crash between fetch and ACK: receive WITHOUT acking
            val first = b.messaging.receive(ack = false)
            assertEquals(1, first.size)
            assertTrue(plaintext.contentEquals(first[0].plaintext))

            // restart, then fetch again: the server redelivers the un-acked row
            b.reopenStore()
            val redelivered = b.messaging.receive(ack = false)
            assertEquals("server must redeliver un-acked rows", 1, redelivered.size)

            // the final receive() decrypts the redelivered row as a duplicate
            // (DuplicateMessageException → already-processed) and ACKs it
            val final = b.messaging.receive()
            assertTrue("duplicate must not re-deliver plaintext", final.isEmpty())

            // the queue is now empty and the local mirror kept the plaintext
            assertTrue(b.messaging.receive().isEmpty())
            assertTrue(b.store.countMessages() >= 1)
        } finally {
            a.close()
            b.close()
        }
    }
}
