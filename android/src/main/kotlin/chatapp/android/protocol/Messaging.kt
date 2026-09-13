package chatapp.android.protocol

import chatapp.android.crypto.SqlCipherProtocolStore
import chatapp.android.net.ChatApiClient
import org.json.JSONArray
import org.json.JSONObject
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage

/**
 * Phase 4 — send/receive wired to the real API (design §6/§7).
 *
 * Session addresses are (account_id, dev_no) — the multi-device model verified
 * in Gate 2/Gate 3. The receiver's decrypt path implements the Gate-4-verified
 * fallback: the wire bytes of BOTH message types start with the same version
 * byte (0x44), so the type cannot be sniffed; cross-construction throws
 * InvalidMessageException deterministically, which makes try/fallback sound.
 * Duplicates (redelivery after crash-before-ACK) surface as
 * DuplicateMessageException and are treated as already-processed (Phase 3 §12).
 */
class Messaging(
    private val client: ChatApiClient,
    private val store: SqlCipherProtocolStore,
) {

    data class TargetDevice(val accountId: String, val deviceId: String, val devNo: Int)

    data class DeviceEntry(val deviceId: String, val devNo: Int, val registrationId: Int)

    data class SentMessage(
        val logicalMsgId: String,
        val targetDeviceId: String,
        val serverStatus: String,
        val ciphertextType: Int,
    )

    data class ReceivedMessage(
        val deliveryId: String,
        val logicalMsgId: String,
        val senderAccountId: String,
        val senderDevNo: Int,
        val seq: Long,
        val plaintext: ByteArray,
    )

    private fun ownAddress(): SignalProtocolAddress {
        val state = store.requireAccountState()
        return SignalProtocolAddress(state.accountId, state.devNo)
    }

    private fun token(): String = store.requireAccountState().token

    fun discoverDevices(accountId: String): List<DeviceEntry> {
        val resp = client.request("GET", "/accounts/$accountId/devices", token = token())!!
        return resp.getJSONArray("devices").let { arr ->
            (0 until arr.length()).map { i ->
                val d = arr.getJSONObject(i)
                DeviceEntry(d.getString("device_id"), d.getInt("dev_no"), d.getInt("registration_id"))
            }
        }
    }

    /** Real PQXDH session establishment: only fetches a bundle when no session exists. */
    fun ensureSession(preKeys: PreKeyManager, target: TargetDevice) {
        val addr = SignalProtocolAddress(target.accountId, target.devNo)
        if (store.containsSession(addr)) return
        val bundle = preKeys.fetchBundle(target.deviceId)
        SessionBuilder(store, addr, ownAddress()).process(bundle)
    }

    fun hasSession(target: TargetDevice): Boolean =
        store.containsSession(SignalProtocolAddress(target.accountId, target.devNo))

    /**
     * Encrypts separately per target device (Gate 3-B: ciphertexts are
     * per-device) and POSTs one logical message. Returns the per-target server
     * status plus the libsignal ciphertext type (PREKEY vs WHISPER).
     */
    fun send(preKeys: PreKeyManager, plaintext: ByteArray, targets: List<TargetDevice>): List<SentMessage> {
        require(targets.isNotEmpty()) { "no targets" }
        val logicalMsgId = java.util.UUID.randomUUID().toString()
        val targetsArray = JSONArray()
        val types = HashMap<String, Int>()
        for (target in targets) {
            ensureSession(preKeys, target)
            val cipher = SessionCipher(store, ownAddress(), SignalProtocolAddress(target.accountId, target.devNo))
            val ciphertext = cipher.encrypt(plaintext)
            types[target.deviceId] = ciphertext.type
            targetsArray.put(
                JSONObject()
                    .put("device_id", target.deviceId)
                    .put("ciphertext_b64", chatapp.android.account.b64(ciphertext.serialize())),
            )
        }
        val resp = client.request(
            "POST",
            "/messages",
            token = token(),
            body = JSONObject().put("logical_msg_id", logicalMsgId).put("targets", targetsArray),
        )!!
        val results = resp.getJSONArray("results")
        return (0 until results.length()).map { i ->
            val r = results.getJSONObject(i)
            SentMessage(logicalMsgId, r.getString("device_id"), r.getString("status"), types[r.getString("device_id")] ?: -1)
        }
    }

    /**
     * Fetches the queue, decrypts (Gate-4 fallback), persists to the local
     * mirror BEFORE acking (crash-safe), and ACKs. Rows that fail decryption
     * with DuplicateMessageException are treated as already-processed: they are
     * mirrored/acked but not re-delivered to the caller.
     */
    fun receive(ack: Boolean = true): List<ReceivedMessage> {
        val resp = client.request("GET", "/messages?limit=200", token = token())!!
        val rows = resp.getJSONArray("messages")
        val out = mutableListOf<ReceivedMessage>()
        val ackIds = mutableListOf<String>()
        val now = System.currentTimeMillis()
        for (i in 0 until rows.length()) {
            val row = rows.getJSONObject(i)
            val deliveryId = row.getString("delivery_id")
            val logicalMsgId = row.getString("logical_msg_id")
            val senderAccountId = row.getString("sender_account_id")
            val senderDevNo = row.getInt("sender_dev_no")
            val seq = row.getLong("seq")
            val wire = chatapp.android.account.unB64(row.getString("ciphertext"))
            val cipher = SessionCipher(store, ownAddress(), SignalProtocolAddress(senderAccountId, senderDevNo))
            val plaintext = try {
                decryptAny(cipher, wire)
            } catch (e: DuplicateMessageException) {
                null
            }
            store.insertMessage(
                deliveryId, logicalMsgId, senderAccountId, senderDevNo, seq,
                plaintext ?: ByteArray(0), now,
            )
            ackIds.add(deliveryId)
            if (plaintext != null) {
                out.add(ReceivedMessage(deliveryId, logicalMsgId, senderAccountId, senderDevNo, seq, plaintext))
            }
        }
        if (ack && ackIds.isNotEmpty()) {
            ackIds.chunked(90).forEach { chunk ->
                client.request(
                    "POST",
                    "/messages/ack",
                    token = token(),
                    body = JSONObject().put("delivery_ids", JSONArray(chunk)),
                )
            }
        }
        return out
    }

    /** Gate-4-verified decode: try Whisper, fall back to PreKey. */
    private fun decryptAny(cipher: SessionCipher, wire: ByteArray): ByteArray =
        try {
            cipher.decrypt(SignalMessage(wire))
        } catch (e: InvalidMessageException) {
            cipher.decrypt(PreKeySignalMessage(wire))
        }
}
