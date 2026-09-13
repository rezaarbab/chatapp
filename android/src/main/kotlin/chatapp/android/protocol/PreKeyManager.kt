package chatapp.android.protocol

import chatapp.android.account.b64
import chatapp.android.account.unB64
import chatapp.android.crypto.SqlCipherProtocolStore
import chatapp.android.net.ChatApiClient
import org.json.JSONArray
import org.json.JSONObject
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/**
 * Phase 4 — PreKey lifecycle wired to the real API (design §5).
 *
 * Wire formats are the verified Phase 2 contract (V4..V7, PHASE2_PREKEY_DESIGN.md):
 *   - EC public keys:  33 bytes, 0x05 prefix  (libsignal serialize() form)
 *   - Kyber public keys: 1569 bytes, 0x08 prefix
 *   - signatures: 64 bytes over the public key's serialize() bytes
 *   - key_id: 0..16777215, device-unique via the persisted counter (store)
 * The bundle mapping is the exact path verified by Gate 4 / Scratch4 (design
 * Appendix A): identity_pub is RAW 32 bytes and must go through
 * ECPublicKey.fromPublicKeyBytes; EC/KEM pubs are the 33B/1569B serialize forms.
 */
class PreKeyManager(
    private val client: ChatApiClient,
    private val store: SqlCipherProtocolStore,
) {

    data class UploadReport(
        val signedPreKeyId: Int,
        val lastResortKyberId: Int,
        val oneTimeEcRemaining: Int,
        val oneTimeKyberRemaining: Int,
    )

    fun uploadBatch(oneTimeEc: Int = 100, oneTimeKyber: Int = 50): UploadReport {
        val state = store.requireAccountState()
        val now = System.currentTimeMillis()
        val identityPriv = store.identityKeyPair.privateKey

        val signedPair = ECKeyPair.generate()
        val signedId = store.nextPreKeyId()
        val signedSig = identityPriv.calculateSignature(signedPair.publicKey.serialize())
        store.storeSignedPreKey(signedId, SignedPreKeyRecord(signedId, now, signedPair, signedSig))

        val kemPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kemId = store.nextPreKeyId()
        val kemSig = identityPriv.calculateSignature(kemPair.publicKey.serialize())
        store.storeKyberPreKey(kemId, KyberPreKeyRecord(kemId, now, kemPair, kemSig))

        val ecArray = JSONArray()
        repeat(oneTimeEc) {
            val id = store.nextPreKeyId()
            val record = PreKeyRecord(id, ECKeyPair.generate())
            store.storePreKey(id, record)
            ecArray.put(
                JSONObject()
                    .put("key_id", id)
                    .put("public_key", b64(record.keyPair.publicKey.serialize())),
            )
        }

        val kyberArray = JSONArray()
        repeat(oneTimeKyber) {
            val id = store.nextPreKeyId()
            val kem = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val sig = identityPriv.calculateSignature(kem.publicKey.serialize())
            val record = KyberPreKeyRecord(id, now, kem, sig)
            store.storeKyberPreKey(id, record)
            kyberArray.put(
                JSONObject()
                    .put("key_id", id)
                    .put("public_key", b64(kem.publicKey.serialize()))
                    .put("signature", b64(sig)),
            )
        }

        val resp = client.request(
            "POST",
            "/prekeys",
            token = state.token,
            body = JSONObject()
                .put(
                    "signed_prekey",
                    JSONObject()
                        .put("key_id", signedId)
                        .put("public_key", b64(signedPair.publicKey.serialize()))
                        .put("signature", b64(signedSig)),
                )
                .put(
                    "last_resort_kyber",
                    JSONObject()
                        .put("key_id", kemId)
                        .put("public_key", b64(kemPair.publicKey.serialize()))
                        .put("signature", b64(kemSig)),
                )
                .put("one_time_prekeys", ecArray)
                .put("one_time_kyber_prekeys", kyberArray),
        )!!

        return UploadReport(
            signedPreKeyId = resp.getInt("signed_prekey_id"),
            lastResortKyberId = resp.getInt("last_resort_kyber_id"),
            oneTimeEcRemaining = resp.getInt("one_time_ec_remaining"),
            oneTimeKyberRemaining = resp.getInt("one_time_kyber_remaining"),
        )
    }

    /**
     * Refill policy (design §5): tops up one-time material when the LOCAL count
     * of unconsumed records falls below the thresholds. The server response's
     * remaining counts are authoritative and returned to the caller.
     */
    fun refillIfNeeded(ecThreshold: Int = 25, kyberThreshold: Int = 15): UploadReport? {
        val ecLocal = countRows("prekeys")
        val kyberLocal = countRows("kyber_prekeys")
        return if (ecLocal < ecThreshold || kyberLocal < kyberThreshold) {
            uploadBatch()
        } else {
            null
        }
    }

    private fun countRows(table: String): Int {
        store.rawQueryCount(table).use { cursor ->
            cursor.moveToFirst()
            return cursor.getInt(0)
        }
    }

    /** Maps the worker's GET /devices/:id/prekeys JSON to a libsignal PreKeyBundle. */
    fun fetchBundle(deviceId: String): PreKeyBundle {
        val state = store.requireAccountState()
        val bundle = client.request("GET", "/devices/$deviceId/prekeys", token = state.token)!!

        val signed = bundle.getJSONObject("signed_prekey")
        val oneTime = bundle.optJSONObject("one_time_prekey")
        val kyber = bundle.getJSONObject("kyber_prekey")
        val identityRaw = unB64(bundle.getString("identity_pub"))

        return PreKeyBundle(
            registrationId = bundle.getInt("registration_id"),
            deviceId = bundle.getInt("dev_no"),
            preKeyId = oneTime?.getInt("key_id") ?: PreKeyBundle.NULL_PRE_KEY_ID,
            preKeyPublic = oneTime?.let { ECPublicKey(unB64(it.getString("public_key"))) },
            signedPreKeyId = signed.getInt("key_id"),
            signedPreKeyPublic = ECPublicKey(unB64(signed.getString("public_key"))),
            signedPreKeySignature = unB64(signed.getString("signature")),
            identityKey = IdentityKey(ECPublicKey.fromPublicKeyBytes(identityRaw)),
            kyberPreKeyId = kyber.getInt("key_id"),
            kyberPreKeyPublic = org.signal.libsignal.protocol.kem.KEMPublicKey(unB64(kyber.getString("public_key"))),
            kyberPreKeySignature = unB64(kyber.getString("signature")),
        )
    }
}
