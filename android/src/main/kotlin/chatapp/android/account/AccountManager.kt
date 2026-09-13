package chatapp.android.account

import android.annotation.SuppressLint
import chatapp.android.crypto.SqlCipherProtocolStore
import chatapp.android.net.ChatApiClient
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.TinkProtoKeysetFormat
import com.google.crypto.tink.proto.Ed25519PrivateKey
import com.google.crypto.tink.proto.Keyset
import com.google.crypto.tink.signature.Ed25519Parameters
import com.google.crypto.tink.signature.PublicKeySignFactory
import com.google.crypto.tink.signature.SignatureConfig
import java.security.SecureRandom
import org.json.JSONObject

/**
 * Phase 4 — real account/device registration against the Cloudflare Worker
 * (design §4). The Ed25519 authentication keypair is generated with Tink and
 * its private keyset is stored ONLY inside the SQLCipher database (encrypted at
 * rest, AndroidKeyStore-wrapped passphrase) — never in prefs, logs, or Git.
 *
 * Challenge contexts are byte-identical to the Worker's buildContext (design §2):
 *   register:   v1|register|challenge_id|nonce|username|identity_pub|auth_pub
 *   add_device: v1|add_device|challenge_id|nonce|username|identity_pub|auth_pub|authorizer_device_id
 */
class AccountManager(
    private val client: ChatApiClient,
    private val store: SqlCipherProtocolStore,
) {

    /** 32-byte raw Ed25519 public key of the auth key (server expects raw 32B). */
    fun authPublicKeyB64(handle: KeysetHandle): String {
        val serialized = TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get())
        val keyset = Keyset.parseFrom(serialized)
        for (i in 0 until keyset.keyCount) {
            val keyData = keyset.getKey(i).keyData
            if (keyData.typeUrl.endsWith("Ed25519PrivateKey")) {
                val privateKey = Ed25519PrivateKey.parseFrom(keyData.value)
                return b64(privateKey.publicKey.keyValue.toByteArray())
            }
        }
        error("no Ed25519 key found in auth keyset")
    }

    /** Raw 32-byte libsignal identity public key (server expects raw 32B). */
    fun identityPublicKeyB64(): String =
        b64(store.identityKeyPair.publicKey.publicKey.publicKeyBytes)

    fun sign(handle: KeysetHandle, context: String): ByteArray {
        SignatureConfig.register()
        return PublicKeySignFactory.getPrimitive(handle).sign(context.toByteArray(Charsets.UTF_8))
    }

    private fun ensureAuthKeyset(): KeysetHandle {
        store.loadAuthKeyset()?.let {
            return TinkProtoKeysetFormat.parseKeyset(it, InsecureSecretKeyAccess.get())
        }
        SignatureConfig.register()
        val handle = KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(Ed25519Parameters.create())
                    .withRandomId()
                    .makePrimary(),
            )
            .build()
        store.saveAuthKeyset(TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get()))
        return handle
    }

    /**
     * Full real registration: challenge → sign → POST /accounts → persist state
     * + token inside SQLCipher. Returns the persisted account state.
     */
    fun register(username: String): SqlCipherProtocolStore.AccountState {
        check(store.loadAccountState() == null) { "device already registered" }
        val handle = ensureAuthKeyset()
        val identityPub = identityPublicKeyB64()
        val authPub = authPublicKeyB64(handle)

        val challenge = client.request(
            "POST",
            "/auth/challenge",
            body = JSONObject()
                .put("purpose", "register")
                .put("username", username)
                .put("identity_pub", identityPub)
                .put("auth_pub", authPub),
        )!!
        val context = listOf(
            "v1", "register", challenge.getString("challenge_id"), challenge.getString("nonce"),
            username, identityPub, authPub,
        ).joinToString("|")
        val signature = sign(handle, context)

        val reg = client.request(
            "POST",
            "/accounts",
            body = JSONObject()
                .put("challenge_id", challenge.getString("challenge_id"))
                .put("signature", b64(signature))
                .put("registration_id", store.localRegistrationId),
        )!!

        val state = SqlCipherProtocolStore.AccountState(
            accountId = reg.getString("account_id"),
            deviceId = reg.getString("device_id"),
            devNo = reg.getInt("dev_no"),
            registrationId = store.localRegistrationId,
            username = username,
            token = reg.getString("token"),
            tokenExpiresAt = reg.getLong("token_expires_at"),
            nextKeyId = SecureRandom().nextInt(16_000_000),
        )
        store.saveAccountState(state)
        return state
    }

    /**
     * add_device flow for a NEW device store (design §9): the new device solves
     * its own challenge and signs with its own auth key; the existing device
     * co-signs the SAME context as authorizer. accountId comes from the
     * authorizer's state (the POST /devices response does not include it).
     */
    fun addDevice(
        accountId: String,
        username: String,
        authorizerDeviceId: String,
        authorizerSignature: (context: String) -> ByteArray,
    ): SqlCipherProtocolStore.AccountState {
        check(store.loadAccountState() == null) { "device already registered" }
        val handle = ensureAuthKeyset()
        val identityPub = identityPublicKeyB64()
        val authPub = authPublicKeyB64(handle)

        val challenge = client.request(
            "POST",
            "/auth/challenge",
            body = JSONObject()
                .put("purpose", "add_device")
                .put("username", username)
                .put("identity_pub", identityPub)
                .put("auth_pub", authPub)
                .put("authorizer_device_id", authorizerDeviceId),
        )!!
        val context = listOf(
            "v1", "add_device", challenge.getString("challenge_id"), challenge.getString("nonce"),
            username, identityPub, authPub, authorizerDeviceId,
        ).joinToString("|")
        val signature = sign(handle, context)

        val added = client.request(
            "POST",
            "/devices",
            body = JSONObject()
                .put("challenge_id", challenge.getString("challenge_id"))
                .put("signature", b64(signature))
                .put("authorizer_signature", b64(authorizerSignature(context)))
                .put("registration_id", store.localRegistrationId),
        )!!

        // The account identity comes from the authorizer (per API contract).
        val state = SqlCipherProtocolStore.AccountState(
            accountId = accountId,
            deviceId = added.getString("device_id"),
            devNo = added.getInt("dev_no"),
            registrationId = store.localRegistrationId,
            username = username,
            token = added.getString("token"),
            tokenExpiresAt = added.getLong("token_expires_at"),
            nextKeyId = SecureRandom().nextInt(16_000_000),
        )
        store.saveAccountState(state)
        return state
    }

    /** The authorizer's signing closure, bound to THIS device's auth keyset. */
    fun authorizerSigner(): (String) -> ByteArray {
        val handle = checkNotNull(store.loadAuthKeyset()) { "no auth keyset stored" }
            .let { TinkProtoKeysetFormat.parseKeyset(it, InsecureSecretKeyAccess.get()) }
        return { context: String -> sign(handle, context) }
    }

    fun requireState(): SqlCipherProtocolStore.AccountState = store.requireAccountState()

    companion object {
        @SuppressLint("DefaultLocale")
        fun randomUsername(prefix: String = "u"): String {
            val alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
            val suffix = buildString {
                val rnd = SecureRandom()
                repeat(15) { append(alphabet[rnd.nextInt(alphabet.length)]) }
            }
            return "${prefix}_$suffix"
        }
    }
}

fun b64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

fun unB64(text: String): ByteArray = java.util.Base64.getDecoder().decode(text)
