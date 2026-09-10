package chatapp.prototype

import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.groups.state.SenderKeyStore
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.KyberPreKeyStore
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyStore
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SessionStore
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyStore
import java.security.SecureRandom
import java.util.UUID

/**
 * In-memory simulation of the future Room database. Every libsignal record is held
 * as opaque serialized bytes (exactly what will be stored in BLOB columns) and is
 * re-hydrated into a fresh object on every read. No live protocol objects are cached,
 * so a "restart" is just a new PersistedStore over the same DeviceDatabase.
 */
class DeviceDatabase(val deviceLabel: String) {
    var identityPair: ByteArray? = null
    var registrationId: Int = 0

    val remoteIdentities = mutableMapOf<String, ByteArray>()
    val sessions = mutableMapOf<String, ByteArray>()
    val preKeys = mutableMapOf<Int, ByteArray>()
    val signedPreKeys = mutableMapOf<Int, ByteArray>()
    val kyberPreKeys = mutableMapOf<Int, ByteArray>()
    val kyberUsedTuples = mutableSetOf<String>()
    val senderKeys = mutableMapOf<String, ByteArray>()

    fun sessionKey(name: String, deviceId: Int) = "$name:$deviceId"
}

class PersistedStore(private val db: DeviceDatabase) : SignalProtocolStore {

    companion object {
        fun createFresh(deviceLabel: String): Pair<DeviceDatabase, PersistedStore> {
            val db = DeviceDatabase(deviceLabel)
            val random = SecureRandom()
            db.registrationId = random.nextInt(16380) + 1 // documented range: 1..16380
            db.identityPair = IdentityKeyPair.generate().serialize()
            return db to PersistedStore(db)
        }
    }

    // ---- IdentityKeyStore (trust-on-first-use, per official javadoc) ----

    override fun getIdentityKeyPair(): IdentityKeyPair = IdentityKeyPair(db.identityPair!!)

    override fun getLocalRegistrationId(): Int = db.registrationId

    override fun saveIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
    ): IdentityKeyStore.IdentityChange {
        val bytes = identityKey.serialize()
        val previous = db.remoteIdentities.put(address.name, bytes)
        return if (previous != null && !previous.contentEquals(bytes)) {
            IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        } else {
            IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        }
    }

    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
        direction: IdentityKeyStore.Direction,
    ): Boolean {
        val previous = db.remoteIdentities[address.name] ?: return true
        return previous.contentEquals(identityKey.serialize())
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? =
        db.remoteIdentities[address.name]?.let { IdentityKey(it) }

    // ---- SessionStore ----

    override fun loadSession(address: SignalProtocolAddress): SessionRecord {
        val bytes = db.sessions[db.sessionKey(address.name, address.deviceId)]
        return if (bytes != null) SessionRecord(bytes) else SessionRecord()
    }

    override fun loadExistingSessions(addresses: MutableList<SignalProtocolAddress>): MutableList<SessionRecord> {
        return addresses.map { address ->
            val bytes = db.sessions[db.sessionKey(address.name, address.deviceId)]
                ?: throw NoSessionException(address, "no active session for ${address.name}.${address.deviceId}")
            SessionRecord(bytes)
        }.toMutableList()
    }

    override fun getSubDeviceSessions(name: String): MutableList<Int> {
        return db.sessions.keys
            .mapNotNull { key ->
                val idx = key.lastIndexOf(':')
                if (idx < 0) null else key.substring(0, idx) to key.substring(idx + 1).toInt()
            }
            .filter { (owner, _) -> owner == name }
            .map { (_, deviceId) -> deviceId }
            .toMutableList()
    }

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        db.sessions[db.sessionKey(address.name, address.deviceId)] = record.serialize()
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean =
        db.sessions.containsKey(db.sessionKey(address.name, address.deviceId))

    override fun deleteSession(address: SignalProtocolAddress) {
        db.sessions.remove(db.sessionKey(address.name, address.deviceId))
    }

    override fun deleteAllSessions(name: String) {
        db.sessions.keys.removeAll { it.startsWith("$name:") }
    }

    // ---- PreKeyStore ----

    override fun loadPreKey(preKeyId: Int): PreKeyRecord =
        db.preKeys[preKeyId]?.let { PreKeyRecord(it) }
            ?: throw InvalidKeyIdException("no such prekey $preKeyId")

    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
        db.preKeys[preKeyId] = record.serialize()
    }

    override fun containsPreKey(preKeyId: Int): Boolean = db.preKeys.containsKey(preKeyId)

    override fun removePreKey(preKeyId: Int) {
        db.preKeys.remove(preKeyId)
    }

    // ---- SignedPreKeyStore ----

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord =
        db.signedPreKeys[signedPreKeyId]?.let { SignedPreKeyRecord(it) }
            ?: throw InvalidKeyIdException("no such signed prekey $signedPreKeyId")

    override fun loadSignedPreKeys(): MutableList<SignedPreKeyRecord> =
        db.signedPreKeys.values.map { SignedPreKeyRecord(it) }.toMutableList()

    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
        db.signedPreKeys[signedPreKeyId] = record.serialize()
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean =
        db.signedPreKeys.containsKey(signedPreKeyId)

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        db.signedPreKeys.remove(signedPreKeyId)
    }

    // ---- KyberPreKeyStore ----

    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord =
        db.kyberPreKeys[kyberPreKeyId]?.let { KyberPreKeyRecord(it) }
            ?: throw InvalidKeyIdException("no such kyber prekey $kyberPreKeyId")

    override fun loadKyberPreKeys(): MutableList<KyberPreKeyRecord> =
        db.kyberPreKeys.values.map { KyberPreKeyRecord(it) }.toMutableList()

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) {
        db.kyberPreKeys[kyberPreKeyId] = record.serialize()
    }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean =
        db.kyberPreKeys.containsKey(kyberPreKeyId)

    override fun markKyberPreKeyUsed(
        kyberPreKeyId: Int,
        signedPreKeyId: Int,
        baseKey: org.signal.libsignal.protocol.ecc.ECPublicKey,
    ) {
        val tuple = "$kyberPreKeyId:$signedPreKeyId:${baseKey.serialize().joinToString("") { "%02x".format(it) }}"
        if (!db.kyberUsedTuples.add(tuple)) {
            throw ReusedBaseKeyException("kyber tuple already used: $tuple")
        }
        // One-time semantics: consume (remove) the kyber prekey after use.
        db.kyberPreKeys.remove(kyberPreKeyId)
    }

    // ---- SenderKeyStore (required by SignalProtocolStore; groups are out of MVP scope) ----

    private fun senderKeyKey(sender: SignalProtocolAddress, distributionId: UUID) =
        "${sender.name}:${sender.deviceId}:$distributionId"

    override fun storeSenderKey(
        sender: SignalProtocolAddress,
        distributionId: UUID,
        record: SenderKeyRecord,
    ) {
        db.senderKeys[senderKeyKey(sender, distributionId)] = record.serialize()
    }

    override fun loadSenderKey(
        sender: SignalProtocolAddress,
        distributionId: UUID,
    ): SenderKeyRecord? =
        db.senderKeys[senderKeyKey(sender, distributionId)]?.let { SenderKeyRecord(it) }
}
