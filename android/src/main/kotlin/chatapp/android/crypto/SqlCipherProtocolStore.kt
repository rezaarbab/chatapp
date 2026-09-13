package chatapp.android.crypto

import android.content.ContentValues
import android.database.Cursor
import java.io.File
import java.security.SecureRandom
import net.zetetic.database.DatabaseErrorHandler
import net.zetetic.database.sqlcipher.SQLiteDatabase
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
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

/**
 * libsignal protocol store backed by a SQLCipher database. Every record is stored
 * as the official serialized bytes of the libsignal object (same pattern planned
 * for Room in Phase 6 and for the server-side schema).
 */
class SqlCipherProtocolStore(private val db: SQLiteDatabase) :
    SignalProtocolStore {

    companion object {
        private val DDL = listOf(
            "CREATE TABLE IF NOT EXISTS identity (" +
                "id INTEGER PRIMARY KEY CHECK (id = 1), " +
                "identity_pair BLOB NOT NULL, " +
                "registration_id INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS remote_identities (" +
                "name TEXT PRIMARY KEY, " +
                "key BLOB NOT NULL)",
            "CREATE TABLE IF NOT EXISTS sessions (" +
                "name TEXT NOT NULL, " +
                "device_id INTEGER NOT NULL, " +
                "record BLOB NOT NULL, " +
                "PRIMARY KEY (name, device_id))",
            "CREATE TABLE IF NOT EXISTS prekeys (" +
                "key_id INTEGER PRIMARY KEY, " +
                "record BLOB NOT NULL)",
            "CREATE TABLE IF NOT EXISTS signed_prekeys (" +
                "key_id INTEGER PRIMARY KEY, " +
                "record BLOB NOT NULL)",
            "CREATE TABLE IF NOT EXISTS kyber_prekeys (" +
                "key_id INTEGER PRIMARY KEY, " +
                "record BLOB NOT NULL)",
            "CREATE TABLE IF NOT EXISTS kyber_used_tuples (" +
                "tuple TEXT PRIMARY KEY)",
            "CREATE TABLE IF NOT EXISTS sender_keys (" +
                "name TEXT NOT NULL, " +
                "device_id INTEGER NOT NULL, " +
                "distribution_id TEXT NOT NULL, " +
                "record BLOB NOT NULL, " +
                "PRIMARY KEY (name, device_id, distribution_id))",
            // Phase 4 additive tables (design §8): account/token state, the Tink
            // auth keyset, and the local plaintext mirror (crash-safe ACK order).
            // All live inside the same SQLCipher database (encrypted at rest).
            "CREATE TABLE IF NOT EXISTS account_state (" +
                "id INTEGER PRIMARY KEY CHECK (id = 1), " +
                "account_id TEXT NOT NULL, " +
                "device_id TEXT NOT NULL, " +
                "dev_no INTEGER NOT NULL, " +
                "registration_id INTEGER NOT NULL, " +
                "username TEXT NOT NULL, " +
                "token TEXT NOT NULL, " +
                "token_expires_at INTEGER NOT NULL, " +
                "next_key_id INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS auth_keyset (" +
                "id INTEGER PRIMARY KEY CHECK (id = 1), " +
                "keyset BLOB NOT NULL)",
            "CREATE TABLE IF NOT EXISTS messages (" +
                "delivery_id TEXT PRIMARY KEY, " +
                "logical_msg_id TEXT NOT NULL, " +
                "sender_account_id TEXT NOT NULL, " +
                "sender_dev_no INTEGER NOT NULL, " +
                "seq INTEGER NOT NULL, " +
                "plaintext BLOB NOT NULL, " +
                "received_at INTEGER NOT NULL)",
        )

        fun open(file: File, passphrase: ByteArray): SqlCipherProtocolStore {
            System.loadLibrary("sqlcipher")
            val db = SQLiteDatabase.openOrCreateDatabase(
                file,
                passphrase,
                null as SQLiteDatabase.CursorFactory?,
                null as DatabaseErrorHandler?,
            )
            val store = SqlCipherProtocolStore(db)
            store.ensureSchema()
            store.ensureFreshIdentity()
            return store
        }
    }

    fun close() = db.close()

    fun isOpen(): Boolean = db.isOpen

    private fun ensureSchema() = DDL.forEach(db::execSQL)

    private fun ensureFreshIdentity() {
        val existing = queryOne("SELECT identity_pair, registration_id FROM identity WHERE id = 1")
        if (existing == null) {
            val pair = IdentityKeyPair.generate()
            val values = ContentValues().apply {
                put("id", 1)
                put("identity_pair", pair.serialize())
                put("registration_id", SecureRandom().nextInt(16380) + 1)
            }
            db.insert("identity", SQLiteDatabase.CONFLICT_REPLACE, values)
        }
    }

    private fun queryOne(sql: String, vararg args: Any?): Cursor? {
        val cursor = if (args.isEmpty()) db.rawQuery(sql) else db.rawQuery(sql, *args)
        return if (cursor.moveToFirst()) cursor else cursor.close().let { null }
    }

    // ---- IdentityKeyStore (trust-on-first-use) ----

    override fun getIdentityKeyPair(): IdentityKeyPair {
        queryOne("SELECT identity_pair FROM identity WHERE id = 1").use { cursor ->
            checkNotNull(cursor) { "identity row missing" }
            return IdentityKeyPair(cursor.getBlob(0))
        }
    }

    override fun getLocalRegistrationId(): Int {
        queryOne("SELECT registration_id FROM identity WHERE id = 1").use { cursor ->
            checkNotNull(cursor) { "identity row missing" }
            return cursor.getInt(0)
        }
    }

    override fun saveIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
    ): IdentityKeyStore.IdentityChange {
        val bytes = identityKey.serialize()
        val previous = queryOne("SELECT key FROM remote_identities WHERE name = ?", address.name)?.use { it.getBlob(0) }
        val values = ContentValues().apply {
            put("name", address.name)
            put("key", bytes)
        }
        db.insert("remote_identities", SQLiteDatabase.CONFLICT_REPLACE, values)
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
        queryOne("SELECT key FROM remote_identities WHERE name = ?", address.name).use { cursor ->
            if (cursor == null) return true
            return cursor.getBlob(0).contentEquals(identityKey.serialize())
        }
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? {
        queryOne("SELECT key FROM remote_identities WHERE name = ?", address.name).use { cursor ->
            if (cursor == null) return null
            return IdentityKey(cursor.getBlob(0))
        }
    }

    // ---- SessionStore ----

    override fun loadSession(address: SignalProtocolAddress): SessionRecord {
        queryOne(
            "SELECT record FROM sessions WHERE name = ? AND device_id = ?",
            address.name, address.deviceId.toLong(),
        ).use { cursor ->
            if (cursor == null) return SessionRecord()
            return SessionRecord(cursor.getBlob(0))
        }
    }

    override fun loadExistingSessions(addresses: MutableList<SignalProtocolAddress>): MutableList<SessionRecord> {
        return addresses.map { address ->
            queryOne(
                "SELECT record FROM sessions WHERE name = ? AND device_id = ?",
                address.name, address.deviceId.toLong(),
            ).use { cursor ->
                cursor ?: throw NoSessionException(address, "no session for $address")
                SessionRecord(cursor.getBlob(0))
            }
        }.toMutableList()
    }

    override fun getSubDeviceSessions(name: String): MutableList<Int> {
        val cursor = db.rawQuery(
            "SELECT device_id FROM sessions WHERE name = ?",
            *arrayOf<Any?>(name),
        )
        val result = mutableListOf<Int>()
        cursor.use { c ->
            while (c.moveToNext()) result.add(c.getInt(0))
        }
        return result
    }

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        val values = ContentValues().apply {
            put("name", address.name)
            put("device_id", address.deviceId)
            put("record", record.serialize())
        }
        db.insert("sessions", SQLiteDatabase.CONFLICT_REPLACE, values)
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean {
        queryOne(
            "SELECT 1 FROM sessions WHERE name = ? AND device_id = ?",
            address.name, address.deviceId.toLong(),
        ).use { return it != null }
    }

    override fun deleteSession(address: SignalProtocolAddress) {
        db.delete(
            "sessions",
            "name = ? AND device_id = ?",
            arrayOf<Any?>(address.name, address.deviceId),
        )
    }

    override fun deleteAllSessions(name: String) {
        db.delete("sessions", "name = ?", arrayOf<Any?>(name))
    }

    // ---- PreKeyStore ----

    override fun loadPreKey(preKeyId: Int): PreKeyRecord {
        queryOne("SELECT record FROM prekeys WHERE key_id = ?", preKeyId.toLong()).use { cursor ->
            cursor ?: throw InvalidKeyIdException("no such prekey $preKeyId")
            return PreKeyRecord(cursor.getBlob(0))
        }
    }

    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
        val values = ContentValues().apply {
            put("key_id", preKeyId)
            put("record", record.serialize())
        }
        db.insert("prekeys", SQLiteDatabase.CONFLICT_REPLACE, values)
    }

    override fun containsPreKey(preKeyId: Int): Boolean {
        queryOne("SELECT 1 FROM prekeys WHERE key_id = ?", preKeyId.toLong()).use { return it != null }
    }

    override fun removePreKey(preKeyId: Int) {
        db.delete("prekeys", "key_id = ?", arrayOf<Any?>(preKeyId))
    }

    // ---- SignedPreKeyStore ----

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord {
        queryOne("SELECT record FROM signed_prekeys WHERE key_id = ?", signedPreKeyId.toLong()).use { cursor ->
            cursor ?: throw InvalidKeyIdException("no such signed prekey $signedPreKeyId")
            return SignedPreKeyRecord(cursor.getBlob(0))
        }
    }

    override fun loadSignedPreKeys(): MutableList<SignedPreKeyRecord> {
        val result = mutableListOf<SignedPreKeyRecord>()
        val cursor = db.rawQuery("SELECT record FROM signed_prekeys")
        cursor.use { c ->
            while (c.moveToNext()) result.add(SignedPreKeyRecord(c.getBlob(0)))
        }
        return result
    }

    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
        val values = ContentValues().apply {
            put("key_id", signedPreKeyId)
            put("record", record.serialize())
        }
        db.insert("signed_prekeys", SQLiteDatabase.CONFLICT_REPLACE, values)
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean {
        queryOne("SELECT 1 FROM signed_prekeys WHERE key_id = ?", signedPreKeyId.toLong()).use { return it != null }
    }

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        db.delete("signed_prekeys", "key_id = ?", arrayOf<Any?>(signedPreKeyId))
    }

    // ---- KyberPreKeyStore ----

    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord {
        queryOne("SELECT record FROM kyber_prekeys WHERE key_id = ?", kyberPreKeyId.toLong()).use { cursor ->
            cursor ?: throw InvalidKeyIdException("no such kyber prekey $kyberPreKeyId")
            return KyberPreKeyRecord(cursor.getBlob(0))
        }
    }

    override fun loadKyberPreKeys(): MutableList<KyberPreKeyRecord> {
        val result = mutableListOf<KyberPreKeyRecord>()
        val cursor = db.rawQuery("SELECT record FROM kyber_prekeys")
        cursor.use { c ->
            while (c.moveToNext()) result.add(KyberPreKeyRecord(c.getBlob(0)))
        }
        return result
    }

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) {
        val values = ContentValues().apply {
            put("key_id", kyberPreKeyId)
            put("record", record.serialize())
        }
        db.insert("kyber_prekeys", SQLiteDatabase.CONFLICT_REPLACE, values)
    }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean {
        queryOne("SELECT 1 FROM kyber_prekeys WHERE key_id = ?", kyberPreKeyId.toLong()).use { return it != null }
    }

    override fun markKyberPreKeyUsed(
        kyberPreKeyId: Int,
        signedPreKeyId: Int,
        baseKey: org.signal.libsignal.protocol.ecc.ECPublicKey,
    ) {
        val tuple = "$kyberPreKeyId:$signedPreKeyId:" +
            baseKey.serialize().joinToString("") { "%02x".format(it) }
        val values = ContentValues().apply { put("tuple", tuple) }
        val inserted = db.insert("kyber_used_tuples", SQLiteDatabase.CONFLICT_IGNORE, values)
        if (inserted == -1L) {
            throw ReusedBaseKeyException("kyber tuple already used: $tuple")
        }
        db.delete("kyber_prekeys", "key_id = ?", arrayOf<Any?>(kyberPreKeyId))
    }

    // ---- SenderKeyStore (required by SignalProtocolStore; groups out of MVP scope) ----

    override fun storeSenderKey(
        sender: SignalProtocolAddress,
        distributionId: java.util.UUID,
        record: SenderKeyRecord,
    ) {
        val values = ContentValues().apply {
            put("name", sender.name)
            put("device_id", sender.deviceId)
            put("distribution_id", distributionId.toString())
            put("record", record.serialize())
        }
        db.insert("sender_keys", SQLiteDatabase.CONFLICT_REPLACE, values)
    }

    override fun loadSenderKey(
        sender: SignalProtocolAddress,
        distributionId: java.util.UUID,
    ): SenderKeyRecord? {
        queryOne(
            "SELECT record FROM sender_keys WHERE name = ? AND device_id = ? AND distribution_id = ?",
            sender.name, sender.deviceId.toLong(), distributionId.toString(),
        ).use { cursor ->
            if (cursor == null) return null
            return SenderKeyRecord(cursor.getBlob(0))
        }
    }

    // ---- Phase 4: account state / auth keyset / local message mirror ----

    data class AccountState(
        val accountId: String,
        val deviceId: String,
        val devNo: Int,
        val registrationId: Int,
        val username: String,
        val token: String,
        val tokenExpiresAt: Long,
        var nextKeyId: Int,
    )

    fun saveAccountState(state: AccountState) {
        val values = ContentValues().apply {
            put("id", 1)
            put("account_id", state.accountId)
            put("device_id", state.deviceId)
            put("dev_no", state.devNo)
            put("registration_id", state.registrationId)
            put("username", state.username)
            put("token", state.token)
            put("token_expires_at", state.tokenExpiresAt)
            put("next_key_id", state.nextKeyId)
        }
        db.insert("account_state", SQLiteDatabase.CONFLICT_REPLACE, values)
    }

    fun loadAccountState(): AccountState? {
        queryOne("SELECT account_id, device_id, dev_no, registration_id, username, token, token_expires_at, next_key_id FROM account_state WHERE id = 1").use { c ->
            if (c == null) return null
            val state = AccountState(
                accountId = c.getString(0),
                deviceId = c.getString(1),
                devNo = c.getInt(2),
                registrationId = c.getInt(3),
                username = c.getString(4),
                token = c.getString(5),
                tokenExpiresAt = c.getLong(6),
                nextKeyId = c.getInt(7),
            )
            return state
        }
    }

    fun requireAccountState(): AccountState =
        checkNotNull(loadAccountState()) { "device not registered" }

    /** Internal counters only; table names are code constants, never input. */
    fun rawQueryCount(table: String): Cursor = db.rawQuery("SELECT COUNT(*) FROM $table")

    fun saveAuthKeyset(keyset: ByteArray) {
        val values = ContentValues().apply {
            put("id", 1)
            put("keyset", keyset)
        }
        db.insert("auth_keyset", SQLiteDatabase.CONFLICT_REPLACE, values)
    }

    fun loadAuthKeyset(): ByteArray? {
        queryOne("SELECT keyset FROM auth_keyset WHERE id = 1").use { c ->
            if (c == null) return null
            return c.getBlob(0)
        }
    }

    /** Allocates a device-unique, never-reused prekey id (persisted counter). */
    fun nextPreKeyId(): Int {
        val state = checkNotNull(loadAccountState()) { "account_state missing" }
        val id = state.nextKeyId
        state.nextKeyId += 1
        check(state.nextKeyId <= 16_777_215) { "prekey id space exhausted" }
        saveAccountState(state)
        return id
    }

    fun insertMessage(
        deliveryId: String,
        logicalMsgId: String,
        senderAccountId: String,
        senderDevNo: Int,
        seq: Long,
        plaintext: ByteArray,
        receivedAt: Long,
    ) {
        val values = ContentValues().apply {
            put("delivery_id", deliveryId)
            put("logical_msg_id", logicalMsgId)
            put("sender_account_id", senderAccountId)
            put("sender_dev_no", senderDevNo)
            put("seq", seq)
            put("plaintext", plaintext)
            put("received_at", receivedAt)
        }
        db.insert("messages", SQLiteDatabase.CONFLICT_IGNORE, values)
    }

    fun countMessages(): Int {
        queryOne("SELECT COUNT(*) FROM messages").use { c ->
            checkNotNull(c) { "messages table missing" }
            return c.getInt(0)
        }
    }
}
