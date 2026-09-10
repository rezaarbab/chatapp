package chatapp.android.crypto

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/**
 * Phase 0.5-B: proves on a real Android environment that
 *  - libsignal-android 0.102.1 native code loads and the full protocol works on device,
 *  - the protocol store persists inside a SQLCipher-encrypted database,
 *  - the database passphrase is protected by a non-exportable AndroidKeyStore key,
 *  - sessions survive an app restart (DB close + reopen + re-unwrap).
 */
@RunWith(AndroidJUnit4::class)
class CryptoOnDeviceTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    private class Device(
        private val context: Context,
        label: String,
        private val alias: String,
        name: String,
        deviceId: Int,
    ) {
        private val dbFile: File = context.getDatabasePath("proto_$label.db")
        lateinit var store: SqlCipherProtocolStore
            private set
        val address = SignalProtocolAddress(name, deviceId)

        fun open() {
            val passphrase = DatabaseKeyManager.getOrCreatePassphrase(context, alias)
            store = SqlCipherProtocolStore.open(dbFile, passphrase)
        }

        fun close() = store.close()

        fun generatePreKeyMaterial() {
            val now = System.currentTimeMillis()
            val identity = store.identityKeyPair

            val signedPair = ECKeyPair.generate()
            val signedSignature = identity.privateKey.calculateSignature(signedPair.publicKey.serialize())
            store.storeSignedPreKey(1, SignedPreKeyRecord(1, now, signedPair, signedSignature))

            val kem100 = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            store.storeKyberPreKey(100, KyberPreKeyRecord(100, now, kem100, identity.privateKey.calculateSignature(kem100.publicKey.serialize())))

            val kem101 = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            store.storeKyberPreKey(101, KyberPreKeyRecord(101, now, kem101, identity.privateKey.calculateSignature(kem101.publicKey.serialize())))
        }

        fun storeOneTimeEcPreKey(id: Int): PreKeyRecord {
            val record = PreKeyRecord(id, ECKeyPair.generate())
            store.storePreKey(id, record)
            return record
        }

        fun buildBundle(oneTimeEc: PreKeyRecord? = null, oneTimeKyberId: Int = 100): PreKeyBundle {
            val signed = store.loadSignedPreKey(1)
            val kem = store.loadKyberPreKey(oneTimeKyberId)
            return PreKeyBundle(
                registrationId = store.localRegistrationId,
                deviceId = deviceId,
                preKeyId = oneTimeEc?.id ?: PreKeyBundle.NULL_PRE_KEY_ID,
                preKeyPublic = oneTimeEc?.keyPair?.publicKey,
                signedPreKeyId = signed.id,
                signedPreKeyPublic = signed.keyPair.publicKey,
                signedPreKeySignature = signed.signature,
                identityKey = store.identityKeyPair.publicKey,
                kyberPreKeyId = kem.id,
                kyberPreKeyPublic = kem.keyPair.publicKey,
                kyberPreKeySignature = kem.signature,
            )
        }

        fun cipherFor(remote: Device): SessionCipher = SessionCipher(store, address, remote.address)

        fun builderFor(remote: Device): SessionBuilder = SessionBuilder(store, remote.address, address)
    }

    private fun assertFileIsNotPlaintextSqlite(file: File) {
        assertTrue("database file does not exist: $file", file.exists())
        val header = file.inputStream().use { stream ->
            val buffer = ByteArray(16)
            var read = 0
            while (read < buffer.size) {
                val n = stream.read(buffer, read, buffer.size - read)
                if (n < 0) break
                read += n
            }
            buffer.copyOf(read)
        }
        val sqliteMagic = "SQLite format 3".toByteArray(Charsets.US_ASCII)
        assertFalse(
            "database file starts with plaintext SQLite magic — encryption is not active",
            header.copyOfRange(0, minOf(sqliteMagic.size, header.size))
                .contentEquals(sqliteMagic.copyOf(minOf(sqliteMagic.size, header.size))),
        )
    }

    @Test
    fun `keystore wrapped passphrase reopens encrypted database after restart`() {
        val alice = Device(context, "alice", "alias_alice_a", "alice", 1)
        val bob = Device(context, "bob", "alias_bob_a", "bob", 1)
        alice.open()
        bob.open()
        bob.generatePreKeyMaterial()

        alice.builderFor(bob).process(bob.buildBundle(oneTimeEc = bob.storeOneTimeEcPreKey(200)))

        val first = alice.cipherFor(bob).encrypt("before restart".toByteArray())
        assertEquals(CiphertextMessage.PREKEY_TYPE, first.type)
        bob.cipherFor(alice).decrypt(PreKeySignalMessage(first.serialize()))

        // Acknowledge the session so the sender side is confirmed before restart.
        val ack = bob.cipherFor(alice).encrypt("ack".toByteArray())
        alice.cipherFor(bob).decrypt(SignalMessage(ack.serialize()))

        assertFileIsNotPlaintextSqlite(context.getDatabasePath("proto_alice.db"))
        assertFileIsNotPlaintextSqlite(context.getDatabasePath("proto_bob.db"))

        alice.close()
        bob.close()

        // Simulate process restart: DB is reopened and the passphrase is unwrapped
        // again from AndroidKeyStore (never stored in plaintext).
        alice.open()
        bob.open()

        val after = alice.cipherFor(bob).encrypt("after restart".toByteArray())
        assertEquals(CiphertextMessage.WHISPER_TYPE, after.type)
        val plaintext = bob.cipherFor(alice).decrypt(SignalMessage(after.serialize()))
        assertEquals("after restart", String(plaintext))

        assertTrue(DatabaseKeyManager.keystoreContainsAlias("alias_alice_a"))
        assertTrue(DatabaseKeyManager.keystoreContainsAlias("alias_bob_a"))

        alice.close()
        bob.close()
    }

    @Test
    fun `one-time prekeys are consumed after first decrypt`() {
        val alice = Device(context, "alice2", "alias_alice_b", "alice", 1)
        val bob = Device(context, "bob2", "alias_bob_b", "bob", 1)
        alice.open()
        bob.open()
        bob.generatePreKeyMaterial()

        alice.builderFor(bob).process(bob.buildBundle(oneTimeEc = bob.storeOneTimeEcPreKey(201), oneTimeKyberId = 100))

        val ciphertext = alice.cipherFor(bob).encrypt("consume".toByteArray())
        bob.cipherFor(alice).decrypt(PreKeySignalMessage(ciphertext.serialize()))

        assertFalse(bob.store.containsPreKey(201))
        assertFalse(bob.store.containsKyberPreKey(100))
        assertTrue(bob.store.containsKyberPreKey(101))

        // Identity keys persisted on device match what the sender trusted.
        assertArrayEquals(
            bob.store.identityKeyPair.publicKey.serialize(),
            alice.store.getIdentity(bob.address)!!.serialize(),
        )

        alice.close()
        bob.close()
    }
}
