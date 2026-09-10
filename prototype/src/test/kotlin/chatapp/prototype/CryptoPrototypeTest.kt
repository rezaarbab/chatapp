package chatapp.prototype

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.UntrustedIdentityException
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.ReusedBaseKeyException
import org.signal.libsignal.protocol.state.KyberPreKeyRecord

/**
 * Phase 0.5 prototype: proves the real libsignal 0.102.1 API supports the project model
 * (device-level identity, PQXDH prekeys, per-device sessions, serialized persistence).
 */
class CryptoPrototypeTest {

    private class Device(val name: String, val deviceId: Int) {
        val db: DeviceDatabase
        val store: PersistedStore
        val address = SignalProtocolAddress(name, deviceId)

        init {
            val (db, store) = PersistedStore.createFresh("$name.$deviceId")
            this.db = db
            this.store = store
        }

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

        fun buildBundle(
            oneTimeEc: PreKeyRecord? = null,
            oneTimeKyberId: Int = 100,
        ): PreKeyBundle {
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

        fun cipherFor(remote: Device): SessionCipher =
            SessionCipher(store, address, remote.address)

        fun builderFor(remote: Device): SessionBuilder =
            SessionBuilder(store, remote.address, address)
    }

    @Test
    fun `identity keypair survives serialize-deserialize roundtrip`() {
        val (_, store) = PersistedStore.createFresh("identity-test")
        val original = store.identityKeyPair
        val restored = IdentityKeyPair(original.serialize())
        assertArrayEquals(original.publicKey.serialize(), restored.publicKey.serialize())
        assertArrayEquals(
            original.privateKey.calculateSignature("msg".toByteArray()),
            restored.privateKey.calculateSignature("msg".toByteArray()),
        )
        assertTrue(store.localRegistrationId in 1..16380)
    }

    @Test
    fun `full session establishment and exchange over prekey bundle`() {
        val alice = Device("alice", 1)
        val bob = Device("bob", 1)
        bob.generatePreKeyMaterial()
        val oneTime = bob.storeOneTimeEcPreKey(200)
        val oneTimeKyberId = 100

        alice.builderFor(bob).process(bob.buildBundle(oneTimeEc = oneTime, oneTimeKyberId = oneTimeKyberId))

        val ciphertext = alice.cipherFor(bob).encrypt("hello bob".toByteArray())
        assertEquals(CiphertextMessage.PREKEY_TYPE, ciphertext.type)

        val plaintext = bob.cipherFor(alice).decrypt(PreKeySignalMessage(ciphertext.serialize()))
        assertEquals("hello bob", String(plaintext))

        // One-time keys are consumed on decrypt (server-side analog: atomic pop on fetch)
        assertFalse(bob.store.containsPreKey(200))
        assertFalse(bob.store.containsKyberPreKey(oneTimeKyberId))
        assertTrue(bob.store.containsKyberPreKey(101))
    }

    @Test
    fun `follow-up messages use whisper type both directions`() {
        val alice = Device("alice", 2)
        val bob = Device("bob", 2)
        bob.generatePreKeyMaterial()

        alice.builderFor(bob).process(bob.buildBundle(oneTimeEc = bob.storeOneTimeEcPreKey(201)))

        val m1 = alice.cipherFor(bob).encrypt("one".toByteArray())
        bob.cipherFor(alice).decrypt(PreKeySignalMessage(m1.serialize()))

        val m2 = alice.cipherFor(bob).encrypt("two".toByteArray())
        assertEquals(CiphertextMessage.WHISPER_TYPE, m2.type)
        assertEquals("two", String(bob.cipherFor(alice).decrypt(SignalMessage(m2.serialize()))))

        val reply = bob.cipherFor(alice).encrypt("hi alice".toByteArray())
        assertEquals("hi alice", String(alice.cipherFor(bob).decrypt(SignalMessage(reply.serialize()))))
    }

    @Test
    fun `replaying the same ciphertext is rejected`() {
        val alice = Device("alice", 3)
        val bob = Device("bob", 3)
        bob.generatePreKeyMaterial()

        alice.builderFor(bob).process(bob.buildBundle(oneTimeEc = bob.storeOneTimeEcPreKey(202)))

        val sent = alice.cipherFor(bob).encrypt("replay-me".toByteArray())
        bob.cipherFor(alice).decrypt(PreKeySignalMessage(sent.serialize()))

        assertThrows<DuplicateMessageException> {
            bob.cipherFor(alice).decrypt(PreKeySignalMessage(sent.serialize()))
        }
    }

    @Test
    fun `session state persists across a simulated restart`() {
        val alice1 = Device("alice", 4)
        val bob1 = Device("bob", 4)
        bob1.generatePreKeyMaterial()

        alice1.builderFor(bob1).process(bob1.buildBundle(oneTimeEc = bob1.storeOneTimeEcPreKey(203)))
        val sent = alice1.cipherFor(bob1).encrypt("before restart".toByteArray())
        bob1.cipherFor(alice1).decrypt(PreKeySignalMessage(sent.serialize()))

        // Simulate app restart: brand-new Java objects hydrated from the same persisted bytes.
        val aliceStore2 = PersistedStore(alice1.db)
        val bobStore2 = PersistedStore(bob1.db)
        val aliceAddr = SignalProtocolAddress("alice", 4)
        val bobAddr = SignalProtocolAddress("bob", 4)

        val cipherAlice = SessionCipher(aliceStore2, aliceAddr, bobAddr)
        val cipherBob = SessionCipher(bobStore2, bobAddr, aliceAddr)

        val m = cipherAlice.encrypt("after restart".toByteArray())
        assertEquals(CiphertextMessage.WHISPER_TYPE, m.type)
        assertEquals("after restart", String(cipherBob.decrypt(SignalMessage(m.serialize()))))
    }

    @Test
    fun `bundle without one-time EC prekey still works via signed and kyber keys`() {
        val alice = Device("alice", 5)
        val bob = Device("bob", 5)
        bob.generatePreKeyMaterial()

        // Server popped all one-time EC prekeys; bundle only carries signed + kyber prekey.
        alice.builderFor(bob).process(bob.buildBundle(oneTimeEc = null, oneTimeKyberId = 101))

        val ciphertext = alice.cipherFor(bob).encrypt("no one-time ec".toByteArray())
        assertEquals(CiphertextMessage.PREKEY_TYPE, ciphertext.type)
        val plaintext = bob.cipherFor(alice).decrypt(PreKeySignalMessage(ciphertext.serialize()))
        assertEquals("no one-time ec", String(plaintext))
        assertFalse(bob.store.containsKyberPreKey(101))
    }

    @Test
    fun `identity change after trust is rejected`() {
        val alice = Device("alice", 6)
        val bob = Device("bob", 6)
        val bobTwin = Device("bob", 6)
        bob.generatePreKeyMaterial()
        bobTwin.generatePreKeyMaterial()

        alice.builderFor(bob).process(bob.buildBundle(oneTimeEc = bob.storeOneTimeEcPreKey(204)))

        // A different device claiming the same name presents a different identity key.
        assertThrows<UntrustedIdentityException> {
            alice.builderFor(bobTwin).process(bobTwin.buildBundle())
        }
    }

    @Test
    fun `kyber prekey tuple reuse is detected by the store`() {
        val (db, store) = PersistedStore.createFresh("kyber-test")
        val now = System.currentTimeMillis()
        val identity = store.identityKeyPair
        val kem = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        store.storeKyberPreKey(300, KyberPreKeyRecord(300, now, kem, identity.privateKey.calculateSignature(kem.publicKey.serialize())))

        val base = ECKeyPair.generate().publicKey
        store.markKyberPreKeyUsed(300, 1, base)
        assertThrows<ReusedBaseKeyException> {
            store.markKyberPreKeyUsed(300, 1, base)
        }
    }
}
