package chatapp.android.crypto

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.TinkProtoKeysetFormat
import com.google.crypto.tink.PublicKeySign
import com.google.crypto.tink.PublicKeyVerify
import com.google.crypto.tink.proto.Ed25519PrivateKey
import com.google.crypto.tink.proto.Keyset
import com.google.crypto.tink.signature.Ed25519Parameters
import com.google.crypto.tink.signature.SignatureConfig
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Tink → WebCrypto interoperability fixture producer (user-mandated gate).
 *
 * Generates a real Ed25519 keypair with Google Tink on an Android device,
 * signs the canonical challenge context bytes (design doc §13.5), and exports
 * the raw public key (32 B) and raw signature (64 B) as base64 in a fixture
 * file. The fixture is verified inside the real workerd runtime by
 * backend/worker/test/interop.spec.ts with the official WebCrypto API.
 * No key conversion, no re-encoding: raw bytes → base64 → raw bytes.
 */
@RunWith(AndroidJUnit4::class)
class AuthInteropInstrumentedTest {

    @Test
    fun tinkSignsChallengeContextForWebCryptoVerification() {
        val context = InstrumentationRegistry.getInstrumentation().context

        // 0. Register Ed25519 key managers (official entry point in tink-android 1.23).
        SignatureConfig.register()

        // 1. Ed25519 keypair via Tink — NO_PREFIX variant ⇒ raw 64-byte signatures.
        val handle = KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParameters(Ed25519Parameters.create()))
            .build()

        // 2. Export the raw Ed25519 public key (32 bytes) from the keyset proto.
        val serialized = TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get())
        val keyset = Keyset.parseFrom(serialized)
        var pubBytes: ByteArray? = null
        for (i in 0 until keyset.keyCount) {
            val keyData = keyset.getKey(i).keyData
            if (keyData.typeUrl.endsWith("Ed25519PrivateKey")) {
                val privateKey = Ed25519PrivateKey.parseFrom(keyData.value)
                pubBytes = privateKey.publicKey.keyValue.toByteArray()
            }
        }
        checkNotNull(pubBytes) { "no Ed25519 key found in keyset" }
        assertEquals(32, pubBytes.size)
        val authPubB64 = Base64.encodeToString(pubBytes, Base64.NO_WRAP)

        // 3. Canonical challenge context (identical construction to Worker §13.5).
        val challengeId = "6f0a9b3e-8d9c-4f2a-9b1e-5c7d8e9f0a1b"
        val nonce = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val username = "alice"
        val identityPubB64 = "Zm9vYmFyYmF6cXV1eGZvb2JhcmJhenF1dXg="
        val contextString = listOf(
            "v1", "register", challengeId, nonce, username, identityPubB64, authPubB64,
        ).joinToString("|")
        val contextBytes = contextString.toByteArray(Charsets.UTF_8)

        // 4. Sign with Tink (raw 64-byte RFC 8032 signature).
        val signer = handle.getPrimitive(RegistryConfiguration.get(), PublicKeySign::class.java)
        val signature = signer.sign(contextBytes)
        assertEquals(64, signature.size)

        // 5. Sanity: Tink verifies its own signature (guard, not the interop proof).
        val verifier = handle.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify::class.java)
        verifier.verify(signature, contextBytes)

        // 6. Export fixture: raw bytes → standard base64. The Worker decodes and
        //    verifies the very same bytes with crypto.subtle — no conversion.
        val fixture = org.json.JSONObject().apply {
            put("alg", "Ed25519")
            put("context_b64", Base64.encodeToString(contextBytes, Base64.NO_WRAP))
            put("pub_b64", authPubB64)
            put("sig_b64", Base64.encodeToString(signature, Base64.NO_WRAP))
        }
        val out = File(context.filesDir, "fixture.json")
        out.writeText(fixture.toString())
        assertTrue(out.exists() && out.length() > 0)
    }
}
