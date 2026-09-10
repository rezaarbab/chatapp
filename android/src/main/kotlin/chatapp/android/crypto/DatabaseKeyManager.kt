package chatapp.android.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Generates a random 32-byte SQLCipher passphrase and protects it with a
 * non-exportable AES-GCM key inside AndroidKeyStore. The passphrase never
 * reaches disk in plaintext; only `IV || ciphertext` is persisted.
 */
object DatabaseKeyManager {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val PREFS_NAME = "chatapp_crypto_prefs"
    private const val GCM_TAG_BITS = 128

    fun getOrCreatePassphrase(context: Context, alias: String): ByteArray {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val key = getOrCreateKeystoreKey(alias)
        val wrappedBase64 = prefs.getString(alias, null)
        if (wrappedBase64 != null) {
            val wrapped = Base64.decode(wrappedBase64, Base64.NO_WRAP)
            val iv = wrapped.copyOfRange(0, 12)
            val ciphertext = wrapped.copyOfRange(12, wrapped.size)
            return unwrap(key, iv, ciphertext)
        }
        val passphrase = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val (iv, ciphertext) = wrap(key, passphrase)
        prefs.edit()
            .putString(alias, Base64.encodeToString(iv + ciphertext, Base64.NO_WRAP))
            .apply()
        return passphrase
    }

    fun keystoreContainsAlias(alias: String): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.containsAlias(alias)
    }

    private fun getOrCreateKeystoreKey(alias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private fun wrap(key: SecretKey, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        return iv to cipher.doFinal(plaintext)
    }

    private fun unwrap(key: SecretKey, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }
}
