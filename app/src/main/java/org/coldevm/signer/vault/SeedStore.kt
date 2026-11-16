package org.coldevm.signer.vault

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Keeps the BIP39 seed encrypted with an AES-256-GCM key that lives in the Android Keystore
 * (StrongBox when available). Every use of the key requires a fresh authentication, so each
 * [Cipher] returned here must be passed through BiometricPrompt before use.
 *
 * Keys live in two alternating slots. Re-keying (e.g. switching to PIN-only) creates the new key
 * in the unused slot and only deletes the old one after the new ciphertext is on disk, so a
 * cancelled prompt halfway through can never leave the seed unreadable.
 *
 * Each wallet has its own file and key aliases.
 *
 * File layout: [version=2][slot][ivLen][iv][ciphertext]
 */
class SeedStore(context: Context, fileName: String, private val aliasPrefix: String) {
    private val file = File(context.noBackupFilesDir, fileName)

    class PendingKey(val cipher: Cipher, val slot: Int, val strongBox: Boolean)

    /** The seed can never be decrypted again: its file or Keystore key is missing or the file is unreadable. */
    class UnavailableException(message: String) : IllegalStateException(message)

    fun exists(): Boolean = file.exists()

    /** Creates a key in the unused slot and returns a cipher ready to encrypt (after authentication). */
    fun newEncryptCipher(pinOnly: Boolean): PendingKey {
        val slot = if (exists()) 1 - currentSlot() else 0
        keyStore().deleteEntry(alias(slot))
        val (key, strongBox) = generateKey(alias(slot), pinOnly)
        return PendingKey(Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }, slot, strongBox)
    }

    fun save(pending: PendingKey, authenticatedCipher: Cipher, seed: ByteArray) {
        val ct = authenticatedCipher.doFinal(seed)
        val iv = authenticatedCipher.iv
        val tmp = File(file.parentFile, file.name + ".tmp")
        // Flush the new ciphertext, the rename and the directory entry to storage before the old key is
        // deleted: after a power cut there is always one complete ciphertext whose key still exists.
        FileOutputStream(tmp).use { out ->
            out.write(byteArrayOf(VERSION, pending.slot.toByte(), iv.size.toByte()) + iv + ct)
            out.fd.sync()
        }
        if (!tmp.renameTo(file)) throw IllegalStateException("无法写入种子文件")
        syncDirectory(file.parentFile!!)
        keyStore().deleteEntry(alias(1 - pending.slot))
    }

    fun decryptCipher(): Cipher {
        val blob = readBlob()
        val key = keyStore().getKey(alias(blob[1].toInt()), null) as? SecretKey
            ?: throw UnavailableException("密钥丢失，请用助记词重新导入")
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob, 3, blob[2].toInt()))
        }
    }

    fun load(authenticatedCipher: Cipher): ByteArray {
        val blob = readBlob()
        val start = 3 + blob[2].toInt()
        return authenticatedCipher.doFinal(blob, start, blob.size - start)
    }

    fun wipe() {
        if (file.exists()) {
            file.writeBytes(ByteArray(file.length().toInt()))
            file.delete()
        }
        keyStore().run { deleteEntry(alias(0)); deleteEntry(alias(1)) }
    }

    /**
     * Whether the key currently protecting the seed accepts only the device credential, read from the Keystore
     * itself, or null when it cannot be read. This is the ground truth when the stored setting disagrees (e.g. a
     * power cut between re-keying and saving the setting).
     */
    fun keyIsPinOnly(): Boolean? = runCatching {
        val key = keyStore().getKey(alias(currentSlot()), null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        info.userAuthenticationType == KeyProperties.AUTH_DEVICE_CREDENTIAL
    }.getOrNull()

    private fun syncDirectory(dir: File) {
        val fd = Os.open(dir.path, OsConstants.O_RDONLY, 0)
        try { Os.fsync(fd) } finally { Os.close(fd) }
    }

    private fun currentSlot(): Int = readBlob()[1].toInt()

    private fun readBlob(): ByteArray {
        if (!file.exists()) throw UnavailableException("种子文件不存在")
        val blob = file.readBytes()
        if (blob.size < 4 || blob[0] != VERSION || blob[1].toInt() !in 0..1) throw UnavailableException("种子文件格式无效")
        return blob
    }

    private fun generateKey(alias: String, pinOnly: Boolean): Pair<SecretKey, Boolean> {
        val authenticators = if (pinOnly) KeyProperties.AUTH_DEVICE_CREDENTIAL
        else KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL

        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, authenticators)
            .setInvalidatedByBiometricEnrollment(false)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()

        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            gen.init(spec(true))
            gen.generateKey() to true
        } catch (e: StrongBoxUnavailableException) {
            gen.init(spec(false))
            gen.generateKey() to false
        }
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun alias(slot: Int) = "$aliasPrefix-$slot"

    companion object {
        private const val VERSION: Byte = 2
        private const val TRANSFORMATION = "AES/GCM/NoPadding"

        fun forWallet(context: Context, id: String) = SeedStore(context, "seed-$id.enc", "coldevm-$id-key")
    }
}
