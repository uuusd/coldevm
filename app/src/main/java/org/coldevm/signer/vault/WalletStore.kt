package org.coldevm.signer.vault

import android.content.Context
import org.coldevm.signer.crypto.Bip32
import org.coldevm.signer.crypto.hexToBytes
import org.coldevm.signer.crypto.toHex
import java.security.SecureRandom
import javax.crypto.Cipher

/** One imported seed. Only public data lives here; the seed itself stays encrypted in [seedStore]. */
class Wallet(
    val id: String,
    val name: String,
    val fingerprint: ByteArray,
    val keys: EthKeys,
    val pinOnly: Boolean,
    val strongBox: Boolean,
    val seedStore: SeedStore,
) {
    val accounts: List<Account> get() = keys.shown
}

/**
 * All wallets on this device. Public, non-secret data (fingerprint, extended public keys) is cached in preferences
 * so lists and the OKX connect QR can be shown without unlocking any seed.
 */
class WalletStore(private val context: Context) {
    private val prefs = context.getSharedPreferences("wallets", Context.MODE_PRIVATE)

    /** Parsed wallets, rebuilt only after a change: screens read this on every recomposition. */
    @Volatile private var cache: List<Wallet>? = null

    init { reconcileAuthModes() }

    val wallets: List<Wallet> get() = cache ?: ids().mapNotNull(::read).also { cache = it }

    val isEmpty: Boolean get() = wallets.isEmpty()

    fun find(id: String): Wallet? = wallets.firstOrNull { it.id == id }

    private fun read(id: String): Wallet? {
        val fp = prefs.getString("$id.fp", null) ?: return null
        val keys = prefs.getString("$id.keys", null)?.let { runCatching { EthKeys.deserialize(it) }.getOrNull() } ?: return null
        return Wallet(
            id = id,
            name = prefs.getString("$id.name", id)!!,
            fingerprint = fp.hexToBytes(),
            keys = keys,
            pinOnly = prefs.getBoolean("$id.pin_only", false),
            strongBox = prefs.getBoolean("$id.strongbox", false),
            seedStore = seedStore(id),
        )
    }

    fun byFingerprint(fp: ByteArray): Wallet? = wallets.firstOrNull { it.fingerprint.contentEquals(fp) }

    /** Wallet that already holds this seed (same mnemonic and passphrase), if any. */
    fun duplicateOf(seed: ByteArray): Wallet? = byFingerprint(Bip32.masterFingerprint(seed))

    fun newId(): String = ByteArray(4).also { SecureRandom().nextBytes(it) }.toHex()

    fun defaultName(): String = "钱包 ${ids().size + 1}"

    fun seedStore(id: String): SeedStore = SeedStore.forWallet(context, id)

    /** Encrypts the seed with an authenticated cipher from [SeedStore.newEncryptCipher] and records the wallet. */
    fun create(id: String, name: String, pending: SeedStore.PendingKey, authenticatedCipher: Cipher, seed: ByteArray, pinOnly: Boolean) {
        val keys = EthKeys.derive(seed)
        seedStore(id).save(pending, authenticatedCipher, seed)
        prefs.edit()
            .putString("$id.name", name)
            .putString("$id.fp", Bip32.masterFingerprint(seed).toHex())
            .putString("$id.keys", keys.serialize())
            .putBoolean("$id.strongbox", pending.strongBox)
            .putBoolean("$id.pin_only", pinOnly)
            .putString(KEY_IDS, (ids() + id).joinToString(","))
            .commit()
        cache = null
    }

    fun rename(id: String, name: String) { prefs.edit().putString("$id.name", name).commit(); cache = null }

    /** Re-encrypts an already decrypted seed under a new key with different authentication rules. */
    fun rekey(wallet: Wallet, pending: SeedStore.PendingKey, authenticatedCipher: Cipher, seed: ByteArray, pinOnly: Boolean) {
        wallet.seedStore.save(pending, authenticatedCipher, seed)
        prefs.edit().putBoolean("${wallet.id}.strongbox", pending.strongBox).putBoolean("${wallet.id}.pin_only", pinOnly).commit()
        cache = null
    }

    fun loadSeed(wallet: Wallet, authenticatedCipher: Cipher): ByteArray = wallet.seedStore.load(authenticatedCipher)

    fun <T> withSeed(wallet: Wallet, authenticatedCipher: Cipher, block: (ByteArray) -> T): T {
        val seed = wallet.seedStore.load(authenticatedCipher)
        try { return block(seed) } finally { seed.fill(0) }
    }

    fun delete(wallet: Wallet) {
        wallet.seedStore.wipe()
        val edit = prefs.edit()
        prefs.all.keys.filter { it.startsWith("${wallet.id}.") }.forEach { edit.remove(it) }
        edit.putString(KEY_IDS, (ids() - wallet.id).joinToString(",")).commit()
        cache = null
    }

    /**
     * Re-keying writes the new seed file first and the "PIN only" setting second; if the app dies in between the
     * setting is stale. The Keystore key is the truth, so correct the setting from it at start-up.
     */
    private fun reconcileAuthModes() {
        for (id in ids()) {
            val actual = seedStore(id).keyIsPinOnly() ?: continue
            if (prefs.getBoolean("$id.pin_only", false) != actual) prefs.edit().putBoolean("$id.pin_only", actual).commit()
        }
    }

    private fun ids(): List<String> = prefs.getString(KEY_IDS, "")!!.split(",").filter { it.isNotEmpty() }

    companion object {
        private const val KEY_IDS = "ids"
    }
}
