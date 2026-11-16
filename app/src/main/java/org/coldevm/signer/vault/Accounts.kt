package org.coldevm.signer.vault

import org.coldevm.signer.crypto.Bip32
import org.coldevm.signer.crypto.DerivationPath
import org.coldevm.signer.crypto.PathComponent
import org.coldevm.signer.crypto.hexToBytes
import org.coldevm.signer.crypto.toHex
import org.coldevm.signer.evm.Address
import org.coldevm.signer.ur.KeystoneUr

/** The two EVM path layouts OKX Wallet offers for a Keystone. */
enum class Scheme(val label: String) {
    /** m/44'/60'/0'/0/i — MetaMask, OKX, most wallets. */
    STANDARD("标准 (BIP44)"),
    /** m/44'/60'/i'/0/0. */
    LEDGER_LIVE("Ledger Live"),
}

class Account(val scheme: Scheme, val index: Int, val path: DerivationPath, val publicKey: ByteArray) {
    val address: Address = Address.fromPublicKey(publicKey)
    val label: String get() = if (scheme == Scheme.STANDARD) "账户 ${index + 1}" else "Ledger Live ${index + 1}"
}

/**
 * Public key material of one wallet: the extended public keys of m/44'/60'/n' for n in 0 until [LEDGER_COUNT], and
 * the fingerprint of their parent m/44'/60'. Everything needed to show addresses, export to OKX and check sign
 * requests, without the seed.
 */
class EthKeys(val purposeFingerprint: ByteArray, val accountNodes: List<Bip32.PublicNode>) {
    init { require(accountNodes.size == LEDGER_COUNT) { "account key count" } }

    private val standardChange: Bip32.PublicNode by lazy { Bip32.publicChild(accountNodes[0], 0) }

    fun standard(i: Int): Account {
        require(i in 0 until MAX_STANDARD)
        return Account(Scheme.STANDARD, i, path(0).child(0).child(i), Bip32.publicChild(standardChange, i).key)
    }

    fun ledgerLive(n: Int): Account {
        require(n in 0 until LEDGER_COUNT)
        return Account(Scheme.LEDGER_LIVE, n, path(n).child(0).child(0), Bip32.publicChild(Bip32.publicChild(accountNodes[n], 0), 0).key)
    }

    /** Accounts listed on the wallet screen. */
    val shown: List<Account> by lazy { (0 until SHOWN_STANDARD).map(::standard) + (1 until LEDGER_COUNT).map(::ledgerLive) }

    /**
     * Every account this wallet can sign for (standard 0 until [MAX_STANDARD], Ledger Live 1 until [LEDGER_COUNT]),
     * used to recognise transfers to oneself and look-alikes of one's own addresses. About 110 public derivations,
     * computed once per wallet.
     */
    val all: List<Account> by lazy { (0 until MAX_STANDARD).map(::standard) + (1 until LEDGER_COUNT).map(::ledgerLive) }

    /** The account for a sign request path, or null when this wallet does not hand out that path. */
    fun resolve(p: DerivationPath): Account? {
        val c = p.components
        if (c.size != 5 || c[0] != PathComponent(44, true) || c[1] != PathComponent(60, true)) return null
        if (!c[2].hardened || c[3] != PathComponent(0, false) || c[4].hardened) return null
        return when {
            c[2].index == 0 && c[4].index < MAX_STANDARD -> standard(c[4].index)
            c[2].index in 1 until LEDGER_COUNT && c[4].index == 0 -> ledgerLive(c[2].index)
            else -> null
        }
    }

    /** The keys the Keystone firmware exports to OKX Wallet, in the same order and with the same notes. */
    fun syncKeys(): List<KeystoneUr.HdKey> {
        val keys = mutableListOf<KeystoneUr.HdKey>()
        for (n in 0 until LEDGER_COUNT) {
            val node = accountNodes[n]
            if (n == 0) keys += KeystoneUr.HdKey(path(0), node.key, node.chainCode, purposeFingerprint, 3, "account.standard")
            val change = Bip32.publicChild(node, 0)
            val target = Bip32.publicChild(change, 0)
            keys += KeystoneUr.HdKey(path(n).child(0).child(0), target.key, null, Bip32.fingerprint(change.key), 3, "account.ledger_live")
        }
        return keys
    }

    /** crypto-hdkey for MetaMask / Rabby: only the standard m/44'/60'/0' xpub (accounts m/44'/60'/0'/0/i). */
    fun standardHdKey(masterFingerprint: ByteArray, name: String): ByteArray =
        KeystoneUr.encodeStandardHdKey(masterFingerprint, accountNodes[0].key, accountNodes[0].chainCode, purposeFingerprint, name)

    fun serialize(): String = purposeFingerprint.toHex() + ";" + accountNodes.joinToString(",") { it.key.toHex() + ":" + it.chainCode.toHex() }

    companion object {
        const val LEDGER_COUNT = 10
        const val SHOWN_STANDARD = 10
        /** OKX can add more standard accounts from the xpub; sign requests beyond this index are refused. */
        const val MAX_STANDARD = 100

        fun path(n: Int) = DerivationPath(listOf(PathComponent(44, true), PathComponent(60, true), PathComponent(n, true)))

        fun derive(seed: ByteArray): EthKeys {
            val purpose = Bip32.derive(seed, DerivationPath(listOf(PathComponent(44, true), PathComponent(60, true))))
            val fp = try { Bip32.fingerprint(org.coldevm.signer.crypto.Secp256k1.publicKey(purpose.key)) } finally { purpose.wipe() }
            val nodes = (0 until LEDGER_COUNT).map { n ->
                val node = Bip32.derive(seed, path(n))
                try { Bip32.publicNode(node) } finally { node.wipe() }
            }
            return EthKeys(fp, nodes)
        }

        fun deserialize(s: String): EthKeys {
            val (fp, nodes) = s.split(";").also { require(it.size == 2) }
            return EthKeys(fp.hexToBytes(), nodes.split(",").map { n ->
                val (k, c) = n.split(":")
                Bip32.PublicNode(k.hexToBytes(), c.hexToBytes())
            })
        }
    }
}
