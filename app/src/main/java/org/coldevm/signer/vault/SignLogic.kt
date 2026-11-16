package org.coldevm.signer.vault

import org.coldevm.signer.crypto.Bip32
import org.coldevm.signer.crypto.Keccak
import org.coldevm.signer.crypto.Secp256k1
import org.coldevm.signer.crypto.toHex
import org.coldevm.signer.evm.Address
import org.coldevm.signer.evm.Describer
import org.coldevm.signer.evm.EvmTx
import org.coldevm.signer.evm.TxSummary
import org.coldevm.signer.evm.UnsupportedTx
import org.coldevm.signer.ur.KeystoneUr
import java.math.BigInteger

class Review(val account: Account, val origin: String?, val tx: EvmTx, val summary: TxSummary)

class RejectedException(message: String) : Exception(message)

/** Everything that decides whether a request may be signed. Pure Kotlin so it can be unit tested. */
object SignLogic {
    /**
     * @param own labels for every address this device controls (all wallets).
     * @param history how many transfers were signed to each address before.
     */
    fun review(
        req: KeystoneUr.SignRequest,
        masterFingerprint: ByteArray,
        keys: EthKeys,
        own: Map<Address, String> = keys.all.associate { it.address to it.label },
        history: Map<Address, Int> = emptyMap(),
    ): Review {
        val fp = req.sourceFingerprint ?: throw RejectedException("请求中缺少主指纹，拒绝签名")
        if (!fp.contentEquals(masterFingerprint)) {
            throw RejectedException("主指纹不匹配（请求 ${fp.toHex()}，本机 ${masterFingerprint.toHex()}）。这个请求不是发给本钱包的。")
        }
        val account = keys.resolve(req.path) ?: throw RejectedException("请求的路径 ${req.path} 不是本钱包提供的账户路径，拒绝签名")
        // The optional address is only a cross-check (the Keystone firmware ignores it, and the JS SDK turns a
        // "0x…" string into an empty buffer). The account is always the one derived from the path. When the field
        // holds a recognisable address it must match.
        declaredAddress(req.address)?.let { declared ->
            if (declared != account.address) throw RejectedException("请求中的地址 ${declared.checksummed} 与路径 ${req.path} 对应的地址不一致，拒绝签名")
        }
        val tx = try {
            EvmTx.parse(req.dataType, req.signData)
        } catch (e: UnsupportedTx) {
            throw RejectedException(e.message ?: "不支持的请求")
        } catch (e: Exception) {
            throw RejectedException("无法解析交易数据（${e.message}），拒绝盲签")
        }
        // The chain id the online wallet declares must be the one inside the signed bytes.
        if (req.chainId != null && req.chainId != 0L && req.chainId != tx.chainId) {
            throw RejectedException("请求声明的链 ID ${req.chainId} 与交易内的链 ID ${tx.chainId} 不一致，拒绝签名")
        }
        return Review(account, req.origin, tx, Describer(own, history).describe(tx))
    }

    /** A 20-byte address, or the same as ASCII hex with or without 0x; null when absent or not an address. */
    fun declaredAddress(field: ByteArray?): Address? = when {
        field == null || field.isEmpty() -> null
        field.size == 20 -> Address(field)
        field.size == 40 || field.size == 42 -> String(field, Charsets.US_ASCII).let { Address.parse(if (it.startsWith("0x")) it else "0x$it") }
        else -> null
    }

    /**
     * Derives the key, checks it matches the reviewed account and signs keccak256 of the exact bytes that were
     * reviewed. Returns r ‖ s ‖ v as the Keystone firmware does (v minimal big-endian; EIP-155 v for legacy).
     */
    fun sign(seed: ByteArray, account: Account, tx: EvmTx, signData: ByteArray): ByteArray {
        val node = Bip32.derive(seed, account.path)
        try {
            val pub = Secp256k1.publicKey(node.key)
            if (!pub.contentEquals(account.publicKey)) throw RejectedException("派生出的公钥与账户不一致，拒绝签名")
            val hash = Keccak.hash(signData)
            val sig = Secp256k1.sign(node.key, hash)
            check(Secp256k1.verify(Secp256k1.decodePoint(pub), hash, sig.r, sig.s)) { "签名自检失败" }
            check(Secp256k1.recover(hash, sig.r, sig.s, sig.recId)?.let { Address.fromPublicKey(it.getEncoded(true)) } == account.address) { "签名恢复地址自检失败" }
            val v = if (tx.type == 0) BigInteger.valueOf(tx.chainId).shiftLeft(1).add(BigInteger.valueOf(35L + sig.recId))
            else BigInteger.valueOf(sig.recId.toLong())
            return sig.rs() + minimalBytes(v)
        } finally {
            node.wipe()
        }
    }

    private fun minimalBytes(v: BigInteger): ByteArray {
        if (v.signum() == 0) return byteArrayOf(0)
        val b = v.toByteArray()
        return if (b[0] == 0.toByte()) b.copyOfRange(1, b.size) else b
    }
}
