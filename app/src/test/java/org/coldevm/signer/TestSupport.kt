package org.coldevm.signer

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import org.coldevm.signer.crypto.Bip32
import org.coldevm.signer.crypto.Bip39
import org.coldevm.signer.crypto.DerivationPath
import org.coldevm.signer.crypto.hexToBytes
import org.coldevm.signer.evm.Address
import org.coldevm.signer.vault.EthKeys
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger

val ABANDON = (List(11) { "abandon" } + "about")
val bip39 = Bip39(File("src/main/assets/bip39_english.txt").readLines().map { it.trim() }.filter { it.isNotEmpty() })
val SEED: ByteArray get() = Bip39.toSeed(ABANDON, "")
val KEYS: EthKeys by lazy { EthKeys.derive(SEED) }
val MFP: ByteArray by lazy { Bip32.masterFingerprint(SEED) }
val ACCOUNT0: Address = Address.parse("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")!!

/** Minimal RLP encoder for building test transactions. */
object RlpEnc {
    fun bytes(b: ByteArray): ByteArray = when {
        b.size == 1 && (b[0].toInt() and 0xff) < 0x80 -> b
        b.size < 56 -> byteArrayOf((0x80 + b.size).toByte()) + b
        else -> lenPrefix(0xb7, b.size) + b
    }
    fun uint(v: BigInteger): ByteArray = bytes(if (v.signum() == 0) ByteArray(0) else v.toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it })
    fun uint(v: Long) = uint(BigInteger.valueOf(v))
    fun list(vararg items: ByteArray): ByteArray {
        val body = items.fold(ByteArray(0)) { a, b -> a + b }
        return if (body.size < 56) byteArrayOf((0xc0 + body.size).toByte()) + body else lenPrefix(0xf7, body.size) + body
    }
    private fun lenPrefix(base: Int, len: Int): ByteArray {
        val l = BigInteger.valueOf(len.toLong()).toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        return byteArrayOf((base + l.size).toByte()) + l
    }
}

val GWEI: BigInteger = BigInteger.TEN.pow(9)
val ETHER: BigInteger = BigInteger.TEN.pow(18)

fun legacyTx(chainId: Long, nonce: Long, to: Address?, value: BigInteger, data: ByteArray = ByteArray(0), gasPrice: BigInteger = GWEI.multiply(BigInteger.valueOf(20)), gas: Long = 21000) =
    RlpEnc.list(RlpEnc.uint(nonce), RlpEnc.uint(gasPrice), RlpEnc.uint(gas), RlpEnc.bytes(to?.bytes ?: ByteArray(0)), RlpEnc.uint(value), RlpEnc.bytes(data),
        RlpEnc.uint(chainId), RlpEnc.uint(0), RlpEnc.uint(0))

fun eip1559Tx(chainId: Long, nonce: Long, to: Address?, value: BigInteger, data: ByteArray = ByteArray(0), gas: Long = 21000,
              maxPriority: BigInteger = GWEI, maxFee: BigInteger = GWEI.multiply(BigInteger.valueOf(30)), accessList: ByteArray = RlpEnc.list()) =
    byteArrayOf(2) + RlpEnc.list(RlpEnc.uint(chainId), RlpEnc.uint(nonce), RlpEnc.uint(maxPriority), RlpEnc.uint(maxFee), RlpEnc.uint(gas),
        RlpEnc.bytes(to?.bytes ?: ByteArray(0)), RlpEnc.uint(value), RlpEnc.bytes(data), accessList)

fun word(v: BigInteger) = ByteArray(32).also { val b = v.toByteArray().let { x -> if (x.size > 32) x.copyOfRange(x.size - 32, x.size) else x }; b.copyInto(it, 32 - b.size) }
fun word(a: Address) = ByteArray(12) + a.bytes
fun call(selector: String, vararg words: ByteArray) = selector.hexToBytes() + words.fold(ByteArray(0)) { a, b -> a + b }

/** An eth-sign-request CBOR exactly as @keystonehq/bc-ur-registry-eth builds it. */
fun signRequest(
    signData: ByteArray, dataType: Int, path: String = "m/44'/60'/0'/0/0", fp: ByteArray = MFP,
    chainId: Long? = null, address: ByteArray? = null, requestId: ByteArray? = ByteArray(16) { it.toByte() }, origin: String? = "okx",
): ByteArray {
    val map = CborMap()
    requestId?.let { map.put(UnsignedInteger(1), ByteString(it).also { b -> b.setTag(37) }) }
    address?.let { map.put(UnsignedInteger(6), ByteString(it)) }
    chainId?.let { map.put(UnsignedInteger(4), UnsignedInteger(it)) }
    origin?.let { map.put(UnsignedInteger(7), UnicodeString(it)) }
    map.put(UnsignedInteger(2), ByteString(signData))
    map.put(UnsignedInteger(3), UnsignedInteger(dataType.toLong()))
    val comps = CborArray()
    DerivationPath.parse(path).components.forEach { comps.add(UnsignedInteger(it.index.toLong())); comps.add(if (it.hardened) SimpleValue.TRUE else SimpleValue.FALSE) }
    val kp = CborMap().put(UnsignedInteger(1), comps).put(UnsignedInteger(2), UnsignedInteger(BigInteger(1, fp).toLong()))
    kp.setTag(304)
    map.put(UnsignedInteger(5), kp)
    return ByteArrayOutputStream().also { CborEncoder(it).encode(map) }.toByteArray()
}
