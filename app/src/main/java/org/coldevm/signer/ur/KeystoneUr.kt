package org.coldevm.signer.ur

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SimpleValueType
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import org.coldevm.signer.crypto.DerivationPath
import org.coldevm.signer.crypto.PathComponent
import org.coldevm.signer.crypto.toHex
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest

/**
 * CBOR payloads of the Keystone QR protocol for EVM, byte-compatible with @keystonehq/bc-ur-registry(-eth) and the
 * Keystone 3 firmware's OKX Wallet export (rust/apps/wallets/src/okx.rs).
 */
object KeystoneUr {
    const val TYPE_MULTI_ACCOUNTS = "crypto-multi-accounts"
    const val TYPE_ETH_SIGN_REQUEST = "eth-sign-request"
    const val TYPE_ETH_SIGNATURE = "eth-signature"
    const val TYPE_ETH_BATCH_SIGN_REQUEST = "eth-batch-sign-request"

    private const val TAG_UUID = 37L
    private const val TAG_HDKEY = 303L
    private const val TAG_KEYPATH = 304L

    /** What the Keystone 3 firmware sends to OKX Wallet (firmware version format "%d.%d.%d", currently 3.2.2). */
    const val DEVICE_TYPE = "Keystone 3 Pro"
    const val DEVICE_VERSION = "3.2.2"
    private const val KEY_NAME = "Keystone"

    class SignRequest(
        val requestId: ByteArray?,
        val signData: ByteArray,
        val dataType: Int,
        val chainId: Long?,
        val path: DerivationPath,
        val sourceFingerprint: ByteArray?,
        val address: ByteArray?,
        val origin: String?,
    )

    /** One crypto-hdkey in the sync payload. */
    class HdKey(
        val path: DerivationPath,
        /** 33-byte compressed public key. */
        val key: ByteArray,
        val chainCode: ByteArray?,
        val parentFingerprint: ByteArray,
        /** Depth written into the key path (the firmware writes the xpub's depth even for derived keys). */
        val depth: Int,
        val note: String,
    )

    /**
     * crypto-multi-accounts as the firmware builds it for OKX Wallet: the standard m/44'/60'/0' xpub plus the
     * Ledger Live keys m/44'/60'/n'/0/0. No Bitcoin or other chains: this device only signs EVM transactions.
     */
    fun encodeMultiAccounts(masterFingerprint: ByteArray, deviceSerial: String, keys: List<HdKey>): ByteArray {
        val hdKeys = CborArray()
        for (k in keys) {
            val m = CborMap()
            m.put(uint(2), cborFalse())
            m.put(uint(3), ByteString(k.key))
            k.chainCode?.let { m.put(uint(4), ByteString(it)) }
            m.put(uint(6), keypath(k.path, masterFingerprint, k.depth).also { it.setTag(TAG_KEYPATH) })
            m.put(uint(8), UnsignedInteger(u32(k.parentFingerprint)))
            m.put(uint(9), UnicodeString(KEY_NAME))
            m.put(uint(10), UnicodeString(k.note))
            m.setTag(TAG_HDKEY)
            hdKeys.add(m)
        }
        val root = CborMap()
            .put(uint(1), UnsignedInteger(u32(masterFingerprint)))
            .put(uint(2), hdKeys)
            .put(uint(3), UnicodeString(DEVICE_TYPE))
            .put(uint(4), UnicodeString(deviceId(deviceSerial)))
            .put(uint(5), UnicodeString(DEVICE_VERSION))
        return encode(root)
    }

    const val TYPE_HDKEY = "crypto-hdkey"
    private const val TAG_COIN_INFO = 305L

    /**
     * crypto-hdkey as the firmware exports it for MetaMask and Rabby (rust/apps/wallets/src/metamask.rs,
     * Bip44Standard): the m/44'/60'/0' xpub with coin info ETH mainnet and children 0/\*.
     */
    fun encodeStandardHdKey(masterFingerprint: ByteArray, key: ByteArray, chainCode: ByteArray, parentFingerprint: ByteArray, name: String): ByteArray {
        val origin = keypath(DerivationPath(listOf(PathComponent(44, true), PathComponent(60, true), PathComponent(0, true))), masterFingerprint, 3)
        origin.setTag(TAG_KEYPATH)
        val children = CborMap()
            .put(uint(1), CborArray().apply {
                add(UnsignedInteger(0)); add(cborFalse())
                add(CborArray()); add(cborFalse())   // wildcard
            })
            .put(uint(3), UnsignedInteger(0))
        children.setTag(TAG_KEYPATH)
        val coinInfo = CborMap().put(uint(1), UnsignedInteger(60)).put(uint(2), UnsignedInteger(0))
        coinInfo.setTag(TAG_COIN_INFO)
        val m = CborMap()
            .put(uint(2), cborFalse())
            .put(uint(3), ByteString(key))
            .put(uint(4), ByteString(chainCode))
            .put(uint(5), coinInfo)
            .put(uint(6), origin)
            .put(uint(7), children)
            .put(uint(8), UnsignedInteger(u32(parentFingerprint)))
            .put(uint(9), UnicodeString(name))
            .put(uint(10), UnicodeString("account.standard"))
        return encode(m)
    }

    /** Same derivation as the firmware: hex of the first 20 bytes of sha256(sha256(serial)). */
    fun deviceId(serial: String): String {
        val sha = MessageDigest.getInstance("SHA-256")
        return sha.digest(sha.digest(serial.toByteArray())).copyOfRange(0, 20).toHex()
    }

    fun decodeSignRequest(cbor: ByteArray): SignRequest {
        CborGuard.check(cbor)
        val map = CborDecoder.decode(cbor).singleOrNull() as? CborMap ?: throw IllegalArgumentException("签名请求不是 CBOR map")
        val requestId = (map.get(uint(1)) as? ByteString)?.bytes
        val signData = (map.get(uint(2)) as? ByteString)?.bytes ?: throw IllegalArgumentException("缺少待签数据")
        val dataType = (map.get(uint(3)) as? UnsignedInteger)?.value?.let(::smallInt) ?: throw IllegalArgumentException("缺少数据类型")
        val chainId = map.get(uint(4))?.let { item ->
            val v = (item as? UnsignedInteger)?.value ?: throw IllegalArgumentException("链 ID 格式错误")
            require(v.bitLength() <= 53) { "链 ID 超出范围: $v" }
            v.toLong()
        }
        val keypath = map.get(uint(5)) as? CborMap ?: throw IllegalArgumentException("缺少派生路径")
        val address = map.get(uint(6))?.let { (it as? ByteString)?.bytes ?: throw IllegalArgumentException("地址格式错误") }
        val origin = (map.get(uint(7)) as? UnicodeString)?.string

        val comps = (keypath.get(uint(1)) as? CborArray)?.dataItems ?: throw IllegalArgumentException("缺少路径分量")
        require(comps.size % 2 == 0) { "路径分量格式错误" }
        val path = comps.chunked(2).map { (idx, hardened) ->
            val h = when ((hardened as? SimpleValue)?.takeIf { it.tag == null }?.simpleValueType) {
                SimpleValueType.TRUE -> true
                SimpleValueType.FALSE -> false
                else -> throw IllegalArgumentException("路径分量格式错误")
            }
            val i = (idx as? UnsignedInteger)?.value?.let(::smallInt) ?: throw IllegalArgumentException("不允许通配路径")
            PathComponent(i, h)
        }
        val fp = (keypath.get(uint(2)) as? UnsignedInteger)?.value?.let { v ->
            require(v.bitLength() <= 32) { "主指纹超出 32 位: $v" }
            val l = v.toLong()
            byteArrayOf((l shr 24).toByte(), (l shr 16).toByte(), (l shr 8).toByte(), l.toByte())
        }
        return SignRequest(requestId, signData, dataType, chainId, DerivationPath(path), fp, address, origin)
    }

    fun encodeSignature(requestId: ByteArray?, signature: ByteArray): ByteArray {
        val map = CborMap()
        if (requestId != null) map.put(uint(1), ByteString(requestId).also { it.setTag(TAG_UUID) })
        map.put(uint(2), ByteString(signature))
        map.put(uint(3), UnicodeString(KEY_NAME))
        return encode(map)
    }

    private fun keypath(path: DerivationPath, fingerprint: ByteArray, depth: Int): CborMap {
        val comps = CborArray()
        path.components.forEach { comps.add(UnsignedInteger(it.index.toLong())); comps.add(if (it.hardened) cborTrue() else cborFalse()) }
        return CborMap()
            .put(uint(1), comps)
            .put(uint(2), UnsignedInteger(u32(fingerprint)))
            .put(uint(3), UnsignedInteger(depth.toLong()))
    }

    /** Rejects values that BigInteger.toInt() would silently truncate (e.g. 2^32 + 44 becoming 44). */
    private fun smallInt(v: BigInteger): Int {
        require(v.signum() >= 0 && v.bitLength() <= 31) { "数值超出范围: $v" }
        return v.toInt()
    }

    private fun uint(v: Int) = UnsignedInteger(v.toLong())

    // Fresh instances: the library's SimpleValue.TRUE/FALSE are shared, mutable (tag) singletons.
    private fun cborTrue() = SimpleValue(SimpleValueType.TRUE)
    private fun cborFalse() = SimpleValue(SimpleValueType.FALSE)

    private fun u32(b: ByteArray): Long =
        ((b[0].toLong() and 0xff) shl 24) or ((b[1].toLong() and 0xff) shl 16) or ((b[2].toLong() and 0xff) shl 8) or (b[3].toLong() and 0xff)

    private fun encode(item: DataItem): ByteArray =
        ByteArrayOutputStream().also { CborEncoder(it).encode(item) }.toByteArray()
}
