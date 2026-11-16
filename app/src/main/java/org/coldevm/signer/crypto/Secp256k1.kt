package org.coldevm.signer.crypto

import org.bouncycastle.asn1.x9.X9IntegerConverter
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.math.ec.ECAlgorithms
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger

/** secp256k1 ECDSA as Ethereum uses it: RFC 6979 nonces, low-s, and a recovery id. */
object Secp256k1 {
    private val params = CustomNamedCurves.getByName("secp256k1")
    val domain = ECDomainParameters(params.curve, params.g, params.n, params.h)
    val n: BigInteger = params.n
    private val halfN: BigInteger = n.shiftRight(1)

    class Signature(val r: BigInteger, val s: BigInteger, val recId: Int) {
        /** r ‖ s, 32 bytes each. */
        fun rs(): ByteArray = to32(r) + to32(s)
    }

    fun publicPoint(priv: ByteArray): ECPoint = domain.g.multiply(BigInteger(1, priv)).normalize()

    fun publicKey(priv: ByteArray, compressed: Boolean = true): ByteArray = publicPoint(priv).getEncoded(compressed)

    fun decodePoint(encoded: ByteArray): ECPoint = domain.curve.decodePoint(encoded).normalize()

    /** 64-byte x ‖ y of an encoded (compressed or not) public key. */
    fun uncompressedXY(encoded: ByteArray): ByteArray = decodePoint(encoded).getEncoded(false).copyOfRange(1, 65)

    fun sign(priv: ByteArray, hash: ByteArray): Signature {
        require(hash.size == 32) { "hash must be 32 bytes" }
        val d = BigInteger(1, priv)
        require(d.signum() > 0 && d < n) { "invalid private key" }
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(d, domain))
        val (r, s0) = signer.generateSignature(hash).let { it[0] to it[1] }
        val s = if (s0 > halfN) n.subtract(s0) else s0
        val pub = domain.g.multiply(d).normalize()
        val recId = (0..1).firstOrNull { recover(hash, r, s, it)?.equals(pub) == true }
            ?: throw IllegalStateException("could not compute recovery id")
        return Signature(r, s, recId)
    }

    fun verify(pub: ECPoint, hash: ByteArray, r: BigInteger, s: BigInteger): Boolean {
        if (s > halfN) return false
        val v = ECDSASigner()
        v.init(false, ECPublicKeyParameters(pub, domain))
        return v.verifySignature(hash, r, s)
    }

    /** SEC1 section 4.1.6 public key recovery for recovery ids 0 and 1 (x = r; r ≥ p − n is never produced). */
    fun recover(hash: ByteArray, r: BigInteger, s: BigInteger, recId: Int): ECPoint? {
        if (r.signum() <= 0 || r >= n || s.signum() <= 0 || s >= n) return null
        val x = r
        val prime = params.curve.field.characteristic
        if (x >= prime) return null
        val conv = X9IntegerConverter()
        val enc = conv.integerToBytes(x, 1 + conv.getByteLength(params.curve))
        enc[0] = if (recId and 1 == 1) 0x03 else 0x02
        val bigR = runCatching { params.curve.decodePoint(enc) }.getOrNull() ?: return null
        if (!bigR.multiply(n).isInfinity) return null
        val e = BigInteger(1, hash)
        val rInv = r.modInverse(n)
        val u1 = n.subtract(e).multiply(rInv).mod(n)
        val u2 = s.multiply(rInv).mod(n)
        val q = ECAlgorithms.sumOfTwoMultiplies(domain.g, u1, bigR, u2).normalize()
        return if (q.isInfinity) null else q
    }

    fun to32(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == 32 -> b
            b.size == 33 && b[0] == 0.toByte() -> b.copyOfRange(1, 33)
            b.size < 32 -> ByteArray(32 - b.size) + b
            else -> throw IllegalArgumentException("value does not fit in 32 bytes")
        }
    }
}
