package org.coldevm.signer.crypto

import org.bouncycastle.crypto.digests.KeccakDigest

/** Ethereum's keccak-256 (the original Keccak padding, not NIST SHA3-256). */
object Keccak {
    fun hash(data: ByteArray): ByteArray {
        val d = KeccakDigest(256)
        d.update(data, 0, data.size)
        return ByteArray(32).also { d.doFinal(it, 0) }
    }
}
