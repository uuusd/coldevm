package org.coldevm.signer.evm

import org.coldevm.signer.crypto.Keccak
import org.coldevm.signer.crypto.Secp256k1
import org.coldevm.signer.crypto.toHex

/** A 20-byte EVM account address. */
class Address(bytes: ByteArray) {
    private val b = bytes.copyOf()
    init { require(b.size == 20) { "address must be 20 bytes" } }

    val bytes: ByteArray get() = b.copyOf()

    /** EIP-55 mixed-case checksum form. */
    val checksummed: String by lazy {
        val hex = b.toHex()
        val hash = Keccak.hash(hex.toByteArray()).toHex()
        "0x" + hex.mapIndexed { i, c -> if (c in 'a'..'f' && hash[i].digitToInt(16) >= 8) c.uppercaseChar() else c }.joinToString("")
    }

    override fun equals(other: Any?) = other is Address && other.b.contentEquals(b)
    override fun hashCode() = b.contentHashCode()
    override fun toString() = checksummed

    companion object {
        fun fromPublicKey(encoded: ByteArray): Address =
            Address(Keccak.hash(Secp256k1.uncompressedXY(encoded)).copyOfRange(12, 32))

        /**
         * Parses "0x…" (40 hex digits). All-lower and all-upper are accepted as is; mixed case must be a valid
         * EIP-55 checksum, so a mistyped address is caught.
         */
        fun parse(text: String): Address? {
            val t = text.trim()
            if (!t.startsWith("0x") && !t.startsWith("0X")) return null
            val hex = t.substring(2)
            if (hex.length != 40 || hex.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }) return null
            val a = Address(ByteArray(20) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() })
            val mixed = hex.any { it in 'a'..'f' } && hex.any { it in 'A'..'F' }
            if (mixed && a.checksummed.substring(2) != hex) return null
            return a
        }
    }
}
