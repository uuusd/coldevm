package org.coldevm.signer.crypto

import org.bouncycastle.crypto.digests.RIPEMD160Digest
import java.math.BigInteger
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** One component of a BIP32 path. */
data class PathComponent(val index: Int, val hardened: Boolean) {
    init { require(index >= 0) { "path index out of range" } }
    val raw: Long get() = index.toLong() or (if (hardened) 0x80000000L else 0L)
    override fun toString() = if (hardened) "$index'" else "$index"
}

data class DerivationPath(val components: List<PathComponent>) {
    override fun toString(): String = "m" + components.joinToString("") { "/$it" }

    fun child(index: Int, hardened: Boolean = false) = DerivationPath(components + PathComponent(index, hardened))

    companion object {
        fun parse(path: String): DerivationPath {
            val parts = path.trim().removePrefix("m").removePrefix("M").removePrefix("/").split("/").filter { it.isNotEmpty() }
            return DerivationPath(parts.map { p ->
                val hardened = p.endsWith("'") || p.endsWith("h")
                val v = (if (hardened) p.dropLast(1) else p).toLong()
                require(v in 0 until 0x80000000L) { "路径索引越界: $path" }
                PathComponent(v.toInt(), hardened)
            })
        }
    }
}

/** BIP32 over secp256k1: private derivation from a seed, public (non-hardened) derivation from an xpub. */
object Bip32 {
    class Node(val key: ByteArray, val chainCode: ByteArray) {
        fun wipe() { key.fill(0); chainCode.fill(0) }
    }

    /** A public node: 33-byte compressed key and chain code. */
    class PublicNode(val key: ByteArray, val chainCode: ByteArray)

    fun master(seed: ByteArray): Node {
        val i = hmac("Bitcoin seed".toByteArray(), seed)
        val node = Node(i.copyOfRange(0, 32), i.copyOfRange(32, 64))
        i.fill(0)
        val k = BigInteger(1, node.key)
        require(k.signum() > 0 && k < Secp256k1.n) { "invalid master key" }
        return node
    }

    fun derive(seed: ByteArray, path: DerivationPath): Node {
        var node = master(seed)
        for (c in path.components) {
            val next = childPrivate(node, c)
            node.wipe()
            node = next
        }
        return node
    }

    private fun childPrivate(parent: Node, c: PathComponent): Node {
        val data = if (c.hardened) byteArrayOf(0) + parent.key else Secp256k1.publicKey(parent.key)
        val input = data + ser32(c.raw)
        val i = hmac(parent.chainCode, input)
        input.fill(0); data.fill(0)
        val il = BigInteger(1, i.copyOfRange(0, 32))
        val k = il.add(BigInteger(1, parent.key)).mod(Secp256k1.n)
        // Probability ~2^-127; BIP32 says skip to the next index, which no wallet does, so refuse.
        require(il < Secp256k1.n && k.signum() != 0) { "invalid child key" }
        val node = Node(Secp256k1.to32(k), i.copyOfRange(32, 64))
        i.fill(0)
        return node
    }

    fun publicChild(parent: PublicNode, index: Int): PublicNode {
        require(index >= 0) { "public derivation cannot be hardened" }
        val i = hmac(parent.chainCode, parent.key + ser32(index.toLong()))
        val il = BigInteger(1, i.copyOfRange(0, 32))
        require(il < Secp256k1.n) { "invalid child key" }
        val p = Secp256k1.domain.g.multiply(il).add(Secp256k1.decodePoint(parent.key)).normalize()
        require(!p.isInfinity) { "invalid child key" }
        return PublicNode(p.getEncoded(true), i.copyOfRange(32, 64))
    }

    fun publicNode(node: Node) = PublicNode(Secp256k1.publicKey(node.key), node.chainCode.copyOf())

    /** First 4 bytes of HASH160 of a compressed public key. */
    fun fingerprint(compressedPub: ByteArray): ByteArray {
        val sha = MessageDigest.getInstance("SHA-256").digest(compressedPub)
        val ripemd = ByteArray(20)
        RIPEMD160Digest().run { update(sha, 0, sha.size); doFinal(ripemd, 0) }
        return ripemd.copyOfRange(0, 4)
    }

    /** Master key fingerprint: Keystone (and OKX) identify a wallet by it and echo it in every sign request. */
    fun masterFingerprint(seed: ByteArray): ByteArray {
        val m = master(seed)
        try { return fingerprint(Secp256k1.publicKey(m.key)) } finally { m.wipe() }
    }

    private fun ser32(v: Long) = byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA512").run { init(SecretKeySpec(key, "HmacSHA512")); doFinal(data) }
}
