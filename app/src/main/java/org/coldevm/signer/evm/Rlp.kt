package org.coldevm.signer.evm

import java.math.BigInteger

/** An RLP item: either a byte string or a list. */
sealed class Rlp {
    class Bytes(val value: ByteArray) : Rlp()
    class List(val items: kotlin.collections.List<Rlp>) : Rlp()

    fun bytes(what: String): ByteArray = (this as? Bytes)?.value ?: throw IllegalArgumentException("$what 应为字节串")
    fun list(what: String): kotlin.collections.List<Rlp> = (this as? List)?.items ?: throw IllegalArgumentException("$what 应为列表")

    /** Canonical unsigned integer: no leading zero bytes, at most 32 bytes. */
    fun uint(what: String): BigInteger {
        val b = bytes(what)
        require(b.size <= 32) { "$what 超过 256 位" }
        require(b.isEmpty() || b[0] != 0.toByte()) { "$what 有前导零（非规范编码）" }
        return BigInteger(1, b)
    }

    companion object {
        /**
         * Strict decoder: only canonical encodings, and the whole input must be one item. Two different byte
         * strings must never decode to the same transaction, or what is reviewed could differ from what is hashed.
         */
        fun decode(input: ByteArray, offset: Int = 0): Rlp {
            val (item, end) = read(input, offset, 0)
            require(end == input.size) { "RLP 数据后有多余字节" }
            return item
        }

        private const val MAX_DEPTH = 16

        private fun read(b: ByteArray, pos: Int, depth: Int): Pair<Rlp, Int> {
            require(depth <= MAX_DEPTH) { "RLP 嵌套过深" }
            require(pos < b.size) { "RLP 数据被截断" }
            val p = b[pos].toInt() and 0xff
            return when {
                p < 0x80 -> Bytes(byteArrayOf(b[pos])) to pos + 1
                p <= 0xb7 -> {
                    val len = p - 0x80
                    val start = pos + 1
                    require(start + len <= b.size) { "RLP 数据被截断" }
                    if (len == 1) require((b[start].toInt() and 0xff) >= 0x80) { "RLP 单字节非规范编码" }
                    Bytes(b.copyOfRange(start, start + len)) to start + len
                }
                p <= 0xbf -> {
                    val (len, start) = longLength(b, pos, p - 0xb7)
                    Bytes(b.copyOfRange(start, start + len)) to start + len
                }
                p <= 0xf7 -> readList(b, pos + 1, p - 0xc0, depth)
                else -> {
                    val (len, start) = longLength(b, pos, p - 0xf7)
                    readList(b, start, len, depth)
                }
            }
        }

        private fun longLength(b: ByteArray, pos: Int, lenOfLen: Int): Pair<Int, Int> {
            require(pos + 1 + lenOfLen <= b.size) { "RLP 数据被截断" }
            require(lenOfLen <= 4) { "RLP 长度过大" }
            require(b[pos + 1] != 0.toByte()) { "RLP 长度有前导零" }
            var len = 0L
            for (i in 0 until lenOfLen) len = (len shl 8) or (b[pos + 1 + i].toLong() and 0xff)
            require(len >= 56) { "RLP 长度应使用短格式" }
            val start = pos + 1 + lenOfLen
            require(start + len <= b.size) { "RLP 数据被截断" }
            return len.toInt() to start
        }

        private fun readList(b: ByteArray, start: Int, len: Int, depth: Int): Pair<Rlp, Int> {
            require(start + len <= b.size) { "RLP 数据被截断" }
            val end = start + len
            val items = mutableListOf<Rlp>()
            var p = start
            while (p < end) {
                val (item, next) = read(b, p, depth + 1)
                require(next <= end) { "RLP 列表元素越界" }
                items += item
                p = next
            }
            return List(items) to end
        }
    }
}
