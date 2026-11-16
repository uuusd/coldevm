package org.coldevm.signer.ur

/**
 * Structural pre-check of untrusted CBOR before it reaches the CBOR library, which allocates whatever length a
 * header declares (a QR claiming a 2 GB string crashes the app with OutOfMemoryError). Accepts only definite-length
 * items whose declared sizes fit in the remaining input, at most [MAX_DEPTH] levels deep, and exactly one top-level
 * item. Keystone payloads are always definite-length.
 */
object CborGuard {
    private const val MAX_DEPTH = 32

    fun check(b: ByteArray) {
        val end = item(b, 0, 0)
        require(end == b.size) { "CBOR 数据后有多余字节" }
    }

    private fun item(b: ByteArray, pos: Int, depth: Int): Int {
        require(depth <= MAX_DEPTH) { "CBOR 嵌套过深" }
        require(pos < b.size) { "CBOR 数据被截断" }
        val ib = b[pos].toInt() and 0xff
        val major = ib ushr 5
        val info = ib and 0x1f
        var p = pos + 1
        val arg: Long = when {
            info < 24 -> info.toLong()
            info in 24..27 -> {
                val n = 1 shl (info - 24)
                require(p + n <= b.size) { "CBOR 数据被截断" }
                var v = 0L
                for (i in 0 until n) v = (v shl 8) or (b[p + i].toLong() and 0xff)
                p += n
                v
            }
            else -> throw IllegalArgumentException("不支持的 CBOR 编码（保留值或不定长）")
        }
        val remaining = (b.size - p).toLong()
        return when (major) {
            0, 1 -> p
            2, 3 -> {
                require(arg in 0..remaining) { "CBOR 声明的长度超出数据" }
                p + arg.toInt()
            }
            4, 5 -> {
                val count = if (major == 5) arg * 2 else arg
                // Every element takes at least one byte, so a count beyond the remaining bytes is a lie.
                require(arg in 0..remaining && count <= remaining) { "CBOR 声明的元素数超出数据" }
                var q = p
                repeat(count.toInt()) { q = item(b, q, depth + 1) }
                q
            }
            6 -> {
                // Keystone tags only byte strings (uuid) and maps (hdkey, keypath, coin info). The CBOR library shares
                // one instance of true/false/null process-wide and would attach a tag to that singleton, corrupting every
                // later encoding, so a tag on anything else is refused.
                require(p < b.size) { "CBOR 数据被截断" }
                val target = (b[p].toInt() and 0xff) ushr 5
                require(target == 2 || target == 5) { "CBOR 标签用在了不支持的类型上" }
                item(b, p, depth + 1)
            }
            else -> {
                // Simple values and floats: info 20-23 are false/true/null/undefined, 24 one extra byte, 25-27 floats.
                require(info <= 27) { "不支持的 CBOR 简单值" }
                p
            }
        }
    }
}
