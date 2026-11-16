package org.coldevm.signer.crypto

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToBytes(): ByteArray {
    val s = removePrefix("0x").removePrefix("0X")
    require(s.length % 2 == 0) { "hex length must be even" }
    return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
