package org.coldevm.signer.crypto

import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.Normalizer

/** BIP39 mnemonic handling (English wordlist only). */
class Bip39(private val wordlist: List<String>) {
    private val index: Map<String, Int> = wordlist.withIndex().associate { it.value to it.index }

    init {
        require(wordlist.size == 2048) { "wordlist must have 2048 words" }
    }

    fun isWord(word: String): Boolean = word in index

    fun suggestions(prefix: String, limit: Int = 4): List<String> =
        if (prefix.isEmpty()) emptyList() else wordlist.filter { it.startsWith(prefix) }.take(limit)

    /** Returns null when valid, otherwise a human readable reason. */
    fun validate(words: List<String>): String? {
        if (words.size !in VALID_LENGTHS) return "助记词必须是 12/15/18/21/24 个单词（当前 ${words.size} 个）"
        val unknown = words.filterNot { it in index }
        if (unknown.isNotEmpty()) return "不在 BIP39 词表中: ${unknown.joinToString(", ")}"
        val bits = BooleanArray(words.size * 11)
        words.forEachIndexed { w, word ->
            val v = index.getValue(word)
            for (b in 0 until 11) bits[w * 11 + b] = (v shr (10 - b)) and 1 == 1
        }
        val checksumBits = bits.size / 33
        val entropy = ByteArray((bits.size - checksumBits) / 8)
        for (i in entropy.indices) {
            var byte = 0
            for (b in 0 until 8) if (bits[i * 8 + b]) byte = byte or (1 shl (7 - b))
            entropy[i] = byte.toByte()
        }
        val hash = MessageDigest.getInstance("SHA-256").digest(entropy)
        for (i in 0 until checksumBits) {
            val expected = (hash[i / 8].toInt() shr (7 - i % 8)) and 1 == 1
            if (bits[entropy.size * 8 + i] != expected) return "校验和错误：请检查单词拼写和顺序"
        }
        return null
    }

    fun fromEntropy(entropy: ByteArray): List<String> {
        require(entropy.size in setOf(16, 20, 24, 28, 32))
        val hash = MessageDigest.getInstance("SHA-256").digest(entropy)
        val checksumBits = entropy.size * 8 / 32
        val totalBits = entropy.size * 8 + checksumBits
        fun bit(i: Int): Int =
            if (i < entropy.size * 8) (entropy[i / 8].toInt() shr (7 - i % 8)) and 1
            else (hash[(i - entropy.size * 8) / 8].toInt() shr (7 - (i - entropy.size * 8) % 8)) and 1
        return (0 until totalBits / 11).map { w ->
            var v = 0
            for (b in 0 until 11) v = (v shl 1) or bit(w * 11 + b)
            wordlist[v]
        }
    }

    fun generate(random: SecureRandom = SecureRandom()): List<String> {
        val entropy = ByteArray(32).also { random.nextBytes(it) }
        return try { fromEntropy(entropy) } finally { entropy.fill(0) }
    }

    companion object {
        val VALID_LENGTHS = setOf(12, 15, 18, 21, 24)

        fun normalize(input: String): List<String> =
            Normalizer.normalize(input, Normalizer.Form.NFKD).lowercase().trim().split(Regex("\\s+")).filter { it.isNotEmpty() }

        fun toSeed(words: List<String>, passphrase: String): ByteArray {
            val mnemonic = Normalizer.normalize(words.joinToString(" "), Normalizer.Form.NFKD).toByteArray(Charsets.UTF_8)
            val salt = Normalizer.normalize("mnemonic$passphrase", Normalizer.Form.NFKD).toByteArray(Charsets.UTF_8)
            val gen = PKCS5S2ParametersGenerator(SHA512Digest())
            gen.init(mnemonic, salt, 2048)
            val seed = (gen.generateDerivedParameters(512) as KeyParameter).key
            mnemonic.fill(0)
            return seed
        }
    }
}
