package org.coldevm.signer

import org.coldevm.signer.crypto.Bip32
import org.coldevm.signer.crypto.Bip39
import org.coldevm.signer.crypto.DerivationPath
import org.coldevm.signer.crypto.Keccak
import org.coldevm.signer.crypto.Secp256k1
import org.coldevm.signer.crypto.hexToBytes
import org.coldevm.signer.crypto.toHex
import org.coldevm.signer.evm.Address
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.math.BigInteger
import java.security.MessageDigest

class CryptoTest {
    @Test fun keccak() {
        assertEquals("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", Keccak.hash(ByteArray(0)).toHex())
        assertEquals("a9059cbb", Keccak.hash("transfer(address,uint256)".toByteArray()).copyOfRange(0, 4).toHex())
        assertEquals("095ea7b3", Keccak.hash("approve(address,uint256)".toByteArray()).copyOfRange(0, 4).toHex())
        assertEquals("a22cb465", Keccak.hash("setApprovalForAll(address,bool)".toByteArray()).copyOfRange(0, 4).toHex())
        assertEquals("23b872dd", Keccak.hash("transferFrom(address,address,uint256)".toByteArray()).copyOfRange(0, 4).toHex())
        assertEquals("42842e0e", Keccak.hash("safeTransferFrom(address,address,uint256)".toByteArray()).copyOfRange(0, 4).toHex())
        assertEquals("b88d4fde", Keccak.hash("safeTransferFrom(address,address,uint256,bytes)".toByteArray()).copyOfRange(0, 4).toHex())
        assertEquals("39509351", Keccak.hash("increaseAllowance(address,uint256)".toByteArray()).copyOfRange(0, 4).toHex())
    }

    @Test fun bip39() {
        assertNull(bip39.validate(ABANDON))
        assertNotNull(bip39.validate(List(12) { "abandon" }))
        assertEquals(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            Bip39.toSeed(ABANDON, "TREZOR").toHex(),
        )
    }

    /** BIP32 test vector 1. */
    @Test fun bip32Vector1() {
        val seed = "000102030405060708090a0b0c0d0e0f".hexToBytes()
        assertEquals("3442193e", Bip32.masterFingerprint(seed).toHex())
        // xprv of m/0'/1/2'/2/1000000000 from the BIP: 471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8
        val leaf = Bip32.derive(seed, DerivationPath.parse("m/0'/1/2'/2/1000000000"))
        assertEquals("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8", leaf.key.toHex())
        assertEquals("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e", leaf.chainCode.toHex())
        // Public derivation of the non-hardened tail matches private derivation.
        val p = Bip32.publicNode(Bip32.derive(seed, DerivationPath.parse("m/0'/1/2'")))
        val pub = Bip32.publicChild(Bip32.publicChild(p, 2), 1000000000)
        assertEquals(Secp256k1.publicKey(leaf.key).toHex(), pub.key.toHex())
    }

    @Test fun abandonAddresses() {
        assertEquals("73c5da0a", MFP.toHex())
        assertEquals(ACCOUNT0, KEYS.standard(0).address)
        assertEquals("0x9858EfFD232B4033E47d90003D41EC34EcaEda94", KEYS.standard(0).address.checksummed)
        // Private derivation agrees with the cached public keys.
        val n = Bip32.derive(SEED, DerivationPath.parse("m/44'/60'/0'/0/7"))
        assertEquals(Address.fromPublicKey(Secp256k1.publicKey(n.key)), KEYS.standard(7).address)
        val l = Bip32.derive(SEED, DerivationPath.parse("m/44'/60'/3'/0/0"))
        assertEquals(Address.fromPublicKey(Secp256k1.publicKey(l.key)), KEYS.ledgerLive(3).address)
    }

    /** Expected value computed independently by ethers 6 (tools/interop). */
    @Test fun xpubOfStandardAccount() {
        val node = KEYS.accountNodes[0]
        val ser = "0488b21e".hexToBytes() + byteArrayOf(3) + KEYS.purposeFingerprint + "80000000".hexToBytes() + node.chainCode + node.key
        assertEquals("xpub6DCoCpSuQZB2jawqnGMEPS63ePKWkwWPH4TU45Q7LPXWuNd8TMtVxRrgjtEshuqpK3mdhaWHPFsBngh5GFZaM6si3yZdUsT8ddYM3PwnATt", base58check(ser))
    }

    @Test fun eip55() {
        // Examples from EIP-55.
        for (a in listOf("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb")) {
            assertEquals(a, Address.parse(a)!!.checksummed)
            assertEquals(a, Address.parse(a.lowercase().replace("0x", "0x"))!!.checksummed)
        }
        // One flipped case breaks the checksum.
        assertNull(Address.parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"))
        assertNull(Address.parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe"))
    }

    @Test fun lowSAndRecovery() {
        val priv = "4646464646464646464646464646464646464646464646464646464646464646".hexToBytes()
        repeat(50) { i ->
            val h = Keccak.hash(byteArrayOf(i.toByte()))
            val sig = Secp256k1.sign(priv, h)
            assert(sig.s <= Secp256k1.n.shiftRight(1))
            assertEquals(Secp256k1.publicPoint(priv), Secp256k1.recover(h, sig.r, sig.s, sig.recId))
        }
    }

    private fun base58check(payload: ByteArray): String {
        val sha = MessageDigest.getInstance("SHA-256")
        val data = payload + sha.digest(sha.digest(payload)).copyOfRange(0, 4)
        val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var n = BigInteger(1, data)
        val sb = StringBuilder()
        while (n.signum() > 0) { val (q, r) = n.divideAndRemainder(BigInteger.valueOf(58)); sb.append(alphabet[r.toInt()]); n = q }
        data.takeWhile { it == 0.toByte() }.forEach { _ -> sb.append('1') }
        return sb.reverse().toString()
    }
}
