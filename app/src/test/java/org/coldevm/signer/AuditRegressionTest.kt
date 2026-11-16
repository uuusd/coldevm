package org.coldevm.signer

import org.coldevm.signer.evm.Address
import org.coldevm.signer.evm.EvmTx
import org.coldevm.signer.evm.RecipientStatus
import org.coldevm.signer.evm.Risk
import org.coldevm.signer.evm.Rlp
import org.coldevm.signer.ur.CborGuard
import org.coldevm.signer.ur.KeystoneUr
import org.coldevm.signer.vault.RejectedException
import org.coldevm.signer.vault.SignLogic
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.util.Random

/** Regression tests for the 2026-11-16 audit findings. */
class AuditRegressionTest {
    private val bob = Address.parse("0x3535353535353535353535353535353535353535")!!
    private fun review(signData: ByteArray, dataType: Int = 4, path: String = "m/44'/60'/0'/0/0", history: Map<Address, Int> = emptyMap()) =
        SignLogic.review(KeystoneUr.decodeSignRequest(signRequest(signData, dataType, path = path)), MFP, KEYS, history = history)

    private fun reencode(r: Rlp): ByteArray = when (r) {
        is Rlp.Bytes -> RlpEnc.bytes(r.value)
        is Rlp.List -> RlpEnc.list(*r.items.map(::reencode).toTypedArray())
    }

    /** What is reviewed is what is signed: every input the strict decoder accepts re-encodes to identical bytes. */
    @Test fun rlpFuzzCanonical() {
        val rnd = Random(1)
        val seeds = listOf(eip1559Tx(1, 5, bob, ETHER), legacyTx(56, 300, bob, ETHER, ByteArray(70) { 1 }), eip1559Tx(137, 0, bob, BigInteger.ZERO, ByteArray(200) { it.toByte() }, gas = 99999))
        var accepted = 0
        repeat(60_000) {
            val base = seeds[rnd.nextInt(seeds.size)].copyOf()
            val m = when (rnd.nextInt(4)) {
                0 -> base.also { b -> repeat(1 + rnd.nextInt(3)) { b[rnd.nextInt(b.size)] = rnd.nextInt(256).toByte() } }
                1 -> base.copyOf(rnd.nextInt(base.size))
                2 -> base + ByteArray(1 + rnd.nextInt(3)) { rnd.nextInt(256).toByte() }
                else -> ByteArray(rnd.nextInt(80)) { rnd.nextInt(256).toByte() }
            }
            val start = if (m.isNotEmpty() && m[0] == 2.toByte()) 1 else 0
            runCatching { Rlp.decode(m, start) }.getOrNull()?.let { accepted++; assertArrayEquals(m.copyOfRange(start, m.size), reencode(it)) }
            try { review(m, if (start == 1) 4 else 1) } catch (_: RejectedException) {}
        }
        assertTrue(accepted > 1000)
    }

    /** Finding L1: a declared 2 GB length used to crash the app with OutOfMemoryError. */
    @Test fun hugeCborLengthsRejectedWithoutAllocation() {
        val hostile = listOf(
            "a1027a7fffffff",                 // {2: text of length 2^31-1}
            "a1025b00000000ffffffff00",       // {2: bytes of length 2^32-1}
            "9b00000000ffffffff",             // array of 2^32-1 items
            "a1025f4100ff",                   // indefinite-length bytes
            "bf01ff",                         // indefinite-length map
            "a10200" + "",                    // fine structurally, missing fields
        )
        for (h in hostile) {
            val b = h.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            try { KeystoneUr.decodeSignRequest(b); fail("accepted $h") } catch (_: IllegalArgumentException) {}
        }
        // Tag on a simple value (would mutate the library's shared SimpleValue.TRUE singleton).
        try { CborGuard.check("d90130f5".chunked(2).map { it.toInt(16).toByte() }.toByteArray()); fail() } catch (_: IllegalArgumentException) {}
        val deep = ByteArray(100) { 0x81.toByte() } + byteArrayOf(0)
        try { CborGuard.check(deep); fail() } catch (_: IllegalArgumentException) {}
        // Real requests (tags, maps, arrays, bools, text) still pass.
        CborGuard.check(signRequest(eip1559Tx(1, 0, bob, ETHER), 4))
    }

    @Test fun cborFuzzOnlyCleanExceptions() {
        val rnd = Random(2)
        val base = signRequest(eip1559Tx(1, 0, bob, ETHER), 4)
        repeat(100_000) {
            val m = base.copyOf().also { b -> repeat(1 + rnd.nextInt(4)) { b[rnd.nextInt(b.size)] = rnd.nextInt(256).toByte() } }
            // Exceptions are shown as "无法解析"; an Error (OutOfMemoryError) would crash the app.
            try { SignLogic.review(KeystoneUr.decodeSignRequest(m), MFP, KEYS) } catch (_: Exception) {}
        }
        // Hostile input must not leave process-wide state behind: our own encodings are unchanged afterwards.
        assertArrayEquals(base, signRequest(eip1559Tx(1, 0, bob, ETHER), 4))
        assertEquals(null, co.nstant.`in`.cbor.model.SimpleValue.TRUE.tag)
    }

    /** Finding M1: an inflated fee is warned about, red when far above normal. */
    @Test fun feeWarnings() {
        val absurd = review(eip1559Tx(1, 0, bob, ETHER.divide(BigInteger.valueOf(100)), gas = 10_000_000, maxPriority = GWEI, maxFee = GWEI.multiply(BigInteger.valueOf(500))))
        assertEquals("5 ETH", absurd.summary.maxFee)
        assertEquals(Risk.DANGER, absurd.summary.feeRisk)
        assertTrue(absurd.summary.needsAcknowledgement)
        // Priority fee = max fee, 21000 gas: 0.105 ETH really paid.
        val tip = review(eip1559Tx(1, 0, bob, ETHER, maxPriority = GWEI.multiply(BigInteger.valueOf(5000)), maxFee = GWEI.multiply(BigInteger.valueOf(5000))))
        assertEquals(Risk.WARN, tip.summary.feeRisk)
        // Legacy BSC at 1000 gwei with a 1M gas limit = 1 BNB.
        val bsc = review(legacyTx(56, 0, bob, ETHER, gasPrice = GWEI.multiply(BigInteger.valueOf(1000)), gas = 1_000_000), dataType = 1)
        assertEquals(Risk.DANGER, bsc.summary.feeRisk)
        // Normal fees stay quiet.
        assertEquals(Risk.INFO, review(eip1559Tx(1, 0, bob, ETHER)).summary.worstRisk)
        assertEquals(Risk.INFO, review(eip1559Tx(137, 0, bob, ETHER, gas = 21000, maxFee = GWEI.multiply(BigInteger.valueOf(300)))).summary.worstRisk)
        // Fee above a (non-dust) amount sent.
        val small = review(eip1559Tx(1, 0, bob, BigInteger.TEN.pow(14), maxFee = GWEI.multiply(BigInteger.valueOf(200))))
        assertTrue(small.summary.warnings.any { it.second.contains("高于转账金额") })
    }

    /** Finding L2: accounts beyond the first ten are still recognised as one's own. */
    @Test fun ownAccountsBeyondShown() {
        val r = review(eip1559Tx(1, 0, KEYS.standard(15).address, ETHER))
        assertEquals(RecipientStatus.SELF, r.summary.headlines.single().status)
        assertTrue(r.summary.recipients.isEmpty())
        assertEquals(RecipientStatus.SELF, review(eip1559Tx(1, 0, KEYS.standard(99).address, ETHER)).summary.headlines.single().status)
        // Look-alike of account 50 is flagged.
        val own = KEYS.standard(50).address.checksummed.lowercase()
        val mimic = Address.parse(own.substring(0, 5) + "0".repeat(34) + own.takeLast(3))!!
        assertNotNull(review(eip1559Tx(1, 0, mimic, ETHER)).summary.headlines.single().alert)
    }

    private val usdt = Address.parse("0xdac17f958d2ee523a2206206994597c13d831ec7")!!
    private val usdc = Address.parse("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")!!
    private val aavePool = Address.parse("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2")!!

    /** Audit #2 M1: a recipient alert (address poisoning, token contract as recipient) is red and needs acknowledgement. */
    @Test fun recipientAlertsGateSigning() {
        val own = KEYS.standard(0).address.checksummed.lowercase()
        val mimic = Address.parse(own.substring(0, 5) + "0".repeat(34) + own.takeLast(3))!!
        for (tx in listOf(
            eip1559Tx(1, 0, mimic, ETHER),
            eip1559Tx(1, 0, usdt, BigInteger.ZERO, call("a9059cbb", word(mimic), word(BigInteger.valueOf(1_000_000_000))), gas = 60000),
            eip1559Tx(1, 0, usdt, BigInteger.ZERO, call("a9059cbb", word(usdc), word(BigInteger.valueOf(1_000_000_000))), gas = 60000),
            eip1559Tx(1, 0, usdc, ETHER),
            eip1559Tx(1, 0, usdt, BigInteger.ZERO, call("a9059cbb", word(usdt), word(BigInteger.ONE)), gas = 60000),
        )) {
            val s = review(tx).summary
            assertEquals(Risk.DANGER, s.worstRisk)
            assertTrue(s.needsAcknowledgement)
            // One red line per problem, not the same alert twice.
            assertEquals(s.warnings.size, s.warnings.distinct().size)
        }
        // A known recipient is not a look-alike of itself and stays quiet.
        assertEquals(Risk.INFO, review(eip1559Tx(1, 0, bob, ETHER), history = mapOf(bob to 2)).summary.worstRisk)
    }

    /** Audit #2 L1: a call whose arguments turn out malformed leaves no half-decoded "deposit" line behind. */
    @Test fun malformedCallLeavesNoStaleHeadline() {
        val dirty = ByteArray(32).also { it[0] = 1; KEYS.standard(0).address.bytes.copyInto(it, 12) }
        val s = review(eip1559Tx(1, 0, aavePool, BigInteger.ZERO, call(org.coldevm.signer.evm.Protocols.AAVE_SUPPLY, word(usdc), word(BigInteger.valueOf(5)), dirty, word(BigInteger.ZERO)), gas = 300000)).summary
        assertTrue(s.headlines.isEmpty())
        assertTrue(s.recipients.isEmpty())
        assertEquals(Risk.DANGER, s.worstRisk)
        assertEquals("合约调用", s.action)
    }

    /** Audit #2 L2: an absurd finite approval to a recognised protocol is red, an exact one stays yellow. */
    @Test fun hugeProtocolApprovalIsRed() {
        fun approve(v: BigInteger, token: Address = usdc) =
            review(eip1559Tx(1, 0, token, BigInteger.ZERO, call("095ea7b3", word(aavePool), word(v)), gas = 60000)).summary
        assertEquals(Risk.DANGER, approve(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)).worstRisk)
        assertEquals(Risk.DANGER, approve(BigInteger.TEN.pow(6 + 12).add(BigInteger.ONE)).worstRisk)
        assertEquals(Risk.WARN, approve(BigInteger.valueOf(5_000_000_000)).worstRisk)
        // Unknown token: 2^96 raw units and above is effectively unlimited.
        val unknown = Address.parse("0x1234567890123456789012345678901234567890")!!
        assertEquals(Risk.DANGER, approve(BigInteger.ONE.shiftLeft(96), unknown).worstRisk)
    }

    /** Audit #2 L3: protocol assets have names and decimals offline. */
    @Test fun protocolAssetsKnown() {
        val dai = Address.parse("0x6b175474e89094c44da98b954eedeac495271d0f")!!
        val s = review(eip1559Tx(1, 0, dai, BigInteger.ZERO, call("a9059cbb", word(bob), word(ETHER.multiply(BigInteger.valueOf(25)))), gas = 60000)).summary
        assertEquals("转账 DAI", s.action)
        assertEquals("25 DAI", s.headlines.single().amount)
        assertEquals(Risk.INFO, s.worstRisk)
    }

    /** Audit #2: the sign-time cache check compares serialized keys; a stored cache must round-trip to the derived one. */
    @Test fun cachedKeysRoundTrip() {
        val stored = org.coldevm.signer.vault.EthKeys.deserialize(KEYS.serialize())
        assertEquals(org.coldevm.signer.vault.EthKeys.derive(SEED).serialize(), stored.serialize())
        val other = org.coldevm.signer.vault.EthKeys.derive(org.coldevm.signer.crypto.Bip39.toSeed(ABANDON, "x"))
        assertTrue(other.serialize() != stored.serialize())
    }
}
