package org.coldevm.signer

import org.coldevm.signer.crypto.Bip32
import org.coldevm.signer.crypto.DerivationPath
import org.coldevm.signer.crypto.Keccak
import org.coldevm.signer.crypto.Secp256k1
import org.coldevm.signer.crypto.hexToBytes
import org.coldevm.signer.crypto.toHex
import org.coldevm.signer.evm.Address
import org.coldevm.signer.evm.EvmTx
import org.coldevm.signer.evm.RecipientStatus
import org.coldevm.signer.evm.Risk
import org.coldevm.signer.ur.KeystoneUr
import org.coldevm.signer.vault.Account
import org.coldevm.signer.vault.RejectedException
import org.coldevm.signer.vault.Scheme
import org.coldevm.signer.vault.SignLogic
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger

class SignFlowTest {
    private val bob = Address.parse("0x3535353535353535353535353535353535353535")!!
    private val usdtPolygon = Address.parse("0xc2132d05d31c914a87c6611c10748aeb04b58e8f")!!

    private fun review(cbor: ByteArray, history: Map<Address, Int> = emptyMap()) =
        SignLogic.review(KeystoneUr.decodeSignRequest(cbor), MFP, KEYS, history = history)

    private fun rejected(cbor: ByteArray, contains: String) {
        try { review(cbor); fail("expected rejection") } catch (e: RejectedException) {
            assertTrue("'${e.message}' should contain '$contains'", e.message!!.contains(contains))
        }
    }

    /** The worked example of EIP-155. */
    @Test fun eip155SpecExample() {
        val tx = legacyTx(1, 9, bob, ETHER)
        assertEquals("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080", tx.toHex())
        assertEquals("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53", Keccak.hash(tx).toHex())
        val priv = "4646464646464646464646464646464646464646464646464646464646464646".hexToBytes()
        val sig = Secp256k1.sign(priv, Keccak.hash(tx))
        assertEquals(BigInteger("18515461264373351373200002665853028612451056578545711640558177340181847433846"), sig.r)
        assertEquals(BigInteger("46948507304638947509940763649030358759909902576025900602547168820602576006531"), sig.s)
        assertEquals(37, 35 + 2 * 1 + sig.recId)
    }

    @Test fun legacySignRoundTrip() {
        val tx = legacyTx(56, 3, bob, ETHER.divide(BigInteger.TEN))
        val r = review(signRequest(tx, EvmTx.DATA_LEGACY, chainId = 56, address = ACCOUNT0.bytes))
        assertEquals("BNB Smart Chain (chainId 56)", r.summary.chainLabel)
        assertEquals("0.1 BNB", r.summary.headlines.single().amount)
        assertEquals(RecipientStatus.NEW, r.summary.headlines.single().status)
        val sig = SignLogic.sign(SEED, r.account, r.tx, tx)
        assertEquals(65, sig.size)
        val v = sig[64].toInt() and 0xff
        assertTrue(v == 56 * 2 + 35 || v == 56 * 2 + 36)
        val rec = Secp256k1.recover(Keccak.hash(tx), BigInteger(1, sig.copyOfRange(0, 32)), BigInteger(1, sig.copyOfRange(32, 64)), v - 56 * 2 - 35)!!
        assertEquals(ACCOUNT0, Address.fromPublicKey(rec.getEncoded(true)))
    }

    @Test fun largeChainIdVIsMultiByte() {
        val tx = legacyTx(11155111, 0, bob, ETHER)
        val r = review(signRequest(tx, EvmTx.DATA_LEGACY))
        val sig = SignLogic.sign(SEED, r.account, r.tx, tx)
        val v = BigInteger(1, sig.copyOfRange(64, sig.size))
        assertTrue(v == BigInteger.valueOf(11155111L * 2 + 35) || v == BigInteger.valueOf(11155111L * 2 + 36))
        assertEquals(64 + 4, sig.size)
    }

    @Test fun eip1559SignRoundTrip() {
        val tx = eip1559Tx(137, 1, bob, ETHER)
        val r = review(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, path = "m/44'/60'/0'/0/2", chainId = 137))
        assertEquals("账户 3", r.account.label)
        assertEquals("1 POL", r.summary.headlines.single().amount)
        assertEquals("0.00063 POL", r.summary.maxFee)
        val sig = SignLogic.sign(SEED, r.account, r.tx, tx)
        val v = sig[64].toInt()
        assertTrue(v == 0 || v == 1)
        val rec = Secp256k1.recover(Keccak.hash(tx), BigInteger(1, sig.copyOfRange(0, 32)), BigInteger(1, sig.copyOfRange(32, 64)), v)!!
        assertEquals(KEYS.standard(2).address, Address.fromPublicKey(rec.getEncoded(true)))
    }

    @Test fun ledgerLivePath() {
        val tx = eip1559Tx(1, 0, bob, ETHER)
        val r = review(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, path = "m/44'/60'/4'/0/0"))
        assertEquals(Scheme.LEDGER_LIVE, r.account.scheme)
        val sig = SignLogic.sign(SEED, r.account, r.tx, tx)
        val rec = Secp256k1.recover(Keccak.hash(tx), BigInteger(1, sig.copyOfRange(0, 32)), BigInteger(1, sig.copyOfRange(32, 64)), sig[64].toInt())!!
        assertEquals(KEYS.ledgerLive(4).address, Address.fromPublicKey(rec.getEncoded(true)))
    }

    @Test fun erc20TransferKnownToken() {
        val data = call("a9059cbb", word(bob), word(BigInteger.valueOf(12_500_000)))
        val r = review(signRequest(eip1559Tx(137, 0, usdtPolygon, BigInteger.ZERO, data, gas = 65000), EvmTx.DATA_TYPED_TRANSACTION))
        val h = r.summary.headlines.single()
        assertEquals("12.5 USDT", h.amount)
        assertEquals(bob.checksummed, h.to)
        assertEquals("转账 USDT", r.summary.action)
        assertEquals(Risk.INFO, r.summary.worstRisk)
        assertEquals(listOf(bob), r.summary.recipients)
    }

    @Test fun sameAddressOnOtherChainIsUnknownToken() {
        // USDT's Polygon address on Ethereum is not USDT.
        val data = call("a9059cbb", word(bob), word(BigInteger.valueOf(12_500_000)))
        val r = review(signRequest(eip1559Tx(1, 0, usdtPolygon, BigInteger.ZERO, data, gas = 65000), EvmTx.DATA_TYPED_TRANSACTION))
        assertTrue(r.summary.headlines.single().amount.contains("原始数量"))
        assertEquals(Risk.WARN, r.summary.worstRisk)
    }

    @Test fun approvals() {
        val unlimited = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)
        val r = review(signRequest(eip1559Tx(137, 0, usdtPolygon, BigInteger.ZERO, call("095ea7b3", word(bob), word(unlimited)), gas = 60000), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals(Risk.DANGER, r.summary.worstRisk)
        assertTrue(r.summary.needsAcknowledgement)
        assertTrue(r.summary.warnings.any { it.second.contains("无限额度") })
        assertTrue(r.summary.headlines.isEmpty())

        val revoke = review(signRequest(eip1559Tx(137, 0, usdtPolygon, BigInteger.ZERO, call("095ea7b3", word(bob), word(BigInteger.ZERO)), gas = 60000), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals("撤销授权", revoke.summary.action)
        assertEquals(Risk.INFO, revoke.summary.worstRisk)

        val nft = review(signRequest(eip1559Tx(1, 0, bob, BigInteger.ZERO, call("a22cb465", word(usdtPolygon), word(BigInteger.ONE)), gas = 60000), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals(Risk.DANGER, nft.summary.worstRisk)
        // A bool that is neither 0 nor 1 is malformed: blind-sign warning, not "revoke".
        val bad = review(signRequest(eip1559Tx(1, 0, bob, BigInteger.ZERO, call("a22cb465", word(usdtPolygon), word(BigInteger.TWO)), gas = 60000), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals(Risk.DANGER, bad.summary.worstRisk)
        assertEquals("合约调用", bad.summary.action)
    }

    @Test fun unknownCallAndDirtyAddressWord() {
        val r = review(signRequest(eip1559Tx(1, 0, bob, ETHER, "12345678".hexToBytes() + ByteArray(64), gas = 200000), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals(Risk.DANGER, r.summary.worstRisk)
        assertEquals("1 ETH", r.summary.headlines.single().amount)
        // Address argument with non-zero high bytes: not a clean transfer.
        val dirty = ByteArray(32) { if (it == 0) 1 else 0 }.also { bob.bytes.copyInto(it, 12) }
        val d = review(signRequest(eip1559Tx(137, 0, usdtPolygon, BigInteger.ZERO, call("a9059cbb", dirty, word(BigInteger.ONE)), gas = 65000), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals(Risk.DANGER, d.summary.worstRisk)
        assertTrue(d.summary.headlines.isEmpty())
        // Trailing bytes after the arguments.
        val t = review(signRequest(eip1559Tx(137, 0, usdtPolygon, BigInteger.ZERO, call("a9059cbb", word(bob), word(BigInteger.ONE), ByteArray(1)), gas = 65000), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals(Risk.DANGER, t.summary.worstRisk)
    }

    @Test fun contractCreation() {
        val r = review(signRequest(eip1559Tx(1, 0, null, BigInteger.ZERO, ByteArray(100), gas = 500000), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals(Risk.DANGER, r.summary.worstRisk)
    }

    @Test fun addressPoisoning() {
        val real = Address.parse("0x1234567890abcdef1234567890abcdef12345678")!!
        val fake = Address.parse("0x1230000000000000000000000000000000000678")!!
        val r = review(signRequest(eip1559Tx(1, 0, fake, ETHER), EvmTx.DATA_TYPED_TRANSACTION), history = mapOf(real to 3))
        assertNotNull(r.summary.headlines.single().alert)
        val ok = review(signRequest(eip1559Tx(1, 0, real, ETHER), EvmTx.DATA_TYPED_TRANSACTION), history = mapOf(real to 3))
        assertNull(ok.summary.headlines.single().alert)
        assertEquals(RecipientStatus.KNOWN, ok.summary.headlines.single().status)
        assertEquals(3, ok.summary.headlines.single().timesBefore)
        // Look-alike of one of our own accounts.
        val own = KEYS.standard(0).address.checksummed.lowercase()
        val mimic = Address.parse(own.substring(0, 5) + "0".repeat(34) + own.takeLast(3))!!
        assertNotNull(review(signRequest(eip1559Tx(1, 0, mimic, ETHER), EvmTx.DATA_TYPED_TRANSACTION)).summary.headlines.single().alert)
        // Sending to an own account.
        val self = review(signRequest(eip1559Tx(1, 0, KEYS.standard(1).address, ETHER), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals(RecipientStatus.SELF, self.summary.headlines.single().status)
        assertTrue(self.summary.recipients.isEmpty())
    }

    @Test fun tokenToTokenContract() {
        val data = call("a9059cbb", word(usdtPolygon), word(BigInteger.ONE))
        val r = review(signRequest(eip1559Tx(137, 0, usdtPolygon, BigInteger.ZERO, data, gas = 65000), EvmTx.DATA_TYPED_TRANSACTION))
        assertEquals(Risk.DANGER, r.summary.worstRisk)
        assertNotNull(r.summary.headlines.single().alert)
    }

    @Test fun rejections() {
        val tx = eip1559Tx(1, 0, bob, ETHER)
        rejected(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, fp = "deadbeef".hexToBytes()), "主指纹不匹配")
        rejected(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, path = "m/44'/60'/1'/0/0/0"), "路径")
        rejected(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, path = "m/44'/61'/0'/0/0"), "路径")
        rejected(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, path = "m/44'/60'/0'/0/100"), "路径")
        rejected(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, path = "m/44'/60'/0'/1/0"), "路径")
        rejected(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, path = "m/44'/60'/10'/0/0"), "路径")
        rejected(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, address = bob.bytes), "地址")
        rejected(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, address = bob.checksummed.toByteArray()), "地址")
        // Empty (JS SDK given "0x…") or uninterpretable address fields are ignored, as the firmware does.
        review(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, address = ByteArray(0)))
        review(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, address = ACCOUNT0.checksummed.toByteArray()))
        review(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, address = ACCOUNT0.checksummed.substring(2).lowercase().toByteArray()))
        rejected(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION, chainId = 56), "链 ID")
        rejected(signRequest(tx, EvmTx.DATA_LEGACY), "无法解析")
        rejected(signRequest(legacyTx(1, 0, bob, ETHER), EvmTx.DATA_TYPED_TRANSACTION), "未知的交易类型")
        rejected(signRequest("hello".toByteArray(), EvmTx.DATA_PERSONAL_MESSAGE), "消息签名")
        rejected(signRequest("{}".toByteArray(), EvmTx.DATA_TYPED_DATA), "消息签名")
        rejected(signRequest(byteArrayOf(4) + tx.copyOfRange(1, tx.size), EvmTx.DATA_TYPED_TRANSACTION), "EIP-7702")
        rejected(signRequest(byteArrayOf(1) + tx.copyOfRange(1, tx.size), EvmTx.DATA_TYPED_TRANSACTION), "2930")
        // Pre-EIP-155 legacy (6 fields, no chain id).
        val noChain = RlpEnc.list(RlpEnc.uint(0), RlpEnc.uint(GWEI), RlpEnc.uint(21000), RlpEnc.bytes(bob.bytes), RlpEnc.uint(ETHER), RlpEnc.bytes(ByteArray(0)))
        rejected(signRequest(noChain, EvmTx.DATA_LEGACY), "重放")
        // Trailing garbage and non-canonical encodings.
        rejected(signRequest(tx + byteArrayOf(0), EvmTx.DATA_TYPED_TRANSACTION), "多余字节")
        val leadingZeroNonce = byteArrayOf(2) + RlpEnc.list(RlpEnc.uint(1), RlpEnc.bytes(byteArrayOf(0, 1)), RlpEnc.uint(GWEI), RlpEnc.uint(GWEI), RlpEnc.uint(21000),
            RlpEnc.bytes(bob.bytes), RlpEnc.uint(ETHER), RlpEnc.bytes(ByteArray(0)), RlpEnc.list())
        rejected(signRequest(leadingZeroNonce, EvmTx.DATA_TYPED_TRANSACTION), "前导零")
        val singleByteLong = byteArrayOf(2) + RlpEnc.list(RlpEnc.uint(1), byteArrayOf(0x81.toByte(), 5), RlpEnc.uint(GWEI), RlpEnc.uint(GWEI), RlpEnc.uint(21000),
            RlpEnc.bytes(bob.bytes), RlpEnc.uint(ETHER), RlpEnc.bytes(ByteArray(0)), RlpEnc.list())
        rejected(signRequest(singleByteLong, EvmTx.DATA_TYPED_TRANSACTION), "非规范")
        // Priority fee above max fee.
        rejected(signRequest(eip1559Tx(1, 0, bob, ETHER, maxPriority = GWEI.multiply(BigInteger.TEN), maxFee = GWEI), EvmTx.DATA_TYPED_TRANSACTION), "maxPriorityFeePerGas")
        // Missing fingerprint.
        try { SignLogic.review(KeystoneUr.decodeSignRequest(signRequest(tx, EvmTx.DATA_TYPED_TRANSACTION).let { it }), "00000000".hexToBytes(), KEYS); fail() } catch (_: RejectedException) {}
    }

    @Test fun signRefusesMismatchedAccount() {
        val tx = eip1559Tx(1, 0, bob, ETHER)
        val fake = Account(Scheme.STANDARD, 0, DerivationPath.parse("m/44'/60'/0'/0/0"), KEYS.standard(1).publicKey)
        try { SignLogic.sign(SEED, fake, EvmTx.parse(4, tx), tx); fail() } catch (_: RejectedException) {}
    }

    @Test fun signatureUr() {
        val id = ByteArray(16) { 7 }
        val cbor = KeystoneUr.encodeSignature(id, ByteArray(65) { 1 })
        // {1: 37(h'0707…'), 2: h'0101…', 3: "Keystone"}
        assertEquals("a301d82550" + "07".repeat(16) + "025841" + "01".repeat(65) + "03684b657973746f6e65", cbor.toHex())
    }

    @Test fun syncKeysMatchFirmwareLayout() {
        val keys = KEYS.syncKeys()
        assertEquals(11, keys.size)
        assertEquals("m/44'/60'/0'", keys[0].path.toString())
        assertEquals("account.standard", keys[0].note)
        assertNotNull(keys[0].chainCode)
        assertEquals("m/44'/60'/0'/0/0", keys[1].path.toString())
        assertEquals("account.ledger_live", keys[1].note)
        assertNull(keys[1].chainCode)
        assertEquals("m/44'/60'/9'/0/0", keys[10].path.toString())
        assertEquals(KEYS.ledgerLive(9).publicKey.toHex(), keys[10].key.toHex())
        // Parent fingerprint of the ledger live key is that of m/44'/60'/n'/0.
        val parent = Bip32.derive(SEED, DerivationPath.parse("m/44'/60'/9'/0"))
        assertEquals(Bip32.fingerprint(Secp256k1.publicKey(parent.key)).toHex(), keys[10].parentFingerprint.toHex())
        assertFalse(KeystoneUr.encodeMultiAccounts(MFP, "x", keys).isEmpty())
    }
}
