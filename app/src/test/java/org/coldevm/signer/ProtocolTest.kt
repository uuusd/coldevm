package org.coldevm.signer

import org.coldevm.signer.evm.Address
import org.coldevm.signer.evm.Protocols
import org.coldevm.signer.evm.RecipientStatus
import org.coldevm.signer.evm.Risk
import org.coldevm.signer.ur.KeystoneUr
import org.coldevm.signer.vault.SignLogic
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class ProtocolTest {
    private val me = KEYS.standard(0).address
    private val bob = Address.parse("0x3535353535353535353535353535353535353535")!!
    private val aavePoolAvax = Address.parse("0x794a61358d6845594f94dc1db02a252b5b4814ad")!!
    private val gatewayAvax = Address.parse("0x2825ce5921538d17cc15ae00a8b24ff759c6cdae")!!
    private val usdcAvax = Address.parse("0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e")!!
    private val qiAvax = Address.parse("0x5c0401e81bc07ca70fad469b451682c0d747ef1c")!!
    private val qiUsdcn = Address.parse("0xb715808a78f6041e46d61cb123c9b4a27056ae9c")!!
    private val spUsdcAvax = Address.parse("0x28b3a8fb53b741a8fd78c0fb9a6b2393d896a43d")!!
    private val max = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)
    private fun n(v: Long) = BigInteger.valueOf(v)

    private fun review(chain: Long, to: Address, data: ByteArray, value: BigInteger = BigInteger.ZERO) =
        SignLogic.review(KeystoneUr.decodeSignRequest(signRequest(eip1559Tx(chain, 0, to, value, data, gas = 300_000), 4)), MFP, KEYS).summary

    @Test fun selectorsMatchKnownValues() {
        assertEquals("617ba037", Protocols.AAVE_SUPPLY)
        assertEquals("e8eda9df", Protocols.AAVE_DEPOSIT)
        assertEquals("69328dec", Protocols.AAVE_WITHDRAW)
        assertEquals("474cf53d", Protocols.GATEWAY_DEPOSIT)
        assertEquals("80500d20", Protocols.GATEWAY_WITHDRAW)
        assertEquals("6e553f65", Protocols.VAULT_DEPOSIT)
        assertEquals("b460af94", Protocols.VAULT_WITHDRAW)
        assertEquals("ba087652", Protocols.VAULT_REDEEM)
        assertEquals("94bf804d", Protocols.VAULT_MINT)
        assertEquals("a0712d68", Protocols.BENQI_MINT)
        assertEquals("1249c58b", Protocols.BENQI_MINT_NATIVE)
        assertEquals("db006a75", Protocols.BENQI_REDEEM)
        assertEquals("852a12e3", Protocols.BENQI_REDEEM_UNDERLYING)
    }

    @Test fun aaveSupplyAndWithdraw() {
        val s = review(43114, aavePoolAvax, call(Protocols.AAVE_SUPPLY, word(usdcAvax), word(n(1_000_000_000)), word(me), word(BigInteger.ZERO)))
        assertEquals(Risk.INFO, s.worstRisk)
        val h = s.headlines.single()
        assertEquals("1000 USDC", h.amount)
        assertEquals(RecipientStatus.PROTOCOL, h.status)
        assertTrue(h.ownLabel!!.contains("Aave V3 Pool") && h.ownLabel!!.contains("Avalanche"))
        assertTrue(s.recipients.isEmpty())

        val w = review(43114, aavePoolAvax, call(Protocols.AAVE_WITHDRAW, word(usdcAvax), word(max), word(me)))
        assertEquals(Risk.INFO, w.worstRisk)
        assertTrue(w.effect!!.contains("全部"))
        assertTrue(w.headlines.isEmpty())
    }

    @Test fun fundsToSomeoneElseAreRed() {
        assertEquals(Risk.DANGER, review(43114, aavePoolAvax, call(Protocols.AAVE_SUPPLY, word(usdcAvax), word(n(1)), word(bob), word(BigInteger.ZERO))).worstRisk)
        assertEquals(Risk.DANGER, review(43114, aavePoolAvax, call(Protocols.AAVE_WITHDRAW, word(usdcAvax), word(n(1)), word(bob))).worstRisk)
        assertEquals(Risk.DANGER, review(43114, spUsdcAvax, call(Protocols.VAULT_REDEEM, word(n(5)), word(me), word(bob))).worstRisk)
        assertEquals(Risk.DANGER, review(43114, spUsdcAvax, call(Protocols.VAULT_DEPOSIT, word(n(5)), word(bob))).worstRisk)
        // Another of my own accounts is fine.
        assertEquals(Risk.INFO, review(43114, aavePoolAvax, call(Protocols.AAVE_WITHDRAW, word(usdcAvax), word(n(1)), word(KEYS.standard(3).address))).worstRisk)
    }

    @Test fun rightAddressWrongChainIsNotRecognised() {
        // The Avalanche pool address on Ethereum is not Aave there: unknown call.
        val s = review(1, aavePoolAvax, call(Protocols.AAVE_SUPPLY, word(usdcAvax), word(n(1)), word(me), word(BigInteger.ZERO)))
        assertEquals(Risk.DANGER, s.worstRisk)
        assertEquals("合约调用", s.action)
    }

    @Test fun approvalsToProtocols() {
        val exact = review(43114, usdcAvax, call("095ea7b3", word(aavePoolAvax), word(n(1_000_000_000))))
        assertEquals(Risk.WARN, exact.worstRisk)
        assertTrue(exact.effect!!.contains("Aave V3 Pool"))
        assertEquals(Risk.DANGER, review(43114, usdcAvax, call("095ea7b3", word(aavePoolAvax), word(max))).worstRisk)
        assertEquals(Risk.WARN, review(43114, usdcAvax, call("095ea7b3", word(qiUsdcn), word(n(5_000_000)))).worstRisk)
        assertEquals(Risk.DANGER, review(43114, usdcAvax, call("095ea7b3", word(bob), word(n(5_000_000)))).worstRisk)
    }

    @Test fun nativeGateway() {
        val d = review(43114, gatewayAvax, call(Protocols.GATEWAY_DEPOSIT, word(aavePoolAvax), word(me), word(BigInteger.ZERO)), ETHER.multiply(n(2)))
        assertEquals(Risk.INFO, d.worstRisk)
        assertEquals("2 AVAX", d.headlines.single().amount)
        assertEquals(RecipientStatus.PROTOCOL, d.headlines.single().status)
        // Gateway pointed at a pool it does not belong to.
        assertEquals(Risk.DANGER, review(43114, gatewayAvax, call(Protocols.GATEWAY_DEPOSIT, word(bob), word(me), word(BigInteger.ZERO)), ETHER).worstRisk)
        val w = review(43114, gatewayAvax, call(Protocols.GATEWAY_WITHDRAW, word(aavePoolAvax), word(ETHER), word(me)))
        assertEquals(Risk.INFO, w.worstRisk)
        assertTrue(w.effect!!.contains("1 AVAX"))
    }

    @Test fun benqi() {
        val m = review(43114, qiAvax, call(Protocols.BENQI_MINT_NATIVE), ETHER.multiply(n(3)))
        assertEquals(Risk.INFO, m.worstRisk)
        assertEquals("3 AVAX", m.headlines.single().amount)
        val u = review(43114, qiUsdcn, call(Protocols.BENQI_MINT, word(n(250_000_000))))
        assertEquals(Risk.INFO, u.worstRisk)
        assertEquals("250 USDC", u.headlines.single().amount)
        assertTrue(review(43114, qiUsdcn, call(Protocols.BENQI_REDEEM_UNDERLYING, word(n(250_000_000)))).effect!!.contains("250 USDC"))
        assertTrue(review(43114, qiUsdcn, call(Protocols.BENQI_REDEEM, word(n(1_234_500_000)))).effect!!.contains("12.345 qiUSDCn"))
        // Wrong mint variant for the market, value on a non-payable call, and borrow (not decoded) are red.
        assertEquals(Risk.DANGER, review(43114, qiAvax, call(Protocols.BENQI_MINT, word(n(1)))).worstRisk)
        assertEquals(Risk.DANGER, review(43114, qiUsdcn, call(Protocols.BENQI_MINT, word(n(1))), ETHER).worstRisk)
        assertEquals(Risk.DANGER, review(43114, qiUsdcn, call(Protocols.selector("borrow(uint256)"), word(n(1)))).worstRisk)
    }

    @Test fun vaults() {
        val d = review(43114, spUsdcAvax, call(Protocols.VAULT_DEPOSIT_REF, word(n(500_000_000)), word(me), word(n(7))))
        assertEquals(Risk.INFO, d.worstRisk)
        assertEquals("500 USDC", d.headlines.single().amount)
        val sdai = Address.parse("0x83f20f44975d03b1b09e64809b757c47f942beea")!!
        val r = review(1, sdai, call(Protocols.VAULT_REDEEM, word(ETHER.multiply(n(10))), word(me), word(me)))
        assertEquals(Risk.INFO, r.worstRisk)
        assertTrue(r.effect!!.contains("10 sDAI") && r.effect!!.contains("DAI"))
        // Malformed argument length: blind-sign warning.
        assertEquals(Risk.DANGER, review(43114, spUsdcAvax, call(Protocols.VAULT_DEPOSIT, word(n(5)))).worstRisk)
    }
}
