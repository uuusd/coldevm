package org.coldevm.signer.evm

import java.math.BigDecimal

/**
 * A chain this wallet knows by id. Anything else is shown as an unknown chain with a warning.
 * [feeWarn] is the maximum fee (in native units) above which the review warns; 10× that is red.
 */
class Chain(val id: Long, val name: String, val symbol: String, feeWarn: String, val testnet: Boolean = false) {
    val feeWarn = BigDecimal(feeWarn)
}

object Chains {
    private val list = listOf(
        Chain(1, "Ethereum", "ETH", "0.03"),
        Chain(10, "Optimism", "ETH", "0.01"),
        Chain(56, "BNB Smart Chain", "BNB", "0.01"),
        Chain(100, "Gnosis", "xDAI", "5"),
        Chain(137, "Polygon", "POL", "10"),
        Chain(196, "X Layer", "OKB", "0.2"),
        Chain(204, "opBNB", "BNB", "0.01"),
        Chain(324, "zkSync Era", "ETH", "0.01"),
        Chain(5000, "Mantle", "MNT", "20"),
        Chain(8453, "Base", "ETH", "0.01"),
        Chain(42161, "Arbitrum One", "ETH", "0.01"),
        Chain(43114, "Avalanche C-Chain", "AVAX", "0.5"),
        Chain(59144, "Linea", "ETH", "0.01"),
        Chain(81457, "Blast", "ETH", "0.01"),
        Chain(534352, "Scroll", "ETH", "0.01"),
        Chain(11155111, "Sepolia 测试网", "SepoliaETH", "1", testnet = true),
    ).associateBy { it.id }

    fun find(id: Long): Chain? = list[id]
}

/** A token contract whose symbol and decimals are known offline. */
class Token(val chainId: Long, val address: Address, val symbol: String, val decimals: Int)

/**
 * A short built-in list: USDT and USDC on major chains plus the assets of the recognised protocols. A token not listed here is shown as
 * "unknown token" with its raw amount: a fake token can copy any name, but not these addresses.
 */
object Tokens {
    private fun t(chain: Long, addr: String, symbol: String, decimals: Int) = Token(chain, Address.parse(addr)!!, symbol, decimals)

    private val list = listOf(
        t(1, "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT", 6),
        t(1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "USDC", 6),
        t(56, "0x55d398326f99059ff775485246999027b3197955", "USDT", 18),
        t(56, "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", "USDC", 18),
        t(137, "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", "USDT", 6),
        t(137, "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", "USDC", 6),
        t(43114, "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", "USDT", 6),
        t(43114, "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e", "USDC", 6),
        t(42161, "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", "USDT", 6),
        t(42161, "0xaf88d065e77c8cc2239327c5edb3a432268e5831", "USDC", 6),
        t(8453, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "USDC", 6),
        // Underlying assets of the protocols in Protocols.kt, read on chain 2026-11-16 (ERC-4626 asset(), Benqi
        // underlying(), then symbol() / decimals()), so approvals and deposits show real amounts.
        t(1, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "WETH", 18),
        t(1, "0x6b175474e89094c44da98b954eedeac495271d0f", "DAI", 18),
        t(1, "0xdc035d45d973e3ec169d2276ddab16f1e407384f", "USDS", 18),
        t(1, "0x6c3ea9036406852006290770bedfcaba0e23a0e8", "PYUSD", 6),
        t(43114, "0x2b2c81e08f1af8835a78bb2a90ae924ace0ea4be", "sAVAX", 18),
        t(43114, "0x152b9d0fdc40c096757f570a51e494bd4b943e50", "BTC.b", 8),
        t(43114, "0x49d5c2bdffac6ce2bfdb6640f4f80f226bc10bab", "WETH.e", 18),
        t(43114, "0x5947bb275c521040051d82396192181b413227a3", "LINK.e", 18),
        t(43114, "0xc7198437980c041c805a1edcba50c1ce5db95118", "USDT.e", 6),
        t(43114, "0xa7d7079b0fead91f3e65f86e8915cb59c1a4c664", "USDC.e", 6),
        t(43114, "0xd586e7f844cea2f87f50152665bcbc2c279d8d70", "DAI.e", 18),
    )

    fun find(chainId: Long, address: Address): Token? = list.firstOrNull { it.chainId == chainId && it.address == address }
}
