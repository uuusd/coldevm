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
 * A short built-in list of USDT and USDC contracts on major chains. A token not listed here is shown as
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
    )

    fun find(chainId: Long, address: Address): Token? = list.firstOrNull { it.chainId == chainId && it.address == address }
}
