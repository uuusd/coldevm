package org.coldevm.signer.evm

import org.coldevm.signer.crypto.Keccak
import org.coldevm.signer.crypto.toHex

/** The lending / savings protocols ColdEVM can decode. Addresses are per chain; nothing is matched by name. */
enum class ProtocolKind { AAVE_POOL, AAVE_GATEWAY, VAULT, BENQI_MARKET }

class ProtocolContract(
    val chainId: Long,
    val address: Address,
    val kind: ProtocolKind,
    /** Shown to the user, e.g. "Aave V3 Pool" or "Spark spUSDC 金库". */
    val name: String,
    /** Underlying asset symbol and decimals: vault asset, Benqi underlying, or the wrapped native coin of a gateway. */
    val assetSymbol: String? = null,
    val assetDecimals: Int = 18,
    /** Share / qiToken symbol and decimals (vaults and Benqi markets). */
    val shareSymbol: String? = null,
    val shareDecimals: Int = 18,
    /** Benqi qiAVAX: mint() takes the native coin. */
    val native: Boolean = false,
)

/**
 * Contract addresses, verified on 2026-11-16:
 * - Aave V3 Pool and WrappedTokenGatewayV3 from bgd-labs/aave-address-book; on chain, PoolAddressesProvider.getPool()
 *   returns the pool and the gateway wraps the chain's native coin.
 * - SparkLend Pool / gateway from sparkdotfi/spark-address-registry (SparkLend.sol); provider and pool agree on chain.
 * - Spark savings vaults from the same registry; asset() and decimals read on chain (ERC-4626).
 * - Benqi core markets from docs.benqi.fi; each is listed in Comptroller 0x486Af395…D9b4 getAllMarkets(), with
 *   symbol(), underlying() and decimals read on chain.
 */
object Protocols {
    private fun a(s: String) = Address.parse(s.lowercase())!!

    private val aavePools = mapOf(
        1L to "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", 10L to "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
        56L to "0x6807dc923806fE8Fd134338EABCA509979a7e0cB", 100L to "0xb50201558B00496A145fE76f7424749556E326D8",
        137L to "0x794a61358D6845594F94dc1DB02A252b5b4814aD", 324L to "0x78e30497a3c7527d953c6B1E3541b021A98Ac43c",
        8453L to "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5", 42161L to "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
        43114L to "0x794a61358D6845594F94dc1DB02A252b5b4814aD", 59144L to "0xc47b8C00b0f69a36fa203Ffeac0334874574a8Ac",
        534352L to "0x11fCfe756c05AD438e312a7fd934381537D3cFfe",
    )
    private val aaveGateways = mapOf(
        1L to "0xd01607c3C5eCABa394D8be377a08590149325722", 10L to "0x5f2508cAE9923b02316254026CD43d7902866725",
        56L to "0x0c2C95b24529664fE55D4437D7A31175CFE6c4f7", 100L to "0x721B9abAb6511b46b9ee83A1aba23BDAcB004149",
        137L to "0xBC302053db3aA514A3c86B9221082f162B91ad63", 324L to "0xAE2b00D676130Bdf22582781BbBA8f4F21e8B0ff",
        8453L to "0xa0d9C1E9E48Ca30c8d8C3B5D69FF5dc1f6DFfC24", 42161L to "0x5283BEcEd7ADF6D003225C13896E536f2D4264FF",
        43114L to "0x2825cE5921538d17cc15Ae00a8B24fF759C6CDaE", 59144L to "0x31A239f3e39c5D8BA6B201bA81ed584492Ae960F",
        534352L to "0xE79Ca44408Dae5a57eA2a9594532f1E84d2edAa4",
    )

    private val list: List<ProtocolContract> = buildList {
        aavePools.forEach { (c, p) -> add(ProtocolContract(c, a(p), ProtocolKind.AAVE_POOL, "Aave V3 Pool")) }
        aaveGateways.forEach { (c, g) -> add(ProtocolContract(c, a(g), ProtocolKind.AAVE_GATEWAY, "Aave V3 原生币存取入口")) }
        add(ProtocolContract(1, a("0xC13e21B648A5Ee794902342038FF3aDAB66BE987"), ProtocolKind.AAVE_POOL, "SparkLend Pool"))
        add(ProtocolContract(1, a("0xBD7D6a9ad7865463DE44B05F04559f65e3B11704"), ProtocolKind.AAVE_GATEWAY, "SparkLend 原生币存取入口"))
        fun vault(c: Long, addr: String, share: String, sd: Int, asset: String, ad: Int) =
            add(ProtocolContract(c, a(addr), ProtocolKind.VAULT, "Spark $share 金库", asset, ad, share, sd))
        vault(1, "0xfE6eb3b609a7C8352A241f7F3A21CEA4e9209B8f", "spETH", 18, "WETH", 18)
        vault(1, "0x80128DbB9f07b93DDE62A6daeadb69ED14a7D354", "spPYUSD", 6, "PYUSD", 6)
        vault(1, "0x28B3a8fb53B741A8Fd78c0fb9A6B2393d896a43d", "spUSDC", 6, "USDC", 6)
        vault(1, "0xe2e7a17dFf93280dec073C995595155283e3C372", "spUSDT", 6, "USDT", 6)
        vault(1, "0xBc65ad17c5C0a2A4D159fa5a503f4992c7B545FE", "sUSDC", 18, "USDC", 6)
        vault(1, "0x83F20F44975D03b1b09e64809B757c47f942BEeA", "sDAI", 18, "DAI", 18)
        vault(1, "0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD", "sUSDS", 18, "USDS", 18)
        vault(43114, "0x28B3a8fb53B741A8Fd78c0fb9A6B2393d896a43d", "spUSDC", 6, "USDC", 6)
        vault(8453, "0x3128a0F7f0ea68E7B7c9B00AFa7E41045828e858", "sUSDC", 18, "USDC", 6)
        vault(42161, "0x45d91340B3B7B96985A72b5c678F7D9e8D664b62", "spUSDT", 6, "USDT0", 6)
        vault(42161, "0x940098b108fB7D0a7E374f6eDED7760787464609", "sUSDC", 18, "USDC", 6)
        fun benqi(addr: String, qi: String, und: String, ud: Int, native: Boolean = false) =
            add(ProtocolContract(43114, a(addr), ProtocolKind.BENQI_MARKET, "Benqi $qi 市场", und, ud, qi, 8, native))
        benqi("0x5C0401e81Bc07Ca70fAD469b451682c0d747Ef1c", "qiAVAX", "AVAX", 18, native = true)
        benqi("0xF362feA9659cf036792c9cb02f8ff8198E21B4cB", "qisAVAX", "sAVAX", 18)
        benqi("0x89a415b3D20098E6A6C8f7a59001C67BD3129821", "qiBTC.b", "BTC.b", 8)
        benqi("0x334AD834Cd4481BB02d09615E7c11a00579A7909", "qiETH", "WETH.e", 18)
        benqi("0x4e9f683A27a6BdAD3FC2764003759277e93696e6", "qiLINK", "LINK.e", 18)
        benqi("0xc9e5999b8e75C3fEB117F6f73E664b9f3C8ca65C", "qiUSDT", "USDT.e", 6)
        benqi("0xBEb5d47A3f720Ec0a390d04b4d41ED7d9688bC7F", "qiUSDC", "USDC.e", 6)
        benqi("0xd8fcDa6ec4Bdc547C0827B8804e89aCd817d56EF", "qiUSDTn", "USDT", 6)
        benqi("0xB715808a78F6041E46d61Cb123C9B4A27056AE9C", "qiUSDCn", "USDC", 6)
        benqi("0x835866d37AFB8CB8F8334dCCdaf66cf01832Ff5D", "qiDAI", "DAI.e", 18)
    }

    fun find(chainId: Long, address: Address): ProtocolContract? = list.firstOrNull { it.chainId == chainId && it.address == address }

    /** "Aave V3 Pool (Avalanche C-Chain)" style label for an approval spender or call target. */
    fun label(p: ProtocolContract): String = "${p.name}（${Chains.find(p.chainId)?.name ?: "chainId ${p.chainId}"}）"

    /** 4-byte selector of a function signature, computed rather than copied. */
    fun selector(signature: String): String = Keccak.hash(signature.toByteArray()).copyOfRange(0, 4).toHex()

    val AAVE_SUPPLY = selector("supply(address,uint256,address,uint16)")
    val AAVE_DEPOSIT = selector("deposit(address,uint256,address,uint16)")
    val AAVE_WITHDRAW = selector("withdraw(address,uint256,address)")
    val GATEWAY_DEPOSIT = selector("depositETH(address,address,uint16)")
    val GATEWAY_WITHDRAW = selector("withdrawETH(address,uint256,address)")
    val VAULT_DEPOSIT = selector("deposit(uint256,address)")
    val VAULT_DEPOSIT_REF = selector("deposit(uint256,address,uint16)")
    val VAULT_DEPOSIT_MIN_REF = selector("deposit(uint256,address,uint256,uint16)")
    val VAULT_MINT = selector("mint(uint256,address)")
    val VAULT_MINT_REF = selector("mint(uint256,address,uint16)")
    val VAULT_MINT_MAX_REF = selector("mint(uint256,address,uint256,uint16)")
    val VAULT_WITHDRAW = selector("withdraw(uint256,address,address)")
    val VAULT_WITHDRAW_MAX = selector("withdraw(uint256,address,address,uint256)")
    val VAULT_REDEEM = selector("redeem(uint256,address,address)")
    val VAULT_REDEEM_MIN = selector("redeem(uint256,address,address,uint256)")
    val BENQI_MINT = selector("mint(uint256)")
    val BENQI_MINT_NATIVE = selector("mint()")
    val BENQI_REDEEM = selector("redeem(uint256)")
    val BENQI_REDEEM_UNDERLYING = selector("redeemUnderlying(uint256)")
}
