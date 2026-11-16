package org.coldevm.signer.evm

import java.math.BigInteger

/** An unsigned EVM transaction, decoded from exactly the bytes that will be hashed and signed. */
class EvmTx(
    /** 0 = legacy (EIP-155), 2 = EIP-1559. */
    val type: Int,
    val chainId: Long,
    val nonce: BigInteger,
    val gasLimit: BigInteger,
    /** Legacy gas price; null for EIP-1559. */
    val gasPrice: BigInteger?,
    val maxFeePerGas: BigInteger?,
    val maxPriorityFeePerGas: BigInteger?,
    /** Null means contract creation. */
    val to: Address?,
    val value: BigInteger,
    val data: ByteArray,
    /** Access list entries: address and the number of storage keys. */
    val accessList: List<Pair<Address, Int>>,
) {
    /** The most the sender can pay in fees, in wei. */
    val maxFeeWei: BigInteger get() = gasLimit.multiply(maxFeePerGas ?: gasPrice!!)

    companion object {
        /** Data types of a Keystone eth-sign-request. */
        const val DATA_LEGACY = 1
        const val DATA_TYPED_DATA = 2
        const val DATA_PERSONAL_MESSAGE = 3
        const val DATA_TYPED_TRANSACTION = 4

        /** Chain ids above this cannot be represented exactly by many wallets (JavaScript numbers). */
        private val MAX_CHAIN_ID = BigInteger.valueOf(1L shl 53)

        fun parse(dataType: Int, data: ByteArray): EvmTx = when (dataType) {
            DATA_LEGACY -> parseLegacy(data)
            DATA_TYPED_TRANSACTION -> {
                require(data.isNotEmpty()) { "交易数据为空" }
                when (val t = data[0].toInt() and 0xff) {
                    0x02 -> parse1559(data)
                    0x04 -> throw UnsupportedTx("这是 EIP-7702 授权交易（把账户委托给一个合约，可被用来转走全部资产）。本钱包一律拒绝签署。")
                    0x01 -> throw UnsupportedTx("不支持 EIP-2930 (type 1) 交易")
                    0x03 -> throw UnsupportedTx("不支持 blob (type 3) 交易")
                    else -> throw UnsupportedTx("未知的交易类型 0x%02x".format(t))
                }
            }
            DATA_TYPED_DATA, DATA_PERSONAL_MESSAGE -> throw UnsupportedTx("这是消息签名请求（${if (dataType == DATA_TYPED_DATA) "EIP-712 结构化数据" else "personal_sign"}）。当前版本只签交易，拒绝。")
            else -> throw UnsupportedTx("未知的签名数据类型 $dataType")
        }

        private fun parseLegacy(data: ByteArray): EvmTx {
            val items = Rlp.decode(data).list("交易")
            if (items.size == 6) throw UnsupportedTx("没有链 ID 的旧式交易（无 EIP-155 重放保护，可在任意链上被重放），拒绝签名")
            require(items.size == 9) { "legacy 交易应有 9 个字段，实际 ${items.size}" }
            require(items[7].uint("r").signum() == 0 && items[8].uint("s").signum() == 0) { "EIP-155 待签交易的最后两个字段必须为 0" }
            return EvmTx(
                type = 0,
                chainId = chainId(items[6]),
                nonce = items[0].uint("nonce"),
                gasPrice = items[1].uint("gasPrice"),
                gasLimit = items[2].uint("gasLimit"),
                maxFeePerGas = null, maxPriorityFeePerGas = null,
                to = to(items[3]),
                value = items[4].uint("value"),
                data = items[5].bytes("data"),
                accessList = emptyList(),
            )
        }

        private fun parse1559(data: ByteArray): EvmTx {
            val items = Rlp.decode(data, 1).list("交易")
            require(items.size == 9) { "EIP-1559 交易应有 9 个字段，实际 ${items.size}" }
            val maxPriority = items[2].uint("maxPriorityFeePerGas")
            val maxFee = items[3].uint("maxFeePerGas")
            require(maxPriority <= maxFee) { "maxPriorityFeePerGas 大于 maxFeePerGas（无效交易）" }
            return EvmTx(
                type = 2,
                chainId = chainId(items[0]),
                nonce = items[1].uint("nonce"),
                maxPriorityFeePerGas = maxPriority,
                maxFeePerGas = maxFee,
                gasPrice = null,
                gasLimit = items[4].uint("gasLimit"),
                to = to(items[5]),
                value = items[6].uint("value"),
                data = items[7].bytes("data"),
                accessList = items[8].list("accessList").map { e ->
                    val pair = e.list("accessList 条目")
                    require(pair.size == 2) { "accessList 条目格式错误" }
                    val keys = pair[1].list("storageKeys")
                    keys.forEach { require(it.bytes("storageKey").size == 32) { "storageKey 应为 32 字节" } }
                    Address(pair[0].bytes("accessList 地址").also { require(it.size == 20) { "accessList 地址应为 20 字节" } }) to keys.size
                },
            )
        }

        private fun chainId(item: Rlp): Long {
            val v = item.uint("chainId")
            require(v.signum() > 0 && v < MAX_CHAIN_ID) { "链 ID 无效: $v" }
            return v.toLong()
        }

        private fun to(item: Rlp): Address? {
            val b = item.bytes("to")
            if (b.isEmpty()) return null
            require(b.size == 20) { "收款地址应为 20 字节" }
            return Address(b)
        }
    }
}

/** A well-formed request this wallet refuses on principle (as opposed to malformed data). */
class UnsupportedTx(message: String) : Exception(message)
