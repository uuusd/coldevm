package org.coldevm.signer.evm

import org.coldevm.signer.crypto.toHex
import java.math.BigDecimal
import java.math.BigInteger

enum class Risk { INFO, WARN, DANGER }

class Field(val label: String, val value: String, val highlight: Boolean = false)

enum class RecipientStatus {
    /** One of this device's own accounts. */
    SELF,
    /** Signed a transfer to this exact address before. */
    KNOWN,
    /** First transfer to this address. */
    NEW,
    /** A lending / savings contract recognised by chain and address (see [Protocols]). */
    PROTOCOL,
}

/** One "what leaves the wallet" line at the top of the review screen. */
class Headline(
    val amount: String,
    val to: String,
    val status: RecipientStatus,
    val ownLabel: String? = null,
    val timesBefore: Int = 0,
    /** A red, unmissable reason the recipient looks wrong (look-alike address, token contract itself, …). */
    val alert: String? = null,
)

class TxSummary(
    /** Short name of what the transaction does, e.g. "转账 USDT" or "授权 (approve)". */
    val action: String,
    val chainLabel: String,
    val headlines: List<Headline>,
    /** Non-payment effect shown in large type when there is no headline (approvals, contract calls). */
    val effect: String?,
    val fields: List<Field>,
    val warnings: List<Pair<Risk, String>>,
    val maxFee: String,
    /** How alarming the fee is on its own (also listed in [warnings]). */
    val feeRisk: Risk,
    val nonce: BigInteger,
    /** Recipients of transfers, remembered after signing to flag look-alike addresses later. */
    val recipients: List<Address>,
) {
    val worstRisk: Risk get() = warnings.maxOfOrNull { it.first } ?: Risk.INFO

    /** A red item needs an explicit "I understand" tick before the sign button works. */
    val needsAcknowledgement: Boolean get() = worstRisk == Risk.DANGER
}

/**
 * Turns a decoded transaction into what the user must see before signing.
 *
 * @param own labels for every address this device controls (all wallets).
 * @param history how many transfers were signed to each address before.
 */
class Describer(private val own: Map<Address, String>, private val history: Map<Address, Int>) {

    fun describe(tx: EvmTx): TxSummary {
        val chain = Chains.find(tx.chainId)
        val symbol = chain?.symbol ?: "原生币"
        val warnings = mutableListOf<Pair<Risk, String>>()
        val fields = mutableListOf<Field>()
        val headlines = mutableListOf<Headline>()
        val recipients = mutableListOf<Address>()
        var effect: String? = null
        val action: String

        if (chain == null) warnings += Risk.WARN to "未知链 ID ${tx.chainId}：原生币名称和小数位无法离线确认（按 18 位显示）。请确认 OKX 中选择的网络。"
        if (chain?.testnet == true) warnings += Risk.INFO to "测试网交易"
        if (tx.accessList.isNotEmpty()) warnings += Risk.WARN to "交易附带访问列表（${tx.accessList.size} 个地址），普通转账不需要"
        val unitPrice = tx.maxFeePerGas ?: tx.gasPrice!!
        val fee = BigDecimal(tx.maxFeeWei, 18)
        val feeText = "${fee.stripTrailingZeros().toPlainString()} $symbol"
        // Legacy gas price and the EIP-1559 priority fee are really paid, so an inflated fee is a real loss.
        var feeRisk = Risk.INFO
        if (chain != null) {
            if (fee > chain.feeWarn.multiply(BigDecimal.TEN)) {
                feeRisk = Risk.DANGER
                warnings += Risk.DANGER to "手续费上限 $feeText，远高于正常水平（Gas 上限 ${tx.gasLimit} × 单价 ${gwei(unitPrice)} gwei）。可能是联网端被篡改，请在 OKX/Rabby 中重新设置手续费。"
            } else if (fee > chain.feeWarn) {
                feeRisk = Risk.WARN
                warnings += Risk.WARN to "手续费上限 $feeText，高于常见水平，请核对"
            }
        } else if (unitPrice > GWEI.multiply(BigInteger.valueOf(5000))) {
            feeRisk = Risk.WARN
            warnings += Risk.WARN to "gas 单价异常高（${gwei(unitPrice)} gwei），请核对手续费"
        }
        if (tx.data.isEmpty() && tx.value.signum() > 0 && tx.maxFeeWei > tx.value && (chain == null || fee > chain.feeWarn.divide(BigDecimal.TEN))) {
            if (feeRisk == Risk.INFO) feeRisk = Risk.WARN
            warnings += Risk.WARN to "手续费上限（$feeText）高于转账金额"
        }

        fun pay(amount: String, to: Address) {
            headlines += headline(amount, to, tx.chainId)
            if (to !in own) recipients += to
        }

        /** Funds going into a recognised protocol contract: shown with its name, not added to the recipient history. */
        fun deposit(amount: String, p: ProtocolContract) {
            headlines += Headline(amount, p.address.checksummed, RecipientStatus.PROTOCOL, ownLabel = Protocols.label(p))
        }

        val to = tx.to
        val data = tx.data
        when {
            to == null -> {
                action = "部署合约"
                effect = "部署新合约"
                warnings += Risk.DANGER to "这是一笔合约部署交易（没有收款地址），普通用户几乎不会用到"
                if (tx.value.signum() > 0) warnings += Risk.DANGER to "同时向新合约转入 ${amount(tx.value, 18)} $symbol"
                fields += Field("代码长度", "${data.size} 字节")
            }
            data.isEmpty() -> {
                action = "转账 $symbol"
                if (tx.value.signum() == 0 && to in own) {
                    effect = "0 金额发给自己"
                    warnings += Risk.INFO to "发给自己的 0 金额交易，通常用于取消或加速一笔未确认的交易（nonce ${tx.nonce}）"
                } else {
                    pay("${amount(tx.value, 18)} $symbol", to)
                    if (tx.value.signum() == 0) warnings += Risk.WARN to "转账金额为 0"
                }
            }
            else -> {
                val (h0, r0, w0) = Triple(headlines.size, recipients.size, warnings.size)
                val call = runCatching {
                    Protocols.find(tx.chainId, to)?.let { decodeProtocol(tx, it, symbol, warnings, fields, ::deposit) }
                        ?: decodeCall(tx, to, symbol, warnings, fields, ::pay)
                }.getOrElse { e ->
                    // Nothing a half-finished decode produced may stay on screen: no "deposit into …" line with a
                    // green tick next to a call whose arguments turned out to be malformed.
                    fields.clear()
                    headlines.subList(h0, headlines.size).clear()
                    recipients.subList(r0, recipients.size).clear()
                    warnings.subList(w0, warnings.size).clear()
                    warnings += Risk.DANGER to "合约调用参数格式异常（${e.message}），无法解析，相当于盲签"
                    null
                }
                if (call != null) {
                    action = call.first; effect = call.second
                } else {
                    action = "合约调用"
                    effect = "调用合约（无法解析）"
                }
                if (call == null || call.third) {
                    fields += Field("合约", to.checksummed, highlight = true)
                    fields += Field("函数选择器", "0x" + data.copyOfRange(0, minOf(4, data.size)).toHex())
                    fields += Field("调用数据", "${data.size} 字节")
                    if (tx.value.signum() > 0) pay("${amount(tx.value, 18)} $symbol", to)
                }
            }
        }

        // A recipient alert (look-alike address, token contract as recipient) is red like any other danger: it must
        // colour the summary and require the explicit acknowledgement, not only show as text under the address.
        headlines.mapNotNull { it.alert }.distinct().forEach { warnings += Risk.DANGER to it }

        fields += Field("链", chainLabel(tx.chainId))
        fields += Field("Nonce", tx.nonce.toString())
        fields += Field("Gas 上限", tx.gasLimit.toString())
        if (tx.type == 2) {
            fields += Field("Max fee", "${gwei(tx.maxFeePerGas!!)} gwei")
            fields += Field("优先费", "${gwei(tx.maxPriorityFeePerGas!!)} gwei")
        } else {
            fields += Field("Gas 单价", "${gwei(tx.gasPrice!!)} gwei")
        }
        fields += Field("交易类型", if (tx.type == 2) "EIP-1559" else "Legacy (EIP-155)")

        return TxSummary(
            action = action,
            chainLabel = chainLabel(tx.chainId),
            headlines = headlines,
            effect = effect,
            fields = fields,
            warnings = warnings,
            maxFee = feeText,
            feeRisk = feeRisk,
            nonce = tx.nonce,
            recipients = recipients,
        )
    }

    /**
     * Decodes the few calls a cold wallet should understand. Returns (action, effect, unknown) where unknown means
     * the call was not recognised (blind signing); throws on malformed arguments.
     */
    private fun decodeCall(
        tx: EvmTx, contract: Address, symbol: String,
        warnings: MutableList<Pair<Risk, String>>, fields: MutableList<Field>,
        pay: (String, Address) -> Unit,
    ): Triple<String, String?, Boolean> {
        val data = tx.data
        require(data.size >= 4) { "调用数据不足 4 字节" }
        val sel = data.copyOfRange(0, 4).toHex()
        val args = Args(data)
        val token = Tokens.find(tx.chainId, contract)
        val tokenName = token?.symbol ?: "未知代币"
        fun tokenAmount(v: BigInteger) = if (token != null) "${amount(v, token.decimals)} ${token.symbol}" else "$v（原始数量，小数位未知）"
        fun tokenFields() {
            fields += Field("代币合约", contract.checksummed + (token?.let { " (${it.symbol})" } ?: ""), highlight = token == null)
            if (token == null) warnings += Risk.WARN to "未知代币合约：名称和小数位无法离线确认，数量按原始整数显示。假冒代币可以使用任何名称。"
        }
        val nativeWithCall = tx.value.signum() > 0

        val result: Triple<String, String?, Boolean> = when (sel) {
            SEL_TRANSFER -> {
                args.expect(2)
                val to = args.address(0); val v = args.uint(1)
                tokenFields()
                pay(tokenAmount(v), to)
                // A listed token contract as recipient is already flagged by the headline alert.
                if (to == contract && token == null) warnings += Risk.DANGER to "收款地址就是代币合约本身，转过去的代币通常无法取回"
                Triple("转账 $tokenName", null, false)
            }
            SEL_APPROVE, SEL_INCREASE_ALLOWANCE -> {
                args.expect(2)
                val spender = args.address(0); val v = args.uint(1)
                tokenFields()
                val protocol = Protocols.find(tx.chainId, spender)
                fields += Field("被授权方", spender.checksummed + (own[spender]?.let { " ($it)" } ?: protocol?.let { " (${Protocols.label(it)})" } ?: ""), highlight = true)
                val unlimited = v >= UNLIMITED
                // Finite but absurd: more than 10^12 whole tokens (or ≥ 2^96 raw units of an unknown token).
                val huge = !unlimited && v > (token?.let { BigInteger.TEN.pow(it.decimals + 12) } ?: HUGE_RAW)
                val amountText = if (unlimited) "无限额度" else tokenAmount(v)
                fields += Field(if (sel == SEL_APPROVE) "授权额度" else "增加额度", amountText, highlight = true)
                if (sel == SEL_APPROVE && v.signum() == 0) {
                    Triple("撤销授权", "撤销 ${spender.short()} 对 $tokenName 的授权", false)
                } else {
                    if (protocol != null && !unlimited && !huge) {
                        // Approving exactly the amount about to be deposited into a recognised protocol is routine.
                        warnings += Risk.WARN to "授权 ${Protocols.label(protocol)} 动用你的 $tokenName（$amountText），通常是存入前的一步。合约地址已离线核对。"
                    } else {
                        warnings += Risk.DANGER to "授权 ${spender.checksummed} 动用你的 $tokenName（$amountText）。对方之后无需你再签名即可转走这些代币，只授权给你确认过的合约。"
                    }
                    if (unlimited) warnings += Risk.DANGER to "无限额度授权：对方可以转走这个代币的全部余额（包括以后收到的）" +
                        (protocol?.let { "。即使是 ${it.name}，也建议只授权本次存入的数量" } ?: "")
                    else if (huge) warnings += Risk.DANGER to "授权额度极大（$amountText），实际上等于无限授权" +
                        (protocol?.let { "。即使是 ${it.name}，也建议只授权本次存入的数量" } ?: "")
                    val target = protocol?.name ?: tokenName
                    Triple(if (sel == SEL_APPROVE) "授权 (approve)" else "增加授权 (increaseAllowance)", if (protocol != null) "授权 ${protocol.name} 使用 $tokenName：$amountText" else "授权 $target：$amountText", false)
                }
            }
            SEL_SET_APPROVAL_FOR_ALL -> {
                args.expect(2)
                val operator = args.address(0); val approved = args.bool(1)
                fields += Field("NFT 合约", contract.checksummed, highlight = true)
                fields += Field("操作方", operator.checksummed, highlight = true)
                if (approved) {
                    warnings += Risk.DANGER to "setApprovalForAll：允许 ${operator.checksummed} 转走你在这个合约下的全部 NFT/资产。这是最常见的钓鱼手法之一。"
                    Triple("全部授权 (setApprovalForAll)", "授权对方转走全部 NFT", false)
                } else {
                    Triple("撤销全部授权", "撤销 ${operator.short()} 的全部授权", false)
                }
            }
            SEL_TRANSFER_FROM, SEL_SAFE_TRANSFER_FROM, SEL_SAFE_TRANSFER_FROM_DATA -> {
                if (sel == SEL_SAFE_TRANSFER_FROM_DATA) args.atLeast(4) else args.expect(3)
                val from = args.address(0); val to = args.address(1); val v = args.uint(2)
                fields += Field("合约", contract.checksummed + (token?.let { " (${it.symbol})" } ?: ""), highlight = true)
                fields += Field("从", from.checksummed + (own[from]?.let { " ($it)" } ?: ""))
                val isToken = token != null && sel == SEL_TRANSFER_FROM
                val what = if (isToken) tokenAmount(v) else "NFT #$v（或数量 $v）"
                if (from in own) pay(what, to) else {
                    fields += Field("到", to.checksummed, highlight = true)
                    fields += Field("数量 / 编号", what)
                    warnings += Risk.WARN to "转出方不是本钱包的账户（使用别人给你的授权转账）"
                }
                if (!isToken) warnings += Risk.WARN to "NFT / 未知合约的转移，编号或数量无法离线确认含义"
                if (sel == SEL_SAFE_TRANSFER_FROM_DATA) warnings += Risk.WARN to "附带额外数据，会传给收款合约处理"
                Triple(if (isToken) "转账 $tokenName (transferFrom)" else "NFT 转移", null, false)
            }
            else -> {
                warnings += Risk.DANGER to "未知的合约调用（函数 0x$sel），离线无法解析它会做什么，相当于盲签。只在你完全确认 DApp 和合约可信时签名。"
                Triple("合约调用", "调用合约 ${contract.short()}", true)
            }
        }
        if (nativeWithCall && !result.third) {
            warnings += Risk.DANGER to "这笔调用同时向合约转入 ${amount(tx.value, 18)} $symbol，普通代币操作不需要"
            pay("${amount(tx.value, 18)} $symbol", contract)
        }
        return result
    }

    /**
     * Calls into a recognised lending / savings contract. Returns null for functions it does not decode (borrow,
     * liquidation, share transfers, …), which then go through [decodeCall] like any other contract call.
     * Every parameter that decides who receives funds or shares must be one of this device's accounts.
     */
    private fun decodeProtocol(
        tx: EvmTx, p: ProtocolContract, symbol: String,
        warnings: MutableList<Pair<Risk, String>>, fields: MutableList<Field>,
        deposit: (String, ProtocolContract) -> Unit,
    ): Triple<String, String?, Boolean>? {
        val data = tx.data
        require(data.size >= 4) { "调用数据不足 4 字节" }
        val sel = data.copyOfRange(0, 4).toHex()
        val args = Args(data)
        val label = Protocols.label(p)
        var payable = false
        fun mustBeOwn(a: Address, role: String) {
            val mine = own[a]
            fields += Field(role, a.checksummed + (mine?.let { " ($it)" } ?: ""), highlight = mine == null)
            if (mine == null) warnings += Risk.DANGER to "$role 不是本机的账户：${a.checksummed}。资金或份额会记到别人名下！"
        }
        fun assetAmount(asset: Address, v: BigInteger): String {
            if (v == MAX_UINT) return "全部"
            val t = Tokens.find(tx.chainId, asset)
            if (t == null) {
                fields += Field("资产合约", asset.checksummed, highlight = true)
                warnings += Risk.WARN to "资产 ${asset.checksummed} 不在内置代币表中，数量按原始整数显示"
                return "$v（原始数量）"
            }
            return "${amount(v, t.decimals)} ${t.symbol}"
        }
        fun units(v: BigInteger, decimals: Int, sym: String?) = if (v == MAX_UINT) "全部" else "${amount(v, decimals)} ${sym ?: ""}".trim()
        fun poolMatches(pool: Address) {
            val target = Protocols.find(tx.chainId, pool)
            fields += Field("借贷池", pool.checksummed + (target?.let { " (${it.name})" } ?: ""), highlight = target == null)
            if (target?.kind != ProtocolKind.AAVE_POOL) warnings += Risk.DANGER to "原生币存取入口指向了未识别的借贷池 ${pool.checksummed}"
        }
        fields += Field("协议合约", "${p.address.checksummed} ($label)")

        val result: Triple<String, String?, Boolean> = when (p.kind) {
            ProtocolKind.AAVE_POOL -> when (sel) {
                Protocols.AAVE_SUPPLY, Protocols.AAVE_DEPOSIT -> {
                    args.expect(4)
                    deposit(assetAmount(args.address(0), args.uint(1)), p)
                    mustBeOwn(args.address(2), "存款记入的账户 (onBehalfOf)")
                    Triple("存入 ${p.name}", null, false)
                }
                Protocols.AAVE_WITHDRAW -> {
                    args.expect(3)
                    val amt = assetAmount(args.address(0), args.uint(1))
                    mustBeOwn(args.address(2), "取款收款地址 (to)")
                    Triple("从 ${p.name} 取出", "从 $label 取出 $amt", false)
                }
                else -> return null
            }
            ProtocolKind.AAVE_GATEWAY -> when (sel) {
                Protocols.GATEWAY_DEPOSIT -> {
                    args.expect(3)
                    poolMatches(args.address(0))
                    mustBeOwn(args.address(1), "存款记入的账户 (onBehalfOf)")
                    payable = true
                    if (tx.value.signum() == 0) warnings += Risk.WARN to "存入金额为 0"
                    deposit("${amount(tx.value, 18)} $symbol", p)
                    Triple("存入 $symbol（${p.name.removeSuffix(" 原生币存取入口")}）", null, false)
                }
                Protocols.GATEWAY_WITHDRAW -> {
                    args.expect(3)
                    poolMatches(args.address(0))
                    val v = args.uint(1)
                    mustBeOwn(args.address(2), "取款收款地址 (to)")
                    Triple("取出 $symbol", "从 $label 取出 ${units(v, 18, symbol)}", false)
                }
                else -> return null
            }
            ProtocolKind.VAULT -> when (sel) {
                Protocols.VAULT_DEPOSIT, Protocols.VAULT_DEPOSIT_REF, Protocols.VAULT_DEPOSIT_MIN_REF -> {
                    args.expect(when (sel) { Protocols.VAULT_DEPOSIT -> 2; Protocols.VAULT_DEPOSIT_REF -> 3; else -> 4 })
                    deposit(units(args.uint(0), p.assetDecimals, p.assetSymbol), p)
                    mustBeOwn(args.address(1), "份额接收账户 (receiver)")
                    if (sel == Protocols.VAULT_DEPOSIT_MIN_REF) fields += Field("最少获得份额", units(args.uint(2), p.shareDecimals, p.shareSymbol))
                    Triple("存入 ${p.name}", null, false)
                }
                Protocols.VAULT_MINT, Protocols.VAULT_MINT_REF, Protocols.VAULT_MINT_MAX_REF -> {
                    args.expect(when (sel) { Protocols.VAULT_MINT -> 2; Protocols.VAULT_MINT_REF -> 3; else -> 4 })
                    val shares = units(args.uint(0), p.shareDecimals, p.shareSymbol)
                    val max = if (sel == Protocols.VAULT_MINT_MAX_REF) "（最多 ${units(args.uint(2), p.assetDecimals, p.assetSymbol)}）" else ""
                    deposit("换取 $shares 所需的 ${p.assetSymbol}$max", p)
                    mustBeOwn(args.address(1), "份额接收账户 (receiver)")
                    Triple("存入 ${p.name}", null, false)
                }
                Protocols.VAULT_WITHDRAW, Protocols.VAULT_WITHDRAW_MAX -> {
                    args.expect(if (sel == Protocols.VAULT_WITHDRAW) 3 else 4)
                    val amt = units(args.uint(0), p.assetDecimals, p.assetSymbol)
                    mustBeOwn(args.address(1), "取款收款地址 (receiver)")
                    mustBeOwn(args.address(2), "份额所有者 (owner)")
                    Triple("从 ${p.name} 取出", "从 $label 取出 $amt", false)
                }
                Protocols.VAULT_REDEEM, Protocols.VAULT_REDEEM_MIN -> {
                    args.expect(if (sel == Protocols.VAULT_REDEEM) 3 else 4)
                    val shares = units(args.uint(0), p.shareDecimals, p.shareSymbol)
                    mustBeOwn(args.address(1), "取款收款地址 (receiver)")
                    mustBeOwn(args.address(2), "份额所有者 (owner)")
                    if (sel == Protocols.VAULT_REDEEM_MIN) fields += Field("最少取回", units(args.uint(3), p.assetDecimals, p.assetSymbol))
                    Triple("从 ${p.name} 赎回", "从 $label 赎回 $shares（换回 ${p.assetSymbol}）", false)
                }
                else -> return null
            }
            ProtocolKind.BENQI_MARKET -> when (sel) {
                Protocols.BENQI_MINT_NATIVE -> {
                    args.expect(0)
                    if (!p.native) throw IllegalArgumentException("mint() 只用于 qiAVAX 市场")
                    payable = true
                    deposit("${amount(tx.value, 18)} $symbol", p)
                    Triple("存入 ${p.name}", null, false)
                }
                Protocols.BENQI_MINT -> {
                    args.expect(1)
                    if (p.native) throw IllegalArgumentException("qiAVAX 市场应使用 mint()")
                    deposit(units(args.uint(0), p.assetDecimals, p.assetSymbol), p)
                    Triple("存入 ${p.name}", null, false)
                }
                Protocols.BENQI_REDEEM -> {
                    args.expect(1)
                    Triple("从 ${p.name} 赎回", "从 $label 赎回 ${units(args.uint(0), p.shareDecimals, p.shareSymbol)}（换回 ${p.assetSymbol}，转到本账户）", false)
                }
                Protocols.BENQI_REDEEM_UNDERLYING -> {
                    args.expect(1)
                    Triple("从 ${p.name} 取出", "从 $label 取出 ${units(args.uint(0), p.assetDecimals, p.assetSymbol)}（转到本账户）", false)
                }
                else -> return null
            }
        }
        if (tx.value.signum() > 0 && !payable) {
            warnings += Risk.DANGER to "这笔调用同时向合约转入 ${amount(tx.value, 18)} $symbol，这个操作不需要原生币"
            deposit("${amount(tx.value, 18)} $symbol", p)
        }
        return result
    }

    private fun headline(amount: String, to: Address, chainId: Long): Headline {
        own[to]?.let { return Headline(amount, to.checksummed, RecipientStatus.SELF, ownLabel = it) }
        val count = history[to] ?: 0
        val alert = when {
            Tokens.find(chainId, to) != null -> "收款地址是代币合约本身，转过去的资产通常无法取回"
            count == 0 -> lookAlike(to)?.let { "疑似地址投毒：与${it.second} ${it.first.checksummed} 首尾相同，但不是同一个地址！" }
            else -> null
        }
        return Headline(amount, to.checksummed, if (count > 0) RecipientStatus.KNOWN else RecipientStatus.NEW, timesBefore = count, alert = alert)
    }

    /** An own or previously paid address with the same first and last hex digits as [a], but different. */
    private fun lookAlike(a: Address): Pair<Address, String>? {
        val hex = a.checksummed.lowercase()
        fun similar(b: Address) = b != a && b.checksummed.lowercase().let { it.substring(2, 2 + EDGE) == hex.substring(2, 2 + EDGE) && it.takeLast(EDGE) == hex.takeLast(EDGE) }
        own.keys.firstOrNull(::similar)?.let { return it to "本机账户（${own[it]}）" }
        history.keys.firstOrNull(::similar)?.let { return it to "你以前转过账的地址" }
        return null
    }

    /** ABI-encoded static arguments after the 4-byte selector, validated strictly. */
    private class Args(private val data: ByteArray) {
        private val words = (data.size - 4) / 32

        fun expect(n: Int) = require(data.size == 4 + 32 * n) { "参数长度应为 ${32 * n} 字节，实际 ${data.size - 4}" }
        fun atLeast(n: Int) = require((data.size - 4) % 32 == 0 && words >= n) { "参数长度不符" }

        private fun word(i: Int) = data.copyOfRange(4 + 32 * i, 4 + 32 * i + 32)

        fun address(i: Int): Address {
            val w = word(i)
            require((0 until 12).all { w[it] == 0.toByte() }) { "地址参数高位不为 0" }
            return Address(w.copyOfRange(12, 32))
        }

        fun uint(i: Int): BigInteger = BigInteger(1, word(i))

        fun bool(i: Int): Boolean = when (uint(i)) {
            BigInteger.ZERO -> false
            BigInteger.ONE -> true
            else -> throw IllegalArgumentException("布尔参数不是 0/1")
        }
    }

    companion object {
        const val SEL_TRANSFER = "a9059cbb"
        const val SEL_APPROVE = "095ea7b3"
        const val SEL_INCREASE_ALLOWANCE = "39509351"
        const val SEL_SET_APPROVAL_FOR_ALL = "a22cb465"
        const val SEL_TRANSFER_FROM = "23b872dd"
        const val SEL_SAFE_TRANSFER_FROM = "42842e0e"
        const val SEL_SAFE_TRANSFER_FROM_DATA = "b88d4fde"

        /** Number of leading and trailing hex digits compared for look-alike addresses. */
        private const val EDGE = 3

        private val GWEI = BigInteger.TEN.pow(9)

        private val MAX_UINT = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)

        /** Treat ≥ 2^128 as "unlimited": real approvals of finite amounts never come near it. */
        private val UNLIMITED = BigInteger.ONE.shiftLeft(128)

        /** Approvals of an unknown token at or above this many raw units are treated as effectively unlimited. */
        private val HUGE_RAW = BigInteger.ONE.shiftLeft(96).subtract(BigInteger.ONE)

        fun amount(v: BigInteger, decimals: Int): String =
            BigDecimal(v, decimals).stripTrailingZeros().toPlainString()

        fun gwei(v: BigInteger): String = BigDecimal(v, 9).stripTrailingZeros().toPlainString()

        fun chainLabel(id: Long): String = Chains.find(id)?.let { "${it.name} (chainId $id)" } ?: "未知链 (chainId $id)"

        private fun Address.short() = checksummed.let { "${it.take(6)}…${it.takeLast(4)}" }
    }
}
