package org.coldevm.signer.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sparrowwallet.hummingbird.UR
import org.coldevm.signer.evm.Headline
import org.coldevm.signer.evm.RecipientStatus
import org.coldevm.signer.evm.Risk
import org.coldevm.signer.evm.TxSummary
import org.coldevm.signer.vault.Review

private val SmallSize = 12.sp
private val AddressSize = 13.sp

/**
 * Compact review: network, what leaves the wallet, to whom, and every warning on one screen; the raw fields are one
 * tap away (opened automatically when something is red). Sign and reject stay fixed at the bottom.
 */
@Composable
fun ReviewScreen(review: Review, walletName: String, onReject: () -> Unit, onSign: () -> Unit) {
    var acknowledged by remember { mutableStateOf(false) }
    val s = review.summary
    var details by remember { mutableStateOf(s.worstRisk == Risk.DANGER) }

    Page(
        "审阅交易",
        onReject,
        bottomBar = { SignBar(s.worstRisk, s.needsAcknowledgement, acknowledged, { acknowledged = it }, onReject, onSign) },
    ) {
        InfoCard {
            Label("网络")
            Text(s.chainLabel, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }
        SummaryCard(s)
        RiskLines(s)
        Small("$walletName · ${review.account.label} · ${s.action} · nonce ${s.nonce}")
        review.origin?.let { Small("请求来源（由联网端声明，不可信）: ${visible(it)}") }

        TextButton(onClick = { details = !details }, modifier = Modifier.padding(0.dp)) {
            Text(if (details) "收起明细 ▲" else "查看全部明细 ▼", fontSize = 13.sp)
        }
        if (details) Details(review)
    }
}

@Composable
private fun Small(text: String) {
    Text(text, fontSize = SmallSize, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f))
}

/** Fixed bottom bar: the acknowledgement (when needed) and side-by-side reject / sign buttons. */
@Composable
private fun ColumnScope.SignBar(
    risk: Risk, needsAck: Boolean, acknowledged: Boolean, onAck: (Boolean) -> Unit,
    onReject: () -> Unit, onSign: () -> Unit,
) {
    HorizontalDivider()
    Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.background).padding(horizontal = 16.dp, vertical = 8.dp)) {
        if (needsAck) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { onAck(!acknowledged) }) {
                Checkbox(checked = acknowledged, onCheckedChange = onAck)
                Text("我已核对，理解上面的风险提示", color = DangerColor, fontSize = 13.sp)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = onReject, modifier = Modifier.weight(1f)) { Text("拒绝") }
            Button(
                onClick = onSign,
                enabled = !needsAck || acknowledged,
                colors = if (risk == Risk.DANGER) ButtonDefaults.buttonColors(containerColor = DangerColor) else ButtonDefaults.buttonColors(),
                modifier = Modifier.weight(2f),
            ) { Text("验证身份并签名") }
        }
    }
}

/** The few facts that matter most, in large type: amount, recipient and what we know about the recipient. */
@Composable
private fun SummaryCard(s: TxSummary) {
    val color = when (s.worstRisk) { Risk.DANGER -> DangerColor; Risk.WARN -> WarnColor; Risk.INFO -> Green }
    InfoCard(color = color.copy(alpha = 0.12f)) {
        if (s.headlines.isEmpty()) {
            Text(s.effect ?: s.action, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold,
                color = if (s.worstRisk == Risk.DANGER) DangerColor else MaterialTheme.colorScheme.onSurface)
            if (s.effect != null) Small(s.action)
        } else {
            s.effect?.let { Text(it, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold) }
            s.headlines.forEachIndexed { i, h -> if (i > 0) HorizontalDivider(); Payment(h) }
        }
        HorizontalDivider()
        val feeColor = when (s.feeRisk) { Risk.DANGER -> DangerColor; Risk.WARN -> WarnColor; Risk.INFO -> MaterialTheme.colorScheme.onSurface }
        Text("最高手续费 ${s.maxFee}", color = feeColor, fontWeight = if (s.feeRisk == Risk.INFO) FontWeight.Normal else FontWeight.Bold, fontSize = 15.sp)
    }
}

@Composable
private fun Payment(h: Headline) {
    Text("转出 ${h.amount}", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
    Label(if (h.status == RecipientStatus.PROTOCOL) "存入合约" else "收款地址")
    Mono(h.to, highlight = h.alert == null, fontSize = AddressSize)
    when {
        h.alert != null -> Text(h.alert, color = DangerColor, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        h.status == RecipientStatus.SELF -> Status("✓ 本机自己的账户（${h.ownLabel}）", Green)
        h.status == RecipientStatus.PROTOCOL -> Status("✓ 存入已识别的协议合约：${h.ownLabel}（地址已离线核对）", Green)
        h.status == RecipientStatus.KNOWN -> Status("✓ 本机以前签过 ${h.timesBefore} 笔给这个地址的转账。仍请核对完整地址", Green)
        else -> Status("本机从未签过给这个地址的转账：请逐字核对完整地址，不要只看开头和结尾", WarnColor)
    }
}

@Composable
private fun Status(text: String, color: Color) {
    Text(text, color = color, fontSize = 13.sp)
}

/** Every warning, one short line each. The details are collapsed by default, so nothing important may live only there. */
@Composable
private fun RiskLines(s: TxSummary) {
    if (s.warnings.isEmpty()) return
    InfoCard {
        s.warnings.sortedByDescending { it.first }.forEach { (r, text) ->
            val (prefix, c) = when (r) { Risk.DANGER -> "⛔ " to DangerColor; Risk.WARN -> "⚠ " to WarnColor; Risk.INFO -> "ℹ " to Green }
            Text(formatAddresses(prefix + text, c), color = c, fontSize = 13.sp)
        }
    }
}

@Composable
private fun Details(review: Review) {
    InfoCard {
        Label("签名账户 · ${review.account.path}")
        Mono(review.account.address.checksummed, fontSize = SmallSize)
    }
    InfoCard {
        review.summary.fields.forEach { f ->
            Label(f.label)
            Mono(f.value, f.highlight, fontSize = SmallSize)
        }
    }
}

/** Control and invisible formatting characters are made visible so a declared origin cannot disguise itself. */
private fun visible(text: String): String = buildString {
    for (ch in text.take(200)) {
        if (ch.isISOControl() || Character.getType(ch) == Character.FORMAT.toInt()) append("\\u%04x".format(ch.code)) else append(ch)
    }
}

@Composable
fun SignatureScreen(ur: UR, onDone: () -> Unit) {
    Page("签名完成") {
        Text("在 OKX Wallet 中点击“获取签名 / 扫描”，扫描下面的二维码，然后由 OKX 广播交易。")
        AnimatedUrQr(ur)
        Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) { Text("完成") }
    }
}
