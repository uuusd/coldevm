package org.coldevm.signer.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.coldevm.signer.BuildConfig
import org.coldevm.signer.vault.Account
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import com.sparrowwallet.hummingbird.UR
import org.coldevm.signer.crypto.toHex
import org.coldevm.signer.evm.Risk
import org.coldevm.signer.ur.KeystoneUr
import org.coldevm.signer.vault.Scheme
import org.coldevm.signer.vault.Wallet

enum class Tab(val label: String) { WALLETS("钱包"), SCAN("扫描"), SETTINGS("设置") }

/** Bottom navigation, as in AirGap Vault: wallets, scan, settings. */
@Composable
fun TabBar(selected: Tab, onSelect: (Tab) -> Unit) {
    NavigationBar(containerColor = MaterialTheme.colorScheme.surfaceVariant) {
        Tab.entries.forEach { t ->
            val icon = when (t) { Tab.WALLETS -> ColdIcons.Wallet; Tab.SCAN -> ColdIcons.Scan; Tab.SETTINGS -> ColdIcons.Settings }
            NavigationBarItem(
                selected = t == selected,
                onClick = { onSelect(t) },
                icon = { Icon(icon, contentDescription = null) },
                label = { Text(t.label) },
            )
        }
    }
}

@Composable
fun WalletsTab(wallets: List<Wallet>, onOpen: (Wallet) -> Unit, onAdd: () -> Unit) {
    Page("钱包", bottomInset = false, actions = {
        IconButton(onClick = onAdd) { Icon(ColdIcons.Add, contentDescription = "添加钱包") }
    }) {
        wallets.forEach { w ->
            ListCard {
                ListRow(
                    title = w.name,
                    subtitle = "EVM · ${shortAddress(w.accounts[0].address.checksummed)} · ${w.fingerprint.toHex()}",
                    onClick = { onOpen(w) },
                ) { WalletAvatar(w.name, w.fingerprint) }
            }
        }
        OutlinedButton(onClick = onAdd, modifier = Modifier.fillMaxWidth()) {
            Icon(ColdIcons.Add, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("添加钱包", modifier = Modifier.padding(start = 6.dp))
        }
        Label("签名时按请求中的主指纹自动选择对应的钱包，不需要先切换。")
    }
}

@Composable
fun ScanTab(onScanned: (UR) -> Unit, onError: (String) -> Unit) {
    Page("扫描签名请求", bottomInset = false) {
        Label("扫描 OKX Wallet 显示的动态二维码")
        UrScanner(onResult = onScanned, onError = onError)
    }
}

@Composable
fun SettingsTab(walletCount: Int, addressBookSize: Int, onClearAddressBook: () -> Unit) {
    Page("设置", bottomInset = false) {
        Label("收款地址记录")
        InfoCard {
            Text("已记住 $addressBookSize 个收款地址")
            Label("每签一笔转账，就记住它的收款地址和签名次数（只有地址和次数；签了但没广播的也算）。之后审阅时会显示“从未签过”或“签过 N 笔”，并对首尾相同但中间不同的地址（地址投毒）发出红色警告。")
        }
        OutlinedButton(onClick = onClearAddressBook, enabled = addressBookSize > 0, modifier = Modifier.fillMaxWidth()) { Text("清空记录") }

        Label("关于")
        InfoCard {
            Text("ColdEVM ${BuildConfig.VERSION_NAME}", fontWeight = FontWeight.SemiBold)
            Label("$walletCount 个钱包 · 无网络权限 · 种子由安全芯片加密 · 只签交易，不签消息")
            Label("钱包的名称、解锁方式和删除，在钱包页右上角的齿轮里。")
        }
    }
}

@Composable
fun WalletScreen(wallet: Wallet, onBack: () -> Unit, onConnect: (ConnectTarget) -> Unit, onAccount: (Account) -> Unit, onSettings: () -> Unit) {
    Page(wallet.name, onBack, actions = {
        IconButton(onClick = onSettings) { Icon(ColdIcons.Settings, contentDescription = "钱包设置") }
    }) {
        InfoCard {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                WalletAvatar(wallet.name, wallet.fingerprint, 56.dp)
                Column {
                    Text(wallet.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Label("主指纹 ${wallet.fingerprint.toHex()}")
                    Label(if (wallet.pinOnly) "仅 PIN" else "指纹或 PIN")
                    Label(if (wallet.strongBox) "StrongBox 安全芯片加密" else "Android Keystore (TEE) 加密")
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { onConnect(ConnectTarget.OKX) }, modifier = Modifier.weight(1f)) {
                Icon(ColdIcons.Sync, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("连接 OKX", modifier = Modifier.padding(start = 6.dp))
            }
            OutlinedButton(onClick = { onConnect(ConnectTarget.RABBY) }, modifier = Modifier.weight(1f)) {
                Icon(ColdIcons.Sync, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("连接 Rabby", modifier = Modifier.padding(start = 6.dp))
            }
        }
        Label("账户（标准路径 m/44'/60'/0'/0/n，所有 EVM 链共用同一地址）")
        ListCard {
            wallet.accounts.filter { it.scheme == Scheme.STANDARD }.forEachIndexed { i, a ->
                if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.background)
                ListRow(title = a.label, subtitle = shortAddress(a.address.checksummed), monoSubtitle = true, onClick = { onAccount(a) }) { EvmBadge() }
            }
        }
        Label("Ledger Live 路径 m/44'/60'/n'/0/0（OKX 中选择 Ledger Live 时使用）")
        ListCard {
            wallet.accounts.filter { it.scheme == Scheme.LEDGER_LIVE }.forEachIndexed { i, a ->
                if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.background)
                ListRow(title = a.label, subtitle = shortAddress(a.address.checksummed), monoSubtitle = true, onClick = { onAccount(a) }) { EvmBadge() }
            }
        }
    }
}

@Composable
private fun EvmBadge() {
    Box(Modifier.size(36.dp).clip(CircleShape).background(Purple.copy(alpha = 0.2f)), contentAlignment = Alignment.Center) {
        Text("EVM", color = Purple, fontWeight = FontWeight.Bold, fontSize = 11.sp)
    }
}

/** One account's receive address, as a QR the online phone can scan and compare against OKX. */
@Composable
fun AccountScreen(wallet: Wallet, account: Account, onBack: () -> Unit) {
    Page("${wallet.name} · ${account.label}", onBack) {
        Box(Modifier.fillMaxWidth().padding(horizontal = 24.dp)) { StaticQr(account.address.checksummed) }
        InfoCard {
            Label("收款地址（所有 EVM 链相同）")
            Mono(account.address.checksummed)
            Label("派生路径 ${account.path}")
        }
        Label("这是公开的收款地址，可以给联网手机扫码，核对 OKX Wallet 中显示的地址是否一致。")
    }
}

/** Which online wallet the connect QR is for: they expect different Keystone export formats. */
enum class ConnectTarget(val title: String) { OKX("连接 OKX Wallet"), RABBY("连接 Rabby / MetaMask") }

@Composable
fun ConnectScreen(wallet: Wallet, target: ConnectTarget, onBack: () -> Unit) {
    val ur = remember(wallet.id, target) {
        when (target) {
            ConnectTarget.OKX -> UR(KeystoneUr.TYPE_MULTI_ACCOUNTS, KeystoneUr.encodeMultiAccounts(wallet.fingerprint, "coldevm-${wallet.id}", wallet.keys.syncKeys()))
            ConnectTarget.RABBY -> UR(KeystoneUr.TYPE_HDKEY, wallet.keys.standardHdKey(wallet.fingerprint, wallet.name.take(32)))
        }
    }
    Page(target.title, onBack) {
        Text(when (target) {
            ConnectTarget.OKX -> "${wallet.name}：在联网手机的 OKX Wallet 中：添加钱包 → 连接硬件钱包 → Keystone，然后扫描下面的动态二维码。"
            ConnectTarget.RABBY -> "${wallet.name}：在 Rabby 中：添加地址 → 硬件钱包 → Keystone，用电脑摄像头扫描下面的二维码（MetaMask 同样：添加硬件钱包 → QR 硬件钱包）。"
        })
        AnimatedUrQr(ur)
        Label(when (target) {
            ConnectTarget.OKX -> "二维码只包含扩展公钥和派生路径，不包含任何私密信息。"
            ConnectTarget.RABBY -> "二维码只包含标准路径 m/44'/60'/0' 的扩展公钥（账户 m/44'/60'/0'/0/n），不包含任何私密信息。Ledger Live 路径请用 OKX。"
        } + "连接后请核对账户 1 的地址：${shortAddress(wallet.accounts[0].address.checksummed)}")
        if (target == ConnectTarget.RABBY) Banner(Risk.WARN, "当前版本只签交易。Rabby / DApp 的消息签名（登录签名、Permit、EIP-712）会被拒绝。")
    }
}

@Composable
fun WalletSettingsScreen(
    wallet: Wallet,
    onBack: () -> Unit,
    onRename: (String) -> Unit,
    onChangeAuth: (pinOnly: Boolean) -> Unit,
    onDelete: () -> Unit,
) {
    var name by remember { mutableStateOf(wallet.name) }
    var confirmText by remember { mutableStateOf("") }
    Page("钱包设置", onBack) {
        Label("名称")
        OutlinedTextField(name, { name = it.take(32) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedButton(onClick = { onRename(name.trim()) }, enabled = name.isNotBlank() && name.trim() != wallet.name, modifier = Modifier.fillMaxWidth()) {
            Text("保存名称")
        }

        Label("签名时的身份验证")
        InfoCard {
            Text(if (wallet.pinOnly) "当前：仅锁屏 PIN" else "当前：指纹或锁屏 PIN")
            Label("切换时会用新的安全芯片密钥重新加密种子，需要先后验证两次。")
        }
        OutlinedButton(onClick = { onChangeAuth(!wallet.pinOnly) }, modifier = Modifier.fillMaxWidth()) {
            Text(if (wallet.pinOnly) "改为允许指纹" else "改为仅锁屏 PIN")
        }

        Label("删除钱包")
        Banner(Risk.DANGER, "删除后本机上这个钱包的加密种子会被清除，只能用助记词恢复。其他钱包不受影响。输入 DELETE（或“删除”）并验证身份以确认。")
        OutlinedTextField(confirmText, { confirmText = it }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedButton(onClick = onDelete, enabled = confirmText.trim().let { it == "DELETE" || it == "删除" }, modifier = Modifier.fillMaxWidth()) {
            Text("删除这个钱包")
        }
    }
}
