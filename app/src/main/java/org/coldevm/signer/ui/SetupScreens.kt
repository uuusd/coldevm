package org.coldevm.signer.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.coldevm.signer.crypto.Bip39
import org.coldevm.signer.evm.Risk
import org.coldevm.signer.vault.EthKeys
import java.security.SecureRandom

/** Keyboard settings that keep the IME from learning or suggesting secret words. */
private val SecretKeyboard = KeyboardOptions(
    capitalization = KeyboardCapitalization.None,
    autoCorrectEnabled = false,
    keyboardType = KeyboardType.Password,
)

@Composable
fun WelcomeScreen(onImport: () -> Unit, onGenerate: () -> Unit, onBack: (() -> Unit)? = null) {
    Page(if (onBack == null) "ColdEVM 离线签名" else "添加钱包", onBack) {
        Text("这是一个永不联网的 EVM（以太坊、BNB Chain、Polygon、Arbitrum、Base 等）冷钱包签名器。它没有网络权限，私钥只保存在本机，并由安全芯片加密。")
        Text("联网手机上的 OKX Wallet 会把它识别为一台 Keystone 硬件钱包：通过二维码配对、发起交易，本机审阅后签名。当前版本只签交易，不签消息。")
        Button(onClick = onImport, modifier = Modifier.fillMaxWidth()) { Text("导入已有助记词") }
        OutlinedButton(onClick = onGenerate, modifier = Modifier.fillMaxWidth()) { Text("生成新助记词（24 个单词）") }
    }
}

@Composable
fun ImportScreen(bip39: Bip39, onBack: () -> Unit, onNext: (List<String>) -> Unit) {
    // TextFieldValue rather than String so a picked suggestion can move the cursor to the end.
    var field by remember { mutableStateOf(TextFieldValue("")) }
    val text = field.text
    val words = Bip39.normalize(text)
    val lastPartial = if (text.endsWith(" ") || text.endsWith("\n")) "" else words.lastOrNull().orEmpty()
    // Don't complain about the word that is still being typed.
    val lastDone = lastPartial.isEmpty() || bip39.isWord(lastPartial)
    val error = if (words.size in Bip39.VALID_LENGTHS && lastDone) bip39.validate(words) else null
    Page("导入助记词", onBack) {
        Text("按顺序输入 12 或 24 个英文单词，用空格分隔。")
        OutlinedTextField(
            value = field,
            onValueChange = { field = it },
            label = { Text("助记词") },
            keyboardOptions = SecretKeyboard,
            minLines = 4,
            modifier = Modifier.fillMaxWidth(),
            textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
        )
        val unknown = words.dropLast(if (lastPartial.isEmpty()) 0 else 1).filterNot { bip39.isWord(it) }
        Label("已输入 ${words.size} 个单词")
        if (unknown.isNotEmpty()) Banner(Risk.WARN, "不在词表中: ${unknown.joinToString(" ")}")
        val sugg = bip39.suggestions(lastPartial).filter { it != lastPartial }
        if (sugg.isNotEmpty()) Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            sugg.forEach { s ->
                OutlinedButton(onClick = {
                    val completed = text.dropLast(lastPartial.length) + s + " "
                    field = TextFieldValue(completed, selection = TextRange(completed.length))
                }) { Text(s) }
            }
        }
        if (error != null) Banner(Risk.DANGER, error)
        Button(
            onClick = { onNext(words); field = TextFieldValue("") },
            enabled = words.size in Bip39.VALID_LENGTHS && lastDone && error == null,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("下一步") }
    }
}

@Composable
fun GenerateScreen(bip39: Bip39, onBack: () -> Unit, onNext: (List<String>) -> Unit) {
    val words = remember { bip39.generate() }
    var verifying by remember { mutableStateOf(false) }
    val checks = remember { (0 until 24).shuffled(SecureRandom()).take(3).sorted() }
    val answers = remember { mutableStateOf(List(3) { "" }) }
    var written by remember { mutableStateOf(false) }

    Page(if (verifying) "确认备份" else "抄写助记词", onBack) {
        if (!verifying) {
            Banner(Risk.WARN, "用纸笔按顺序抄写这 24 个单词，放在安全的地方。不要拍照、不要存到任何联网设备。丢失助记词等于丢失资产。")
            InfoCard {
                words.chunked(2).forEachIndexed { row, pair ->
                    Row {
                        pair.forEachIndexed { col, w ->
                            val n = row * 2 + col + 1
                            Text("%2d. %s".format(n, w), fontFamily = FontFamily.Monospace, modifier = Modifier.width(160.dp))
                        }
                    }
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { written = !written }) {
                Checkbox(checked = written, onCheckedChange = { written = it })
                Text("我已经抄写好了")
            }
            Button(onClick = { verifying = true }, enabled = written, modifier = Modifier.fillMaxWidth()) { Text("下一步：验证") }
        } else {
            Text("请输入以下位置的单词，确认你的抄写正确。")
            checks.forEachIndexed { i, pos ->
                OutlinedTextField(
                    value = answers.value[i],
                    onValueChange = { v -> answers.value = answers.value.toMutableList().also { it[i] = v.trim().lowercase() } },
                    label = { Text("第 ${pos + 1} 个单词") },
                    singleLine = true,
                    keyboardOptions = SecretKeyboard,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            val ok = checks.withIndex().all { (i, pos) -> answers.value[i] == words[pos] }
            Button(onClick = { onNext(words) }, enabled = ok, modifier = Modifier.fillMaxWidth()) { Text("验证通过，下一步") }
            OutlinedButton(onClick = { verifying = false }, modifier = Modifier.fillMaxWidth()) { Text("再看一次助记词") }
        }
    }
}

@Composable
fun ConfigureScreen(
    words: List<String>,
    defaultName: String,
    onBack: () -> Unit,
    onSave: (passphrase: String, pinOnly: Boolean, name: String) -> Unit,
) {
    var pinOnly by remember { mutableStateOf(true) }
    var name by remember { mutableStateOf(defaultName) }
    var usePassphrase by remember { mutableStateOf(false) }
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var preview by remember { mutableStateOf<String?>(null) }
    val effectivePass = if (usePassphrase) passphrase else ""

    LaunchedEffect(words, effectivePass) {
        preview = null
        delay(300)
        preview = withContext(Dispatchers.Default) {
            val seed = Bip39.toSeed(words, effectivePass)
            try { EthKeys.derive(seed).standard(0).address.checksummed } finally { seed.fill(0) }
        }
    }

    Page("钱包设置", onBack) {
        OutlinedTextField(name, { name = it.take(32) }, label = { Text("钱包名称") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = usePassphrase, onCheckedChange = { usePassphrase = it })
            Text("  使用 BIP39 密码（第 25 个词）", modifier = Modifier.padding(start = 8.dp))
        }
        if (usePassphrase) {
            OutlinedTextField(passphrase, { passphrase = it }, label = { Text("BIP39 密码") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = SecretKeyboard, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(confirm, { confirm = it }, label = { Text("再次输入") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = SecretKeyboard, modifier = Modifier.fillMaxWidth())
            if (confirm.isNotEmpty() && confirm != passphrase) Banner(Risk.WARN, "两次输入不一致")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = pinOnly, onCheckedChange = { pinOnly = it })
            Column(Modifier.padding(start = 12.dp)) {
                Text("签名只接受锁屏 PIN（不用指纹）")
                Label("被胁迫时，按手指远比说出 PIN 容易。可以随时在设置里更改。")
            }
        }
        InfoCard {
            Label("账户 1 地址 m/44'/60'/0'/0/0（请与原钱包中的地址核对）")
            Mono(preview ?: "计算中…", highlight = preview != null)
        }
        val valid = !usePassphrase || (passphrase.isNotEmpty() && passphrase == confirm)
        Button(onClick = { onSave(effectivePass, pinOnly, name.trim().ifEmpty { defaultName }) }, enabled = valid && preview != null, modifier = Modifier.fillMaxWidth()) {
            Text("加密保存")
        }
        Label("保存时需要验证身份。种子由安全芯片中的密钥加密，之后每次签名都需要再次验证。")
    }
}
