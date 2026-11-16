package org.coldevm.signer.ui

import android.app.KeyguardManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import com.sparrowwallet.hummingbird.UR
import com.sparrowwallet.hummingbird.URDecoder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.coldevm.signer.BuildConfig
import org.coldevm.signer.crypto.Bip39
import org.coldevm.signer.crypto.toHex
import org.coldevm.signer.ur.KeystoneUr
import org.coldevm.signer.vault.AddressBook
import org.coldevm.signer.vault.RejectedException
import org.coldevm.signer.vault.Review
import org.coldevm.signer.evm.Address
import org.coldevm.signer.vault.SeedStore
import org.coldevm.signer.vault.SignLogic
import org.coldevm.signer.vault.Wallet
import org.coldevm.signer.vault.WalletStore

private sealed class Screen {
    data object Welcome : Screen()
    data object AddWallet : Screen()
    data object Import : Screen()
    data object Generate : Screen()
    class Configure(val words: List<String>) : Screen()
    data class Tabs(val tab: Tab) : Screen()
    class Wallet(val id: String) : Screen()
    class AccountDetail(val id: String, val index: Int) : Screen()
    class Connect(val id: String, val target: ConnectTarget) : Screen()
    class WalletSettings(val id: String) : Screen()
    class ReviewRequest(val walletId: String, val request: KeystoneUr.SignRequest, val review: Review) : Screen()
    class Signed(val ur: UR) : Screen()
}

class MainActivity : FragmentActivity() {
    // Debug-only injected QR parts; a state so a new injection reaches the running UI without rebuilding it.
    private var injected by mutableStateOf<List<String>?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no screen recording, no thumbnail in the recents list.
        // Debug builds skip this so emulator tests can capture the screen.
        if (!BuildConfig.DEBUG) window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        // Other apps cannot draw over the review screen to trick a tap on "sign" (tapjacking).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
        injected = debugInjectedParts(intent)
        val store = WalletStore(applicationContext)
        val addressBook = AddressBook(applicationContext)
        val bip39 = Bip39(assets.open("bip39_english.txt").bufferedReader().readLines().map { it.trim() }.filter { it.isNotEmpty() })
        setContent { ColdEvmTheme { App(this, store, addressBook, bip39, injected) } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        debugInjectedParts(intent)?.let { injected = it }
    }

    /** Debug builds only: `am start --esa ur_parts p1,p2,...` stands in for the camera in emulator tests. */
    private fun debugInjectedParts(intent: Intent?): List<String>? =
        if (BuildConfig.DEBUG) intent?.getStringArrayExtra("ur_parts")?.toList() else null
}

@Composable
private fun App(activity: FragmentActivity, store: WalletStore, addressBook: AddressBook, bip39: Bip39, injectedParts: List<String>?) {
    var screen by remember { mutableStateOf<Screen>(if (store.isEmpty) Screen.Welcome else Screen.Tabs(Tab.WALLETS)) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    // Bumped after any change to stored data so screens re-read it.
    var revision by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()

    fun run(block: suspend () -> Unit) {
        if (busy) return
        busy = true
        scope.launch {
            try { block() }
            catch (e: AuthCancelledException) { error = "已取消：${e.message}" }
            catch (e: RejectedException) { error = e.message }
            catch (e: Exception) { error = "${e.javaClass.simpleName}: ${e.message}" }
            finally { busy = false; revision++ }
        }
    }

    val home = { screen = if (store.isEmpty) Screen.Welcome else Screen.Tabs(Tab.WALLETS) }

    fun onScanned(ur: UR) {
        try {
            when (ur.type) {
                KeystoneUr.TYPE_ETH_SIGN_REQUEST -> {}
                KeystoneUr.TYPE_ETH_BATCH_SIGN_REQUEST -> throw RejectedException("不支持批量签名请求，请在 OKX 中逐笔发起")
                else -> throw RejectedException("不支持的二维码类型: ${ur.type}")
            }
            val req = KeystoneUr.decodeSignRequest(ur.cborBytes)
            val fp = req.sourceFingerprint ?: throw RejectedException("请求中缺少主指纹，拒绝签名")
            val wallet = store.byFingerprint(fp)
                ?: throw RejectedException("本机没有主指纹为 ${fp.toHex()} 的钱包。这个请求来自 OKX 中连接的另一台设备，或对应的钱包已被删除。")
            val own: Map<Address, String> = store.wallets.flatMap { w -> w.keys.all.map { it.address to "${w.name} ${it.label}" } }.toMap()
            val review = SignLogic.review(req, wallet.fingerprint, wallet.keys, own, addressBook.all())
            screen = Screen.ReviewRequest(wallet.id, req, review)
        } catch (e: RejectedException) {
            error = e.message; home()
        } catch (e: Exception) {
            error = "无法解析签名请求: ${e.message}"; home()
        } catch (e: OutOfMemoryError) {
            // Last line of defence for hostile input: CborGuard should already have rejected it.
            error = "签名请求数据异常（过大），已拒绝"; home()
        }
    }

    LaunchedEffect(injectedParts) {
        if (injectedParts == null || store.isEmpty) return@LaunchedEffect
        val decoder = URDecoder()
        injectedParts.forEach { if (decoder.result == null) decoder.receivePart(it.lowercase()) }
        decoder.result?.ur?.let(::onScanned)
    }

    BackHandler(enabled = screen != Screen.Tabs(Tab.WALLETS) && screen != Screen.Welcome) {
        screen = when (val s = screen) {
            is Screen.Connect -> Screen.Wallet(s.id)
            is Screen.WalletSettings -> Screen.Wallet(s.id)
            is Screen.AccountDetail -> Screen.Wallet(s.id)
            else -> if (store.isEmpty) Screen.Welcome else Screen.Tabs(Tab.WALLETS)
        }
    }

    // Surface (not a plain Box) so Text picks up onBackground as its default content colour.
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background, contentColor = MaterialTheme.colorScheme.onBackground) {
        revision.let { } // read so stored-data changes recompose
        when (val s = screen) {
            Screen.Welcome -> WelcomeScreen(onImport = { screen = Screen.Import }, onGenerate = { screen = Screen.Generate })
            Screen.AddWallet -> WelcomeScreen(onImport = { screen = Screen.Import }, onGenerate = { screen = Screen.Generate }, onBack = home)
            Screen.Import -> ImportScreen(bip39, onBack = home) { screen = Screen.Configure(it) }
            Screen.Generate -> GenerateScreen(bip39, onBack = home) { screen = Screen.Configure(it) }
            is Screen.Configure -> ConfigureScreen(s.words, store.defaultName(), onBack = home) { passphrase, pinOnly, name ->
                run {
                    val keyguard = activity.getSystemService(KeyguardManager::class.java)
                    if (!keyguard.isDeviceSecure) throw RejectedException("请先在系统设置中设置锁屏密码（PIN），再保存钱包。")
                    val seed = withContext(Dispatchers.Default) { Bip39.toSeed(s.words, passphrase) }
                    try {
                        store.duplicateOf(seed)?.let { throw RejectedException("这套助记词（含 BIP39 密码）已经导入过了：${it.name}") }
                        val id = store.newId()
                        // Keystore (StrongBox) key generation can take a second: keep it off the main thread.
                        val pending = withContext(Dispatchers.IO) { store.seedStore(id).newEncryptCipher(pinOnly) }
                        val cipher = activity.authenticate(pending.cipher, "加密保存钱包", pinOnly = pinOnly)
                        withContext(Dispatchers.Default) { store.create(id, name, pending, cipher, seed, pinOnly) }
                        screen = Screen.Wallet(id)
                    } finally {
                        seed.fill(0)
                    }
                }
            }
            is Screen.Tabs -> Column(Modifier.fillMaxSize()) {
                Box(Modifier.weight(1f)) {
                    when (s.tab) {
                        Tab.WALLETS -> WalletsTab(store.wallets, onOpen = { screen = Screen.Wallet(it.id) }, onAdd = { screen = Screen.AddWallet })
                        Tab.SCAN -> ScanTab(onScanned = ::onScanned, onError = { error = it; home() })
                        Tab.SETTINGS -> SettingsTab(store.wallets.size, addressBook.size, onClearAddressBook = { addressBook.clear(); revision++ })
                    }
                }
                TabBar(s.tab) { screen = Screen.Tabs(it) }
            }
            is Screen.Wallet -> store.find(s.id)?.let { w ->
                WalletScreen(
                    w,
                    onBack = home,
                    onConnect = { screen = Screen.Connect(w.id, it) },
                    onAccount = { screen = Screen.AccountDetail(w.id, w.accounts.indexOf(it)) },
                    onSettings = { screen = Screen.WalletSettings(w.id) },
                )
            } ?: home()
            is Screen.AccountDetail -> store.find(s.id)?.let { w ->
                w.accounts.getOrNull(s.index)?.let { a -> AccountScreen(w, a, onBack = { screen = Screen.Wallet(w.id) }) }
            } ?: home()
            is Screen.Connect -> store.find(s.id)?.let { w -> ConnectScreen(w, s.target, onBack = { screen = Screen.Wallet(w.id) }) } ?: home()
            is Screen.WalletSettings -> store.find(s.id)?.let { w ->
                WalletSettingsScreen(
                    wallet = w,
                    onBack = { screen = Screen.Wallet(w.id) },
                    onRename = { name -> store.rename(w.id, name); revision++ },
                    onChangeAuth = { pinOnly ->
                        run {
                            val decrypt = withContext(Dispatchers.IO) { w.seedStore.decryptCipher() }
                            val current = activity.authenticate(decrypt, "验证当前身份", w.name, w.pinOnly)
                            val seed = store.loadSeed(w, current)
                            try {
                                val pending = withContext(Dispatchers.IO) { w.seedStore.newEncryptCipher(pinOnly) }
                                val cipher = activity.authenticate(pending.cipher, if (pinOnly) "用锁屏 PIN 确认" else "确认新的解锁方式", w.name, pinOnly)
                                withContext(Dispatchers.Default) { store.rekey(w, pending, cipher, seed, pinOnly) }
                            } finally {
                                seed.fill(0)
                            }
                            screen = Screen.Wallet(w.id)
                        }
                    },
                    onDelete = {
                        run {
                            // Only a seed that can never be decrypted again (missing file or key, key invalidated by
                            // removing the screen lock) is deleted without a prompt; any other error stops the deletion.
                            val cipher = withContext(Dispatchers.IO) {
                                try { w.seedStore.decryptCipher() }
                                catch (e: SeedStore.UnavailableException) { null }
                                catch (e: KeyPermanentlyInvalidatedException) { null }
                            }
                            if (cipher != null) activity.authenticate(cipher, "删除钱包", w.name, w.pinOnly)
                            store.delete(w)
                            home()
                        }
                    },
                )
            } ?: home()
            is Screen.ReviewRequest -> {
                val w = store.find(s.walletId)
                // Keyed by request so a risk acknowledgement never carries over to another request.
                if (w == null) home() else key(s.request) { ReviewScreen(s.review, w.name, onReject = home, onSign = {
                    run {
                        val decrypt = withContext(Dispatchers.IO) { w.seedStore.decryptCipher() }
                        val cipher = activity.authenticate(decrypt, "签名 · ${w.name}", s.review.account.address.checksummed, w.pinOnly)
                        val sig = withContext(Dispatchers.Default) {
                            store.withSeed(w, cipher) { seed -> SignLogic.sign(seed, s.review.account, s.review.tx, s.request.signData) }
                        }
                        addressBook.remember(s.review.summary.recipients)
                        screen = Screen.Signed(UR(KeystoneUr.TYPE_ETH_SIGNATURE, KeystoneUr.encodeSignature(s.request.requestId, sig)))
                    }
                }) }
            }
            is Screen.Signed -> SignatureScreen(s.ur, onDone = home)
        }
    }

    error?.let { msg ->
        AlertDialog(
            onDismissRequest = { error = null },
            confirmButton = { TextButton(onClick = { error = null }) { Text("确定") } },
            title = { Text("提示") },
            text = { Text(msg) },
        )
    }
}
