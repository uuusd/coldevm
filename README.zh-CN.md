# ColdEVM：Android 离线 EVM 交易签名器

[English](README.md) | 简体中文

> ⚠️ **免责声明**：本软件按“现状”提供，不附带任何担保，**未经过第三方审计**。私钥和资产由你自己负责，请先用小额测试。安全问题请按 [SECURITY.md](SECURITY.md) 私下报告，不要公开发 issue。

装在一台永不联网的手机上（例如运行 GrapheneOS 的 Pixel）。联网设备上的 **OKX Wallet**、**Rabby** 或 **MetaMask** 会把它当作一台 **Keystone 硬件钱包**，两台设备之间只通过二维码传数据。它是 [ColdSol](https://github.com/uuusd/coldsol) 的 EVM 版本，种子保管、扫码和审阅界面沿用 ColdSol 的设计。

**只签交易。** 当前版本支持任意 EVM 链上的 legacy（EIP-155）和 EIP-1559 交易。以下请求一律拒签：消息签名（`personal_sign`、EIP-712）、EIP-7702 授权交易（type 4）、type 1 和 type 3 交易、没有链 ID 的旧式交易、批量签名请求。

## 安装

1. 从 [GitHub Releases](../../releases) 下载 `coldevm-<版本>.apk`，按下文**核对**，用 USB 拷到离线手机上安装。也可以自己编译。
2. App 不申请 `INTERNET` 权限，在 GrapheneOS 的应用信息里可以确认它没有网络权限。
3. 离线手机必须设置锁屏。⚠️ 以后不要取消锁屏：取消后 Android 会永久作废安全芯片里的密钥，只能用助记词重新导入。

## 核对 APK

```bash
sha256sum coldevm-<版本>.apk
apksigner verify --print-certs coldevm-<版本>.apk
```

`Signer #1 certificate SHA-256 digest` 必须是：

```
9a4541a4708e2d2fa4f08a2b70b3501468f3bced6153c4d7baaab6ccfecd0973
```

每个版本都用这张证书签名。指纹不同的 APK 不要安装。

## 初始设置

导入 12 或 24 个单词的助记词（可选 BIP39 密码），或生成 24 个单词。保存前会显示账户 1（`m/44'/60'/0'/0/0`）的地址，请先和原钱包核对。种子用安全芯片里的 AES-256-GCM 密钥加密（支持 StrongBox 时用 StrongBox），每次使用都要验证身份。支持多个钱包，签名时按请求里的主指纹自动选择。

## 连接

| 联网钱包 | ColdEVM 中 | 联网钱包中 | 可用账户 |
|---|---|---|---|
| OKX Wallet | 钱包 → **连接 OKX** | 添加钱包 → 连接硬件钱包 → Keystone | `m/44'/60'/0'/0/n`，以及 Ledger Live 路径 `m/44'/60'/n'/0/0` |
| Rabby / MetaMask | 钱包 → **连接 Rabby** | 添加地址 → 硬件钱包 → Keystone（MetaMask：添加硬件钱包 → QR 硬件钱包） | `m/44'/60'/0'/0/n` |

连接后请在两边核对账户 1 的地址。

## 审阅页显示什么

- 网络名称和链 ID、转出金额和收款地址（地址按 4 个字符一组显示，首尾两组高亮）、最高手续费。
- 能解析的调用：原生币转账、ERC-20 `transfer`、`approve` / `increaseAllowance`（红色；无限额度会额外警告；`approve(…, 0)` 显示为撤销授权）、`setApprovalForAll`（红色）、`transferFrom` / `safeTransferFrom`。
- 代币名称只认内置的 USDT/USDC 合约（Ethereum、BNB Chain、Polygon、Avalanche、Arbitrum、Base）。其他代币一律显示为“未知代币”和原始数量——假冒代币可以用任何名字，但用不了这些合约地址。
- 未知合约调用、部署合约、参数格式不规范：标红（相当于盲签），必须先勾选确认才能签名。
- 手续费：超过该链常见水平显示黄色，超过 10 倍标红并需要确认；手续费高于转账金额时也会提醒。
- 收款记录：区分“本机从未签过给这个地址的转账”和“签过 N 笔”。如果收款地址和本机 110 个账户之一或以前的收款地址首尾各 3 位相同但不是同一个地址，会标红提示**疑似地址投毒**。

## 安全设计

- 没有网络权限；禁止截屏；App 在前台时隐藏其他 App 的悬浮窗；App 数据不参与备份和设备迁移。
- 种子只在验证身份后为一次签名解密，用完立即清除。
- 严格按规范编码解析 RLP 和 ABI：两串不同的字节不会被解析成同一笔交易，签名用的字节就是审阅时解析的那串字节。请求里声明的链 ID 必须和交易内的一致。
- 签名前重新推导私钥，并和账户缓存的公钥核对；签名后验签、恢复签名地址，确认无误才显示签名二维码。使用确定性随机数（RFC 6979）和 low-s。
- 不可信的二维码数据先做 CBOR 结构检查再解析（声明长度不能超过实际数据、只接受定长编码、限制嵌套深度、只在 Keystone 协议使用的位置接受标签）。
- 依赖库的校验和固定在 `gradle/verification-metadata.xml` 中。

## 已知限制

- 没有第三方审计，只做过自查（见 `AuditRegressionTest`）。
- 不签消息，所以 DApp 登录、Permit、EIP-712 都用不了。
- Java 运行环境无法可靠清除私钥计算过程中的所有中间副本（BigInteger、String）。
- 暂不支持可复现构建。

## 从源码编译

需要 JDK 17 和 Android SDK（platform 35、build-tools 35）。

```bash
./gradlew testDebugUnitTest     # 单元测试
./gradlew assembleRelease       # 需要 keystore.properties 和 release.jks
```

没有 `keystore.properties` 时，`assembleRelease` 生成未签名的 APK。用你自己的密钥签名后，它是另一个 App 身份，无法升级官方发布的版本。

测试说明、互通测试和协议格式见英文 [README](README.md)。

## 许可证

GPL-3.0。本项目与 OKX、Rabby、MetaMask、Keystone 均无关联，提到它们的名字只为说明兼容性。
