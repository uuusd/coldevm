# Security Policy / 安全政策

## Reporting a vulnerability

**Do not open a public issue for security problems.** Report them privately through GitHub: the repository's **Security** tab → **Report a vulnerability** (GitHub private vulnerability reporting).

Please include:

- the affected version (shown at the top of the Settings tab)
- what an attacker can achieve (e.g. sign something the user did not see, make a wrong recipient or chain look right, read the seed)
- steps or a sample `eth-sign-request` / transaction to reproduce

In scope: anything that leads to signing a transaction the review screen misrepresents, seed or key disclosure, bypassing authentication, or breaking the offline guarantees. Out of scope: attacks that require the user's unlocked offline phone plus their PIN, or a compromised OS.

I will acknowledge reports as soon as I can, fix confirmed issues with a regression test, and credit reporters in the release notes unless they prefer otherwise.

## 报告漏洞

**安全问题请不要公开发 issue。** 请通过 GitHub 私下报告：仓库的 **Security** 标签 → **Report a vulnerability**。

请写明：受影响的版本；攻击者能做到什么（例如让用户签下审阅页没显示的内容、让错误的收款人或网络看起来正确、读取种子）；复现步骤，或者一个能复现的 `eth-sign-request` / 交易样例。

确认的问题会附带回归测试修复，除非报告者不愿意，否则会在发布说明中致谢。

## Supported versions / 支持的版本

Only the latest release receives fixes. / 只有最新版本会收到修复。
