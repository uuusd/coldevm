# ColdEVM: an air-gapped EVM transaction signer for Android

English | [简体中文](README.zh-CN.md)

> ⚠️ **Disclaimer**: This software is provided "as is", without warranty of any kind, and **has not been audited by a third party**. You are solely responsible for your keys and funds — start with small amounts. Please report security issues privately as described in [SECURITY.md](SECURITY.md), not as public issues.

Install it on a phone that never goes online (e.g. a Pixel running GrapheneOS). **OKX Wallet**, **Rabby** or **MetaMask** on your online device treats it as a **Keystone hardware wallet**; the two devices talk only through QR codes. It is the EVM sibling of [ColdSol](https://github.com/uuusd/coldsol) and shares its seed storage, scanner and review design.

```
Online device (OKX / Rabby)                   Offline phone (ColdEVM)
   │  ①  scan pairing code  ◄───────────────  extended public keys only
   │  ②  build a transaction, shows
   │      eth-sign-request  ────────────────►  scan → parse → you review every item
   │                                           → screen-lock PIN (or fingerprint) → sign
   │  ③  scan eth-signature ◄───────────────  shows signature QR
   │  ④  broadcast
```

**Transactions only.** This version signs legacy (EIP-155) and EIP-1559 transactions on any EVM chain. It refuses message signing (`personal_sign`, EIP-712), EIP-7702 authorizations (type 4, always), type 1 and type 3 transactions, transactions without a chain id, and batch requests.

## Installation

1. Download `coldevm-<version>.apk` from [GitHub Releases](../../releases), **verify it** (below), copy it to the offline phone over USB and install it. Or build it yourself.
2. The manifest never requests `INTERNET`; GrapheneOS's app info shows no Network permission.
3. The offline phone must have a screen lock. ⚠️ Never remove the screen lock later: Android permanently invalidates the Keystore keys and you would have to re-import your mnemonic.

## Verifying the APK

```bash
sha256sum coldevm-<version>.apk
apksigner verify --print-certs coldevm-<version>.apk
```

`Signer #1 certificate SHA-256 digest` must be:

```
9a4541a4708e2d2fa4f08a2b70b3501468f3bced6153c4d7baaab6ccfecd0973
```

Every release is signed with this certificate. Do not install an APK with a different fingerprint.

## Setup

Import a 12/24-word mnemonic (optional BIP39 passphrase) or generate 24 words. Account 1 (`m/44'/60'/0'/0/0`) is shown so you can compare it with your existing wallet before saving. The seed is encrypted with an AES-256-GCM key held in the secure element (StrongBox where available) that requires authentication on every use. Multiple wallets are supported; requests are routed by master fingerprint.

## Connecting

| Online wallet | In ColdEVM | In the online wallet | Accounts |
|---|---|---|---|
| OKX Wallet | Wallet → **Connect OKX** | Add wallet → Connect hardware wallet → Keystone | `m/44'/60'/0'/0/n` and Ledger Live `m/44'/60'/n'/0/0` |
| Rabby / MetaMask | Wallet → **Connect Rabby** | Add address → Hardware wallet → Keystone (MetaMask: Add hardware wallet → QR-based) | `m/44'/60'/0'/0/n` |

After connecting, compare account 1's address in both apps.

## What the review screen shows

- Network name and chain id, amount and recipient (addresses in groups of four, first and last group highlighted), maximum fee.
- Decoded calls: native transfers, ERC-20 `transfer`, `approve` / `increaseAllowance` (red; unlimited amounts get an extra warning; `approve(…, 0)` is shown as a revocation), `setApprovalForAll` (red), `transferFrom` / `safeTransferFrom`.
- Lending and savings protocols, recognised only by chain **and** address (verified on chain, see `Protocols.kt`): Aave V3 (11 chains) and SparkLend `supply` / `withdraw` and the native-coin gateways, Spark savings vaults (sDAI, sUSDS, sUSDC, spUSDC, spUSDT, spETH, spPYUSD) `deposit` / `mint` / `withdraw` / `redeem`, and Benqi core markets on Avalanche `mint` / `redeem` / `redeemUnderlying`. These show as "deposit 1000 USDC into Aave V3 Pool (Avalanche)" instead of a blind call; every `onBehalfOf` / `receiver` / `to` / `owner` must be one of your own accounts or the review turns red. Approving a normal amount to one of these contracts is yellow; unlimited approvals and absurd finite ones (more than 10^12 tokens) stay red. Other functions on these contracts (borrow, liquidation, …) remain unknown calls.
- Token names come only from a built-in list: USDT/USDC on Ethereum, BNB Chain, Polygon, Avalanche, Arbitrum and Base, plus the underlying assets of the protocols above (WETH, DAI, USDS, PYUSD on Ethereum; sAVAX, BTC.b, WETH.e, LINK.e, USDT.e, USDC.e, DAI.e on Avalanche), each read on chain. Any other token is "unknown token" with its raw amount — a fake token can use any name, not these addresses.
- Unknown contract calls, contract creation and malformed arguments are red ("blind signing") and need an explicit acknowledgement before signing.
- Fees: yellow above a per-chain normal level, red (acknowledgement required) above 10×, and a warning when the fee exceeds the amount sent.
- Recipient history: "never signed a transfer to this address" vs "signed N transfers before"; an address whose first and last 3 hex digits match one of your 110 own accounts or a previous recipient but which is different is flagged red as likely **address poisoning** and needs the explicit acknowledgement before signing; so does a recipient that is itself a listed token contract.

## Security design

- No network permission; FLAG_SECURE (no screenshots), overlay windows hidden while the app is in front, no backup / device transfer of app data.
- The seed is decrypted only for one signature, after authentication, and wiped afterwards.
- Before every signature the cached public keys (own accounts, receive addresses) are re-derived from the seed; on a mismatch the cache is rebuilt and the request refused.
- Strict, canonical RLP and ABI decoding: two different byte strings never decode to the same transaction, and the bytes that are hashed are exactly the bytes that were reviewed. The chain id declared in the request must match the one inside the transaction.
- Before signing, the private key is derived again and checked against the account's cached public key; after signing, the signature is verified and the signer address recovered before it is shown. Deterministic nonces (RFC 6979), low-s.
- Untrusted QR payloads pass a structural CBOR check before parsing (declared lengths must fit the data, definite lengths only, depth limit, tags only where the Keystone protocol uses them).
- Dependency checksums are pinned in `gradle/verification-metadata.xml`.

## Known limitations

- No third-party audit; self-reviewed only (see `AuditRegressionTest`).
- No message signing, so DApp logins, Permit and EIP-712 do not work. On Aave / Spark choose "approve with transaction" instead of a signed permit.
- The JVM cannot reliably wipe every intermediate copy of key material (BigInteger, String).
- Builds are reproducible in practice (a rebuild of the tagged commit with the same toolchain gives identical APK contents apart from the signature block), but this is not yet independently verified or documented step by step.

## Building from source

Requires JDK 17 and the Android SDK (platform 35, build-tools 35).

```bash
./gradlew testDebugUnitTest     # unit tests
./gradlew assembleRelease       # needs keystore.properties + release.jks
```

Without `keystore.properties`, `assembleRelease` produces an unsigned APK; signed with your own key it is a different app identity and cannot upgrade the official releases.

### Tests

- BIP32 test vector 1, EIP-55 examples, the EIP-155 worked example (exact r and s), `abandon … about` → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`, master fingerprint `73c5da0a`.
- Review and refusal rules; RLP canonical-encoding fuzzing; CBOR fuzzing (no crash, no leaked state).
- `tools/interop/run.sh <node_modules>`: round trip with `@keystonehq/keystone-sdk` and `ethers` 6 (the OKX path) — pairing payload passes the SDK's strict validator, xpub and addresses match ethers, legacy / EIP-1559 / ERC-20 / approve / Ledger Live requests are signed and the signed transactions recover the right sender.
- `tools/interop/run-rabby.sh <node_modules>`: the same with `@keystonehq/base-eth-keyring` (Rabby / MetaMask).

Both scripts run Node in a `node:22-alpine` container without network access.

## Protocol reference

Formats follow the Keystone 3 firmware (`rust/apps/wallets/src/okx.rs`, `metamask.rs`, `rust/rust_c/src/ethereum`) and `@keystonehq/bc-ur-registry-eth`:

- OKX: `crypto-multi-accounts` with the `m/44'/60'/0'` xpub (`account.standard`) and ten `m/44'/60'/n'/0/0` keys (`account.ledger_live`), device "Keystone 3 Pro".
- Rabby / MetaMask: `crypto-hdkey` of `m/44'/60'/0'`, children `0/*`, ETH coin info.
- `eth-sign-request` (401): data type 1 = legacy RLP, 4 = typed transaction (only `0x02` is accepted).
- `eth-signature` (402): `r ‖ s ‖ v`, v minimal big-endian (EIP-155 value for legacy, y-parity for typed).

## License

GPL-3.0. This project is not affiliated with OKX, Rabby, MetaMask or Keystone; their names are used only to describe compatibility.
