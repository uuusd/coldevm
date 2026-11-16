// Interop test against Keystone's JS SDK (what OKX-style wallets use) and ethers.
// Usage: node interop.js <exchange dir> phase1|phase2
const [xdir, phase] = process.argv.slice(2);
const fs = require('fs'), path = require('path');
const { URDecoder, UREncoder } = require('@ngraveio/bc-ur');
const { KeystoneSDK } = require('@keystonehq/keystone-sdk');
const { ethers } = require('ethers');

const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const BOB = '0x3535353535353535353535353535353535353535';
const sdk = new KeystoneSDK();
const assert = (c, m) => { if (!c) { console.error('FAIL: ' + m); process.exitCode = 1; } else console.log('ok   ' + m); };

function decodeParts(file) {
  const d = new URDecoder();
  for (const line of fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)) { d.receivePart(line); if (d.isComplete()) break; }
  if (!d.isSuccess()) throw new Error('UR decode failed: ' + d.resultError());
  return d.resultUR();
}
function writeParts(file, ur) {
  const enc = new UREncoder(ur, 120);
  const parts = []; for (let i = 0; i < enc.fragmentsLength * 2; i++) parts.push(enc.nextPart().toUpperCase());
  fs.writeFileSync(file, parts.join('\n'));
}

const usdtPolygon = '0xc2132D05D31c914a87C6611C10748AEb04B58e8F';
const erc20 = new ethers.Interface(['function transfer(address,uint256)', 'function approve(address,uint256)']);

// name -> { tx, dataType, path, expectReject? }
function cases(xfp) {
  return {
    'legacy-bsc': { tx: { type: 0, chainId: 56, nonce: 7, gasPrice: 3n * 10n ** 9n, gasLimit: 21000, to: BOB, value: ethers.parseEther('0.25') }, dataType: 1, path: "m/44'/60'/0'/0/0" },
    '1559-eth': { tx: { type: 2, chainId: 1, nonce: 0, maxPriorityFeePerGas: 10n ** 9n, maxFeePerGas: 30n * 10n ** 9n, gasLimit: 21000, to: BOB, value: ethers.parseEther('1.5') }, dataType: 4, path: "m/44'/60'/0'/0/1" },
    'usdt-polygon': { tx: { type: 2, chainId: 137, nonce: 3, maxPriorityFeePerGas: 30n * 10n ** 9n, maxFeePerGas: 100n * 10n ** 9n, gasLimit: 65000, to: usdtPolygon, value: 0, data: erc20.encodeFunctionData('transfer', [BOB, 12_340_000n]) }, dataType: 4, path: "m/44'/60'/0'/0/0" },
    'approve-polygon': { tx: { type: 2, chainId: 137, nonce: 4, maxPriorityFeePerGas: 30n * 10n ** 9n, maxFeePerGas: 100n * 10n ** 9n, gasLimit: 60000, to: usdtPolygon, value: 0, data: erc20.encodeFunctionData('approve', [BOB, ethers.MaxUint256]) }, dataType: 4, path: "m/44'/60'/0'/0/0" },
    'ledger-live-arb': { tx: { type: 2, chainId: 42161, nonce: 0, maxPriorityFeePerGas: 0n, maxFeePerGas: 10n ** 8n, gasLimit: 30000, to: BOB, value: ethers.parseEther('0.01') }, dataType: 4, path: "m/44'/60'/2'/0/0" },
    'personal-msg': { raw: Buffer.from('hello'), dataType: 3, path: "m/44'/60'/0'/0/0", expectReject: true },
  };
}

if (phase === 'phase1') {
  const ur = decodeParts(path.join(xdir, 'sync.txt'));
  console.log('sync UR type:', ur.type, ur.cbor.length, 'bytes');
  const ma = sdk.parseMultiAccounts(ur);   // strict validation (allowlisted paths, notes, unique origins)
  console.log('device:', ma.device, '| deviceId:', ma.deviceId, '| version:', ma.deviceVersion, '| mfp:', ma.masterFingerprint, '| keys:', ma.keys.length);
  const root = ethers.HDNodeWallet.fromPhrase(PHRASE, undefined, 'm');
  assert(ma.masterFingerprint === root.fingerprint.slice(2), 'master fingerprint matches ethers (' + root.fingerprint + ')');
  const std = ma.keys.find(k => k.note === 'account.standard');
  const ethersXpub = root.derivePath("m/44'/60'/0'").neuter().extendedKey;
  assert(std && std.path === "m/44'/60'/0'" && std.extendedPublicKey === ethersXpub, 'standard xpub == ethers ' + ethersXpub);
  fs.writeFileSync(path.join(xdir, 'xpub.txt'), ethersXpub);
  const fromXpub = ethers.HDNodeWallet.fromExtendedKey(std.extendedPublicKey).derivePath('0/0').address;
  assert(fromXpub === '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', 'account 1 from xpub = ' + fromXpub);
  const ll = ma.keys.filter(k => k.note === 'account.ledger_live');
  assert(ll.length === 10, '10 ledger live keys');
  for (const k of ll) {
    const expect = root.derivePath(k.path).address;
    assert(ethers.computeAddress('0x' + k.publicKey) === expect, `${k.path} -> ${expect}`);
  }
  for (const [name, c] of Object.entries(cases(ma.masterFingerprint))) {
    const signData = c.raw ? c.raw.toString('hex') : ethers.Transaction.from(c.tx).unsignedSerialized.slice(2);
    const ur = sdk.eth.generateSignRequest({
      requestId: crypto.randomUUID(), signData, dataType: c.dataType, path: c.path, xfp: ma.masterFingerprint,
      chainId: c.tx ? c.tx.chainId : 1,
      // Alternate between the two forms wallets pass: bare hex (-> 20 bytes) and "0x…" (-> empty buffer).
      address: name.includes('1559') ? root.derivePath(c.path).address : root.derivePath(c.path).address.slice(2), origin: 'interop',
    });
    writeParts(path.join(xdir, 'req-' + name + '.txt'), ur);
  }
} else {
  const root = ethers.HDNodeWallet.fromPhrase(PHRASE, undefined, 'm');
  for (const [name, c] of Object.entries(cases())) {
    const review = path.join(xdir, 'review-' + name + '.txt');
    if (fs.existsSync(review)) console.log('     ColdEVM review ' + name + ':\n       ' + fs.readFileSync(review, 'utf8').trim().split('\n').join('\n       '));
    const rej = path.join(xdir, 'rej-' + name + '.txt');
    if (c.expectReject) { assert(fs.existsSync(rej), name + ' rejected: ' + (fs.existsSync(rej) ? fs.readFileSync(rej, 'utf8') : '')); continue; }
    const sig = sdk.eth.parseSignature(decodeParts(path.join(xdir, 'sig-' + name + '.txt')));
    const t = ethers.Transaction.from(c.tx);
    const raw = Buffer.from(sig.signature, 'hex');
    const r = '0x' + raw.subarray(0, 32).toString('hex'), s = '0x' + raw.subarray(32, 64).toString('hex');
    const v = BigInt('0x' + raw.subarray(64).toString('hex'));
    // Keystone-style v: legacy = EIP-155 value, typed = y-parity.
    t.signature = ethers.Signature.from({ r, s, v: t.type === 0 ? v : 27n + v });
    const expect = root.derivePath(c.path).address;
    assert(t.from === expect, `${name}: signed tx recovers ${t.from} (expect ${expect}), requestId echoed=${!!sig.requestId}`);
    // The broadcastable raw tx also parses back to the same sender.
    assert(ethers.Transaction.from(t.serialized).from === expect, `${name}: serialized tx ok (${t.serialized.length / 2 - 1} bytes)`);
  }
}
