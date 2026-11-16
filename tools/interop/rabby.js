// Rabby / MetaMask path: Keystone's base-eth-keyring syncs from our crypto-hdkey and signs through ColdEVM.
// Usage: node rabby.js <exchange dir>   (waits for sig-rabby-*.txt written by InteropTest.signJsRequests)
const xdir = process.argv[2];
const fs = require('fs'), path = require('path');
const { URDecoder, UREncoder } = require('@ngraveio/bc-ur');
const { CryptoHDKey } = require('@keystonehq/bc-ur-registry');
const { ETHSignature } = require('@keystonehq/bc-ur-registry-eth');
const { BaseKeyring } = require('@keystonehq/base-eth-keyring');
const { TransactionFactory } = require('@keystonehq/base-eth-keyring/node_modules/@ethereumjs/tx');
const { Common } = require('@keystonehq/base-eth-keyring/node_modules/@ethereumjs/common');
const { ethers } = require('ethers');
const assert = (c, m) => { if (!c) { console.error('FAIL: ' + m); process.exitCode = 1; } else console.log('ok   ' + m); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
function decodeParts(file) {
  const d = new URDecoder();
  for (const l of fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)) { d.receivePart(l); if (d.isComplete()) break; }
  return d.resultUR();
}
let n = 0;
class FileKeyring extends BaseKeyring {
  constructor() {
    super();
    this.getInteraction = () => ({
      requestSignature: async (signRequest) => {
        const name = 'rabby-' + (++n);
        const enc = new UREncoder(signRequest.toUR(), 150); const parts = [];
        for (let i = 0; i < enc.fragmentsLength * 2; i++) parts.push(enc.nextPart().toUpperCase());
        fs.writeFileSync(path.join(xdir, 'req-' + name + '.txt'), parts.join('\n'));
        const sigFile = path.join(xdir, 'sig-' + name + '.txt');
        for (let i = 0; i < 600 && !fs.existsSync(sigFile); i++) await sleep(500);
        const rev = path.join(xdir, 'review-' + name + '.txt');
        if (fs.existsSync(rev)) console.log('     ColdEVM review:\n       ' + fs.readFileSync(rev, 'utf8').trim().split('\n').join('\n       '));
        return ETHSignature.fromCBOR(decodeParts(sigFile).cbor);
      },
    });
  }
}
(async () => {
  const ur = decodeParts(path.join(xdir, 'hdkey.txt'));
  assert(ur.type === 'crypto-hdkey', 'UR type ' + ur.type);
  const kr = new FileKeyring();
  kr.syncKeyring(CryptoHDKey.fromCBOR(ur.cbor));
  const [a1, a2] = await kr.addAccounts(2);
  assert(a1.toLowerCase() === '0x9858effd232b4033e47d90003d41ec34ecaeda94', 'Rabby keyring account 1 = ' + a1);
  assert(a2.toLowerCase() === '0x6fac4d18c912343bf86fa7049364dd4e424ab9c0', 'Rabby keyring account 2 = ' + a2);
  console.log('     keyring xfp', kr.xfp, 'name', kr.name, 'keyringMode', kr.keyringMode);
  const BOB = '0x3535353535353535353535353535353535353535';
  const cases = [
    { from: a1, tx: { type: 2, chainId: 8453n, nonce: 1n, maxPriorityFeePerGas: 10n ** 6n, maxFeePerGas: 10n ** 8n, gasLimit: 21000n, to: BOB, value: 10n ** 16n }, common: Common.custom({ chainId: 8453 }) },
    { from: a2, tx: { type: 0, nonce: 2n, gasPrice: 3n * 10n ** 9n, gasLimit: 21000n, to: BOB, value: 10n ** 17n }, common: Common.custom({ chainId: 56 }) },
  ];
  for (const c of cases) {
    const tx = TransactionFactory.fromTxData(c.tx, { common: c.common });
    const signed = await kr.signTransaction(c.from, tx);
    const raw = '0x' + Buffer.from(signed.serialize()).toString('hex');
    const back = ethers.Transaction.from(raw);
    assert(back.from.toLowerCase() === c.from.toLowerCase() && signed.verifySignature(), `type ${c.tx.type} chain ${back.chainId}: signed by ${back.from}`);
  }
})().catch(e => { console.error(e); process.exit(1); });
