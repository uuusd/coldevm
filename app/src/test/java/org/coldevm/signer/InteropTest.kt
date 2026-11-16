package org.coldevm.signer

import com.sparrowwallet.hummingbird.UR
import com.sparrowwallet.hummingbird.URDecoder
import com.sparrowwallet.hummingbird.UREncoder
import org.coldevm.signer.ur.KeystoneUr
import org.coldevm.signer.vault.RejectedException
import org.coldevm.signer.vault.SignLogic
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Exchanges QR payloads with the official Keystone JS SDK and ethers (scripts in tools/interop).
 * Skipped unless COLDEVM_INTEROP_DIR is set.
 */
class InteropTest {
    private val dir = System.getenv("COLDEVM_INTEROP_DIR")?.let(::File)

    @Test fun writeSyncUr() {
        assumeTrue(dir != null)
        val ur = UR(KeystoneUr.TYPE_MULTI_ACCOUNTS, KeystoneUr.encodeMultiAccounts(MFP, "coldevm-test", KEYS.syncKeys()))
        val enc = UREncoder(ur, 200, 10, 0)
        File(dir, "sync.txt").writeText((0 until enc.seqLen * 3).joinToString("\n") { enc.nextPart().uppercase() })
    }

    /** Signs every req-<name>.txt the JS side wrote; writes sig-<name>.txt, or rej-<name>.txt with the reason. */
    @Test fun signJsRequests() {
        assumeTrue(dir != null)
        dir!!.listFiles { f -> f.name.startsWith("req-") }!!.sortedBy { it.name }.forEach { f ->
            val name = f.name.removePrefix("req-")
            val decoder = URDecoder()
            f.readLines().filter { it.isNotBlank() }.forEach { if (decoder.result == null) decoder.receivePart(it.lowercase()) }
            val ur = decoder.result.ur
            check(ur.type == KeystoneUr.TYPE_ETH_SIGN_REQUEST) { "type ${ur.type}" }
            val req = KeystoneUr.decodeSignRequest(ur.cborBytes)
            try {
                val review = SignLogic.review(req, MFP, KEYS)
                val s = review.summary
                File(dir, "review-$name").writeText(buildString {
                    appendLine("${s.action} | ${s.chainLabel} | fee ${s.maxFee} | risk ${s.worstRisk}")
                    s.headlines.forEach { appendLine("  -> ${it.amount} to ${it.to} (${it.status})") }
                    s.warnings.forEach { appendLine("  ! ${it.first}: ${it.second}") }
                })
                val sig = SignLogic.sign(SEED, review.account, review.tx, req.signData)
                val out = UREncoder(UR(KeystoneUr.TYPE_ETH_SIGNATURE, KeystoneUr.encodeSignature(req.requestId, sig)), 200, 10, 0)
                File(dir, "sig-$name").writeText(out.nextPart().uppercase())
            } catch (e: RejectedException) {
                File(dir, "rej-$name").writeText(e.message ?: "")
            }
        }
    }
}
