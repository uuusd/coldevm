package org.coldevm.signer

import com.sparrowwallet.hummingbird.UR
import com.sparrowwallet.hummingbird.UREncoder
import org.coldevm.signer.ur.KeystoneUr
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/** Writes the Rabby / MetaMask connect QR (crypto-hdkey) for tools/interop/rabby.js. */
class InteropRabbyTest {
    private val dir = System.getenv("COLDEVM_INTEROP_DIR")?.let(::File)

    @Test fun writeHdKeyUr() {
        assumeTrue(dir != null)
        val enc = UREncoder(UR(KeystoneUr.TYPE_HDKEY, KEYS.standardHdKey(MFP, "钱包 1")), 200, 10, 0)
        File(dir, "hdkey.txt").writeText((0 until enc.seqLen * 3).joinToString("\n") { enc.nextPart().uppercase() })
    }
}
