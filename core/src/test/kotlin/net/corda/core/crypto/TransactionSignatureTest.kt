package net.corda.core.crypto

import net.corda.testing.TestDependencyInjectionBase
import org.junit.Test
import java.security.SignatureException
import kotlin.test.assertTrue

/**
 * Digital signature MetaData tests.
 */
class TransactionSignatureTest : TestDependencyInjectionBase() {

    val testBytes = "12345678901234567890123456789012".toByteArray()

    /** Valid sign and verify. */
    @Test
    fun `MetaData Full sign and verify`() {
        val keyPair = Crypto.generateKeyPair("ECDSA_SECP256K1_SHA256")

        // Create a MerkleRootWithMeta object.
        val meta = MerkleRootWithMeta(testBytes.sha256(), TransactionSignatureMeta(1))

        // Sign the meta object.
        val transactionSignature: TransactionSignature = keyPair.sign(meta)

        // Check auto-verification.
        assertTrue(transactionSignature.verify(testBytes.sha256()))

        // Check manual verification.
        assertTrue(Crypto.doVerify(testBytes.sha256(), transactionSignature))
    }

    /** Verification should fail; corrupted metadata - clearData (merkle root) has changed. */
    @Test(expected = SignatureException::class)
    fun `MetaData Full failure clearData has changed`() {
        val keyPair = Crypto.generateKeyPair("ECDSA_SECP256K1_SHA256")
        val meta = MerkleRootWithMeta(testBytes.sha256(), TransactionSignatureMeta(1))
        val transactionSignature = keyPair.sign(meta)
        Crypto.doVerify((testBytes + testBytes).sha256(), transactionSignature)
    }
}
