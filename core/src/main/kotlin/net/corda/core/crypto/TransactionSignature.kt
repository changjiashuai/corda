package net.corda.core.crypto

import net.corda.core.serialization.CordaSerializable
import java.security.InvalidKeyException
import java.security.PublicKey
import java.security.SignatureException
import java.util.*

/**
 * A wrapper around a digital signature accompanied with metadata.
 * This is similar to [DigitalSignature.WithKey], but targeted to DLT transaction signatures.
 */
@CordaSerializable
open class TransactionSignature(bytes: ByteArray, val by: PublicKey, val transactionSignatureMeta: TransactionSignatureMeta): DigitalSignature(bytes) {
    /**
     * Function to verify a [MerkleRootWithMeta] object's signature.
     * Note that [MerkleRootWithMeta] contains merkle root of the transaction and extra metadata, such as DLT's platform version.
     *
     * @param merkleRoot transaction's merkle root, which along with [transactionSignatureMeta] will be used to construct the [MerkleRootWithMeta] object to be signed.
     * @throws InvalidKeyException if the key is invalid.
     * @throws SignatureException if this signatureData object is not initialized properly,
     * the passed-in signatureData is improperly encoded or of the wrong type,
     * if this signatureData algorithm is unable to process the input data provided, etc.
     * @throws IllegalArgumentException if the signature scheme is not supported for this private key or if any of the clear or signature data is empty.
     */
    @Throws(InvalidKeyException::class, SignatureException::class)
    fun verify(merkleRoot: SecureHash) = Crypto.doVerify(merkleRoot, this)

    @Throws(InvalidKeyException::class, SignatureException::class)
    fun isValid(merkleRoot: SecureHash) = Crypto.isValid(merkleRoot, this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TransactionSignature) return false

        return (Arrays.equals(bytes, other.bytes)
                && by == other.by
                && transactionSignatureMeta == other.transactionSignatureMeta)
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + by.hashCode()
        result = 31 * result + transactionSignatureMeta.hashCode()
        return result
    }
}
