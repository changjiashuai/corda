package net.corda.core.crypto

import net.corda.core.serialization.CordaSerializable
import net.corda.core.serialization.serialize

/**
 * TransactionSignatureMeta is required to add extra meta-data to a transaction's signature.
 * It currently supports platformVersion only, but it can be extended to support a universal digital
 * signature model enabling partial signatures and attaching extra information, such as a user's timestamp or other
 * application-specific fields.
 *
 * @param platformVersion current DLT version.
 */
@CordaSerializable
open class TransactionSignatureMeta(val platformVersion: Int) {

    fun bytes() = this.serialize().bytes

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TransactionSignatureMeta) return false
        return platformVersion == other.platformVersion
    }

    override fun hashCode(): Int {
        return platformVersion
    }

    override fun toString(): String {
        return "TransactionSignatureMeta(platformVersion=$platformVersion)"
    }
}
