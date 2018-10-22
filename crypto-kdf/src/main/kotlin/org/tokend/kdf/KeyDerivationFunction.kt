package org.tokend.kdf

/**
 * Represents key derivation function interface.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Key_derivation_function">KDF in Wikipedia</a>
 */
interface KeyDerivationFunction {
    /**
     * Derives key of given length from passphrase and salt.
     */
    fun derive(passphrase: ByteArray, salt: ByteArray, keyLengthBytes: Int): ByteArray
}