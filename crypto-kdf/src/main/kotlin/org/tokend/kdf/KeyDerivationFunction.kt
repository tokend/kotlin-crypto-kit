package org.tokend.kdf

interface KeyDerivationFunction {
    /**
     * Derives key from given passphrase and salt.
     */
    fun derive(passphrase: ByteArray, salt: ByteArray, keyLengthBytes: Int): ByteArray
}