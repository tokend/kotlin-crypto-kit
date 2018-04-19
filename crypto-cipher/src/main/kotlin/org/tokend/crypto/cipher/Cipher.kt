package org.tokend.crypto.cipher

interface Cipher {
    /**
     * Encrypts data with given key.
     */
    fun encrypt(data: ByteArray, key: ByteArray): ByteArray

    /**
     * Decrypts cipher text with given key.
     * @throws InvalidCipherTextException if cipher text is invalid in some way
     */
    @Throws(InvalidCipherTextException::class)
    fun decrypt(cipherText: ByteArray, key: ByteArray): ByteArray
}