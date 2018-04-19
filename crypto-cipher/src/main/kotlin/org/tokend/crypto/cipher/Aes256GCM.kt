package org.tokend.crypto.cipher

import org.spongycastle.crypto.engines.AESEngine
import org.spongycastle.crypto.modes.GCMBlockCipher
import org.spongycastle.crypto.params.KeyParameter
import org.spongycastle.crypto.params.ParametersWithIV

/**
 * Represents AES-256-GCM cipher.
 */
class Aes256GCM : Cipher{
    private val iv: ByteArray

    /**
     * Creates AES-256-GCM cipher initialized with given IV.
     * @param iv non-empty byte array of initialization vector
     */
    constructor(iv: ByteArray) {
        if (iv.isEmpty()) {
            throw IllegalArgumentException("IV must be at least 1 byte")
        }

        this.iv = iv
    }

    /**
     * Encrypts data with given 128/192/256 bits key.
     */
    override fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
        return applyCipher(data, key, false)
    }

    /**
     * Decrypts cipher text with given 128/192/256 bits key.
     * @throws InvalidCipherTextException if cipher text is invalid in some way
     */
    override fun decrypt(cipherText: ByteArray, key: ByteArray): ByteArray {
        try {
            return applyCipher(cipherText, key, true)
        } catch (cryptoException: org.spongycastle.crypto.InvalidCipherTextException) {
            throw InvalidCipherTextException(cryptoException)
        }
    }

    private fun applyCipher(data: ByteArray, key: ByteArray, isDecrypt: Boolean): ByteArray {
        val cipher = GCMBlockCipher(AESEngine())
        cipher.init(!isDecrypt, ParametersWithIV(KeyParameter(key), iv))

        val out = ByteArray(cipher.getOutputSize(data.size))
        var processed = cipher.processBytes(data, 0, data.size, out, 0)
        processed += cipher.doFinal(out, processed)

        return out
    }
}