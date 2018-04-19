package org.tokend.crypto.cipher

import org.junit.Assert
import org.junit.Test
import org.spongycastle.util.encoders.Base64
import org.spongycastle.util.encoders.Hex

class Aes256GCMTest {
    val DATA = "TokenD is awesome".toByteArray()
    val ENCRYPTED = Hex.decode("7056bd62af0a6d574a5b8bb1b0da278bdd36b5ef529a14164cd7db716e8556f3f8")
    val KEY = Hex.decode(
            "2e0c7a28545d4c53a1f4b9ef82245d7da853c7f0b0ae949040faedaa60c23c0b")
    val IV = Base64.decode("dcDptDqlQv7tWIT2")

    @Test
    fun encrypt() {
        val encrypted = Aes256GCM(IV).encrypt(DATA, KEY)
        Assert.assertArrayEquals(ENCRYPTED, encrypted)
    }

    @Test
    fun decrypt() {
        val decrypted = Aes256GCM(IV).decrypt(ENCRYPTED, KEY)
        Assert.assertArrayEquals(DATA, decrypted)
    }

    @Test
    fun failedDecrypt() {
        try {
            Aes256GCM(IV).decrypt(ByteArray(0), KEY)
            Assert.fail()
        } catch (ex: InvalidCipherTextException) {
        }
    }
}