package org.tokend.kdf

import org.junit.Assert
import org.junit.Test
import org.spongycastle.util.encoders.Base64
import org.spongycastle.util.encoders.Hex

class ScryptKeyDerivationTest {
    val N = 4096
    val R = 8
    val P = 1
    val KEY_LENGTH = 32
    val PASSPHRASE = "qwe123".toByteArray()
    val SALT = Base64.decode("67ufG1N/Rf+j2ugDaXaopw==")

    @Test
    fun derive() {
        val expectedKey = Hex.decode("88061aa9806b1007dbad487c65c0aa54fed2e8e1b8a4731c3ebbfb87f2ecdf21")
        val key = ScryptKeyDerivation(N, R, P).derive(PASSPHRASE, SALT, KEY_LENGTH)
        Assert.assertArrayEquals(expectedKey, key)
    }
}