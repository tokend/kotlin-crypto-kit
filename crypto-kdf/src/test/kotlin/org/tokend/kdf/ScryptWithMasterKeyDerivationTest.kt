package org.tokend.kdf

import org.junit.Assert
import org.junit.Test
import org.spongycastle.util.encoders.Base64
import org.spongycastle.util.encoders.Hex

class ScryptWithMasterKeyDerivationTest {
    val N = 4096
    val R = 8
    val P = 1
    val KEY_LENGTH = 32
    val MASTER_KEY = "WALLET_ID".toByteArray()
    val LOGIN = "oleg@tokend.org".toByteArray()
    val PASSPHRASE = "qwe123".toByteArray()
    val SALT = Base64.decode("67ufG1N/Rf+j2ugDaXaopw==")

    @Test
    fun defaultEncryptionVersion() {
        Assert.assertEquals(1.toByte(),
                ScryptWithMasterKeyDerivation(N, R, P, LOGIN, MASTER_KEY).encryptionVersion)
    }

    @Test
    fun derive() {
        val expectedKey = Hex.decode("96319900eff4dcc51beabd55200aa0f29490191ede16d26cd6adcc2554416dc3")
        val key = ScryptWithMasterKeyDerivation(N, R, P, LOGIN, MASTER_KEY)
                .derive(PASSPHRASE, SALT, KEY_LENGTH)
        Assert.assertArrayEquals(expectedKey, key)
    }
}