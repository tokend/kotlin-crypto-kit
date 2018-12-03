package org.tokend.crypto.ecdsa

import com.google.common.io.BaseEncoding
import org.junit.Assert
import org.junit.Test

class EcDSAKeyPairTest {
    val CURVE = Curves.ED25519_SHA512
    val PRIVATE_KEY_SEED = (0 until 32).map { it.toByte() }.toByteArray()
    val PUBLIC_KEY_BYTES = BaseEncoding.base16().decode(
            "03A107BFF3CE10BE1D70DD18E74BC09967E4D6309BA50D5F1DDC8664125531B8")
    val DATA = "TokenD is awesome".toByteArray()
    val DATA_SIGNATURE = BaseEncoding.base16().decode(
            "B0B890056CCBA3B3188EFF742F581EC08F0540706C9AA83B2B669E58F5E488DD892FD543F9C9182F6E6CBA013D3953CADD2D9EDF2938A45918F063FCA01A0B0A"
    )

    @Test
    fun fromPrivateKeySeed() {
        val keyPair = EcDSAKeyPair.fromPrivateKeySeed(CURVE, PRIVATE_KEY_SEED)
        Assert.assertArrayEquals(PRIVATE_KEY_SEED, keyPair.privateKeySeed)
    }

    @Test
    fun fromPublicKeyBytes() {
        val keyPair = EcDSAKeyPair.fromPublicKeyBytes(CURVE, PUBLIC_KEY_BYTES)
        Assert.assertArrayEquals(PUBLIC_KEY_BYTES, keyPair.publicKeyBytes)
    }

    @Test
    fun canSignTrue() {
        val keyPair = EcDSAKeyPair.fromPrivateKeySeed(CURVE, PRIVATE_KEY_SEED)
        Assert.assertTrue(keyPair.canSign)
    }

    @Test
    fun canSignFalse() {
        val keyPair = EcDSAKeyPair.fromPublicKeyBytes(CURVE, PUBLIC_KEY_BYTES)
        Assert.assertFalse(keyPair.canSign)
    }

    @Test
    fun sign() {
        val keyPair = EcDSAKeyPair.fromPrivateKeySeed(CURVE, PRIVATE_KEY_SEED)
        val signature = keyPair.sign(DATA)
        Assert.assertArrayEquals(DATA_SIGNATURE, signature)
    }

    @Test
    fun verifyValid() {
        val keyPair = EcDSAKeyPair.fromPrivateKeySeed(CURVE, PRIVATE_KEY_SEED)
        Assert.assertTrue(keyPair.verify(DATA, DATA_SIGNATURE))
    }

    @Test
    fun verifyInvalid() {
        val keyPair = EcDSAKeyPair.fromPrivateKeySeed(CURVE, PRIVATE_KEY_SEED)
        Assert.assertFalse(keyPair.verify(ByteArray(0), ByteArray(0)))
    }

    @Test
    fun destroy() {
        val seedCopy = PRIVATE_KEY_SEED.copyOf()
        val keyPair = EcDSAKeyPair.fromPrivateKeySeed(CURVE, PRIVATE_KEY_SEED)
        keyPair.destroy()

        Assert.assertArrayEquals("KeyPair has destroyed the original seed",
                seedCopy, PRIVATE_KEY_SEED)
        Assert.assertNull(keyPair.privateKeyBytes)
        Assert.assertNull(keyPair.privateKeySeed)
    }

    @Test
    fun isDestroyedTrue() {
        val keyPair = EcDSAKeyPair.fromPrivateKeySeed(CURVE, PRIVATE_KEY_SEED)
        keyPair.destroy()
        Assert.assertTrue(keyPair.isDestroyed)
    }

    @Test
    fun isDestroyedFalse() {
        val keyPair = EcDSAKeyPair.fromPrivateKeySeed(CURVE, PRIVATE_KEY_SEED)
        Assert.assertFalse(keyPair.isDestroyed)
    }
}