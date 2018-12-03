package org.tokend.crypto.ecdsa

import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.KeyPairGenerator
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import java.security.*
import javax.security.auth.Destroyable

/**
 * Holds private and/or public keys defined on elliptic curve.
 */
class EcDSAKeyPair private constructor(
        private val curveSpec: EdDSANamedCurveSpec,
        private val publicKey: EdDSAPublicKey,
        private var privateKey: EdDSAPrivateKey? = null
) : Destroyable {
    private fun getSignatureEngine(): Signature =
            EdDSAEngine(MessageDigest.getInstance(curveSpec.hashAlgorithm))

    /**
     * @return raw public key bytes
     */
    val publicKeyBytes: ByteArray
        get() = publicKey.abyte

    /**
     * @return raw private key bytes if keypair has it
     */
    val privateKeyBytes: ByteArray?
        get() = privateKey?.geta()

    /**
     * @return private key seed if keypair has it
     */
    val privateKeySeed: ByteArray?
        get() = privateKey?.seed

    /**
     * @return [true] if keypair can be used for signing i.e. it has a private key, false otherwise
     */
    val canSign: Boolean
        get() = privateKey != null

    /**
     * Signs given data with private key if keypair has it
     *
     * @throws SignUnavailableException if keypair can't be used for signing
     *
     * @see [EcDSAKeyPair.canSign]
     * @see [EcDSAKeyPair.isDestroyed]
     */
    fun sign(data: ByteArray): ByteArray {
        if (!canSign) {
            throw SignUnavailableException()
        }

        val signatureEngine = getSignatureEngine()
        signatureEngine.initSign(privateKey)
        signatureEngine.update(data)

        return signatureEngine.sign()
    }

    /**
     * Verifies signature for provided data with public key
     *
     * @return [true] if the signature is valid, [false] otherwise
     */
    fun verify(data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val signatureEngine = getSignatureEngine()
            signatureEngine.initVerify(publicKey)
            signatureEngine.update(data)
            signatureEngine.verify(signature)
        } catch (e: SignatureException) {
            false
        } catch (e: GeneralSecurityException) {
            throw RuntimeException(e)
        }
    }

    /**
     * Destroys keypair's private key by filling it content with zeros
     */
    override fun destroy() {
        privateKey?.h?.erase()
        privateKey?.abyte?.erase()
        privateKey?.geta()?.erase()
        privateKey?.seed?.erase()
        privateKey = null
    }

    /**
     * @return [true] if keypair private key is destroyed
     *
     * @see [EcDSAKeyPair.destroy]
     */
    override fun isDestroyed(): Boolean {
        return privateKey == null
    }

    companion object {
        private fun getCurveSpecByName(curveName: String): EdDSANamedCurveSpec {
            return EdDSANamedCurveTable.getByName(curveName) ?: throw NoCurveFoundException()
        }

        /**
         * Creates keypair for given curve with random keys.
         */
        @JvmStatic
        fun random(curveName: String): EcDSAKeyPair {
            val curveSpec = getCurveSpecByName(curveName)

            val generator = KeyPairGenerator()
            generator.initialize(curveSpec, SecureRandom())

            val keypair = generator.generateKeyPair()
            val publicKey = keypair.public as EdDSAPublicKey
            val privateKey = keypair.private as EdDSAPrivateKey

            return EcDSAKeyPair(curveSpec, publicKey, privateKey)
        }

        /**
         * Creates keypair from given 32 byte seed for given curve.
         * Original seed will be duplicated.
         */
        @JvmStatic
        fun fromPrivateKeySeed(curveName: String, seed: ByteArray): EcDSAKeyPair {
            val curveSpec = getCurveSpecByName(curveName)

            val privateKeySpec = EdDSAPrivateKeySpec(seed.copyOf(), curveSpec)
            val publicKeySpec = EdDSAPublicKeySpec(privateKeySpec.a.toByteArray(), curveSpec)

            return EcDSAKeyPair(curveSpec, EdDSAPublicKey(publicKeySpec), EdDSAPrivateKey(privateKeySpec))
        }

        /**
         * Creates 'verify-only' keypair from 32 bytes of public key for given curve.
         */
        @JvmStatic
        fun fromPublicKeyBytes(curveName: String, bytes: ByteArray): EcDSAKeyPair {
            val curveSpec = getCurveSpecByName(curveName)

            val publicKeySpec = EdDSAPublicKeySpec(bytes, curveSpec)

            return EcDSAKeyPair(curveSpec, EdDSAPublicKey(publicKeySpec))
        }
    }
}