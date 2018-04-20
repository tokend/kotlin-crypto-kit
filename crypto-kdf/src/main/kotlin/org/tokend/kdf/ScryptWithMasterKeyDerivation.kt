package org.tokend.kdf

import org.spongycastle.crypto.generators.SCrypt
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Implements an advanced scrypt KDF based on login and master key
 * used in TokenD/Stellar ecosystem.
 */
class ScryptWithMasterKeyDerivation: ScryptKeyDerivation {
    private val login: ByteArray
    private val masterKey: ByteArray

    /**
     * Creates based on master key and login scrypt instance with given params.
     * @param n iterations count
     * @param r block size
     * @param p parallelization factor
     * @param login login
     * @param masterKey master key
     */
    constructor(n: Int, r: Int, p: Int,
                login: ByteArray, masterKey: ByteArray) : super(n, r, p) {
        this.login = login
        this.masterKey = masterKey
    }

    /**
     * Version byte of the encryption method. 1 by default.
     */
    val encryptionVersion: Byte = 1

    override fun derive(passphrase: ByteArray, salt: ByteArray, keyLengthBytes: Int): ByteArray {
        // For this derivation type we are composing
        // another salt as a sha256(VERSION+ORIGINAL_SALT+LOGIN)
        val composedRawSalt = ByteArray(1 + salt.size + login.size)
        composedRawSalt[0] = encryptionVersion
        System.arraycopy(salt, 0, composedRawSalt, 1, salt.size)
        System.arraycopy(login, 0, composedRawSalt, 1 + salt.size, login.size)
        val composedSalt = MessageDigest.getInstance(COMPOSED_SALT_HASH_ALG).digest(composedRawSalt)

        val key = SCrypt.generate(passphrase, composedSalt, n, r, p, keyLengthBytes)

        val hmacSha256 = Mac.getInstance(MASTER_KEY_MAC_ALG)
        hmacSha256.init(SecretKeySpec(key, MASTER_KEY_MAC_ALG))

        return hmacSha256.doFinal(masterKey)
    }

    companion object {
        private const val COMPOSED_SALT_HASH_ALG = "SHA-256"
        private const val MASTER_KEY_MAC_ALG = "HmacSHA256"
    }
}