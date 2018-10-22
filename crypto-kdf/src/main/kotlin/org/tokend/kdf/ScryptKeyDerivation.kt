package org.tokend.kdf

import org.spongycastle.crypto.generators.SCrypt

/**
 * Implements a classic scrypt KDF.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Scrypt">Scrypt in Wikipedia</a>
 */
open class ScryptKeyDerivation : KeyDerivationFunction {
    protected val n: Int
    protected val r: Int
    protected val p: Int

    /**
     * Creates scrypt instance with given params.
     * @param n iterations count
     * @param r block size
     * @param p parallelization factor
     */
    constructor(n: Int, r: Int, p: Int) {
        this.n = n
        this.r = r
        this.p = p
    }

    override fun derive(passphrase: ByteArray, salt: ByteArray, keyLengthBytes: Int): ByteArray {
        return SCrypt.generate(passphrase, salt, n, r, p, keyLengthBytes)
    }
}