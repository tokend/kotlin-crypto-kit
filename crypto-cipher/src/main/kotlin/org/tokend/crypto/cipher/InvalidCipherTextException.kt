package org.tokend.crypto.cipher

/**
 * Thrown if cipher text is invalid in some way.
 */
class InvalidCipherTextException: Exception {
    constructor(): super()
    constructor(t: Throwable): super(t)
}