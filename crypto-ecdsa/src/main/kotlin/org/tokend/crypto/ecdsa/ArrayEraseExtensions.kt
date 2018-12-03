@file:JvmName("ArraysErasing")

package org.tokend.crypto.ecdsa

fun ByteArray.erase() {
    fill(0)
}

fun CharArray.erase() {
    fill('0')
}