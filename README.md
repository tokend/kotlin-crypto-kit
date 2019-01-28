# TokenD Kotlin crypto kit

Crypto kit is a set of wrappers for third-party crypto libraries. It simplifies usage of crypto in TokenD-related projects by separating it's actual implementation.

## Cipher

Cipher module contains ciphers required for TokenD. Currently the only used cipher is `AES-256-GCM`.

Based on [Spongy Castle](https://rtyley.github.io/spongycastle/).

```groovy
allprojects {
    repositories {
        ...
        maven { url "https://maven.tokend.org" }
    }
}

dependencies {
    ...
    compile "org.tokend:crypto-cipher:1.0.2"
}
```
Usage example:
```kotlin
val DATA = "TokenD is awesome".toByteArray()
val KEY = Hex.decode("2e0c7a28545d4c53a1f4b9ef82245d7da853c7f0b0ae949040faedaa60c23c0b")
val IV = Base64.decode("dcDptDqlQv7tWIT2")

val encryptedData = Aes256GCM(IV).encrypt(DATA, KEY)
```

## EcDSA

EcDSA module contains elliptic curve cryptography used in TokenD. It provides signing on `Ed25519` curve with `SHA-256` hashing.

Based on [EdDSA-Java](https://github.com/str4d/ed25519-java).

```groovy
allprojects {
    repositories {
        ...
        maven { url "https://maven.tokend.org" }
    }
}

dependencies {
    ...
    compile "org.tokend:crypto-ecdsa:1.0.4"
}
```
Usage example:
```kotlin
val CURVE = Curves.ED25519_SHA512
val DATA = "TokenD is awesome".toByteArray()
val keyPair = EcDSAKeyPair.random(CURVE)
val signature = keyPair.sign(DATA)
keyPair.verify(DATA, signature)
```

## KDF

KDF module contains key derivation functions used in TokenD. It provides classical `scrypt` implementation and it's special modification used for [wallet ID and wallet key derivation](https://tokend.gitlab.io/docs/?http#wallet-id-derivation).

Based on [Spongy Castle](https://rtyley.github.io/spongycastle/).

```groovy
allprojects {
    repositories {
        ...
        maven { url "https://maven.tokend.org" }
    }
}

dependencies {
    ...
    compile "org.tokend:crypto-kdf:1.0.4"
}
```
Usage example:
```kotlin
val N = 4096
val R = 8
val P = 1
val KEY_LENGTH = 32
val LOGIN = "oleg@tokend.org".toByteArray()
val PASSPHRASE = "qwe123".toByteArray()
val SALT = Base64.decode("67ufG1N/Rf+j2ugDaXaopw==")

val walletId = ScryptWithMasterKeyDerivation(N, R, P, LOGIN, "WALLET_ID".toByteArray())
                .derive(PASSPHRASE, SALT, KEY_LENGTH)

val walletKey = ScryptWithMasterKeyDerivation(N, R, P, LOGIN, "WALLET_KEY".toByteArray())
                .derive(PASSPHRASE, SALT, KEY_LENGTH)
```
