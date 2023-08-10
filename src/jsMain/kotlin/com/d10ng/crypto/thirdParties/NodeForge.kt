package com.d10ng.crypto.thirdParties

@JsModule("node-forge")
@JsNonModule
external object NodeForge {

    object jsbn {
        class BigInteger {
            fun bitLength(): Int
        }
    }

    object asn1 {
        fun fromDer(bytes: String): Asn1
        class Asn1 {}
    }

    object pki {
        fun publicKeyToPem(key: rsa.PublicKey): String
        fun privateKeyToPem(key: rsa.PrivateKey): String
        fun privateKeyToAsn1(privateKey: rsa.PrivateKey): asn1.Asn1
        fun privateKeyInfoToPem(privateKey: asn1.Asn1): String
        fun wrapRsaPrivateKey(privateKey: asn1.Asn1): asn1.Asn1
        fun publicKeyFromPem(pem: String): rsa.PublicKey
        fun publicKeyFromAsn1(publicKey: asn1.Asn1): rsa.PublicKey
        fun privateKeyFromAsn1(privateKey: asn1.Asn1): rsa.PrivateKey

        object rsa {
            fun generateKeyPair(bits: Int): KeyPair
            class PublicKey {
                var n: jsbn.BigInteger
                var e: jsbn.BigInteger
                fun encrypt(data: String, scheme: String?, schemeOptions: Any?): String
            }

            class PrivateKey {
                var n: jsbn.BigInteger
                var e: jsbn.BigInteger
                fun decrypt(bytes: ByteArray): ByteArray
            }

            class KeyPair {
                val publicKey: PublicKey
                val privateKey: PrivateKey
            }
        }
    }
    object md {

        object sha1 {
            class MessageDigest: md.MessageDigest {}
            fun create(): MessageDigest
        }
        object sha256 {
            class MessageDigest: md.MessageDigest {}
            fun create(): MessageDigest
        }
        object sha512 {
            class MessageDigest: md.MessageDigest {}
            fun create(): MessageDigest
        }
        open class MessageDigest {
            var algorithm: String
        }
    }

    object util {
        fun encode64(bytes: String): String
        fun decode64(encoded: String): String
    }
}