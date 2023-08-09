package com.d10ng.crypto.thirdParties

@JsModule("node-forge")
@JsNonModule
external class NodeForge {
    class pki {
        companion object {
            fun publicKeyToPem(key: rsa.PublicKey): String
            fun privateKeyToPem(key: rsa.PrivateKey): String
            fun privateKeyToAsn1(privateKey: rsa.PrivateKey): asn1.Asn1
            fun privateKeyInfoToPem(privateKey: asn1.Asn1): String
            fun wrapRsaPrivateKey(privateKey: asn1.Asn1): asn1.Asn1
        }
        class asn1 {
            class Asn1 {}
        }
        class rsa {
            class KeyPair {
                val publicKey: PublicKey
                val privateKey: PrivateKey
            }

            class PublicKey {
                fun encrypt(bytes: ByteArray): ByteArray
            }

            class PrivateKey {
                var n: Long
                var e: Long
                fun decrypt(bytes: ByteArray): ByteArray
            }

            companion object {
                fun generateKeyPair(
                    bits: Int
                ): KeyPair
            }
        }
    }
}