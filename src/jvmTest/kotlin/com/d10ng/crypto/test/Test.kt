package com.d10ng.crypto.test

import com.d10ng.crypto.*
import org.junit.Test
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateCrtKeySpec
import kotlin.io.encoding.Base64.Default.decode
import kotlin.io.encoding.ExperimentalEncodingApi


class Test {

    @Test
    fun test() {
        // 生成密钥对
        val keyPair = generateRSAKeyPair(KeyFormat.PKCS1)
        println("Public Key: ${keyPair.first}")
        println("Private Key: ${keyPair.second}")

        val pkcs8KeyPair = generateRSAKeyPair(KeyFormat.PKCS8)
        println("Public Key (PKCS8): ${pkcs8KeyPair.first}")
        println("Private Key (PKCS8): ${pkcs8KeyPair.second}")

        // 测试公钥加密
        val content = "1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv"
        val encryptContent = rsaPublicEncrypt(content, keyPair.first, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding)
        println("Encrypt Content: $encryptContent")

        // 测试私钥解密
        val decryptContent = rsaPrivateDecrypt(encryptContent, keyPair.second, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding)
        assert(content == decryptContent)

        // 测试私钥加密
        val encryptContent2 = rsaPrivateEncrypt(content, keyPair.second, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding)
        println("Encrypt Content: $encryptContent2")

        // 测试公钥解密
        val decryptContent2 = rsaPublicDecrypt(encryptContent2, keyPair.first, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding)
        assert(content == decryptContent2)
    }

    @Test
    fun test1() {
        val encryptContent = "Qg+vdIbdUsLPWnZ95EA/N+DVqOpS5UD6STrM7VtYwdYa53aZZgJgB+Obo1oDwc2kNeLOo7AnwPzb38teE6EC5zsdmw6w/KfOhMknYiZWzBQtziUpugHi90+RtxDtjSAKPzjZy5j5A516IWDpza/qV7XmE4DVxSwfKJTGrfjea0IQ57FnZfI1bWt/PiC2hoty2OgGQ63HLlPgtoVncphjkyl7mEaIeToXtuyHvCsEC/CoKMw/bmlz1nhbsqS5kutl20rNxSmfXYIZMZv3FGkzC6aGaQNFs+AlzeNLs8kWONbDUTunbq29xUK39k0laRc7mqo3g4U8mvp8lxafWIn4/A=="
        val key = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANCA/yhtSvdT7g+cZGNPxPDot5OxbqePGk1G5ynwo76BGbRvrLDmx5qDvw89+fSJww/a3OhS6CdyXi0L6a5lZyquYH6gDoyufWSU7/k5Ivw7MxXMG2VsepYtKJlZEp1DjwzEzdVMH/XCwjS1qADGD2QOMcUfAeLcXk/fdsBko24NAgMBAAECgYAsxQYEsDMAmEztnS8RA/fNoqqIU/jmkZucLDVGlB0UsrPKQpBaC7OgQdmsdCpPj6UKqnv0hpjCn5QJKB2tDKjx5ZyNd3vsrHwO+veIo2avk7ANAmjDH7XuM0Me11hkBLN0PqyErFoOuDn8JCQ7vfK3sKJRlqpXGs3cEZCL2jjhIQJBAPt9rpHgVDwc0RFm0VKwsug4QSj8PhCB7DI4amNg63zHqRAKOLf2/0+Ehb5BRsJ9iDG0HVp3jqs8vuiYp2Dksu8CQQDUPgIxOs58/Pc5e/3um9sb+TeOyXopTiHhlzjPuQ4+20+VUG5INnEYtDeDsT5pw9Ix4njjCB0V00mpW5kJev7DAkEA1ZHi+QDfp/j01ulQ4/8ov6peM5cagdxDoFZmiqSY9ut7uCJmDlxUbsvk5C/9DleanFMQBm63mtXIbjCNG+y7wwJBALA1EwjgM9KdCnvVL0tMZirhS3jmWN+2GHb8X5RFpUgWOApVDloxqM/Dv1s8af7RLs9voMGMWOln034hp/qw/JUCQQCzCG3OR3vSwtiVWBP3LrtW282a1eZGyIC4d88Jeq2EHpuruS8vdWAmusdfRCnw2GJJ+w7sJXtpxIQwsNTN0ev6"
        // 测试私钥解密
        val decryptContent = rsaPrivateDecrypt(encryptContent, key, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding, HashAlgorithm.SHA256, MGFHashAlgorithm.SHA1)
        println("Decrypt Content: $decryptContent")
    }
}