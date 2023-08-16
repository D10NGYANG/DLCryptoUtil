package com.d10ng.crypto.test

import com.d10ng.crypto.*
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Security
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64.Default.encode
import kotlin.io.encoding.ExperimentalEncodingApi


class Test {

    @Test
    fun test() {
        // 生成密钥对
        val keyPair = generateRSAKeyPair(KeyFormat.PKCS1)
        println("Public Key: ${keyPair[0]}")
        println("Private Key: ${keyPair[1]}")

        val pkcs8KeyPair = generateRSAKeyPair(KeyFormat.PKCS8)
        println("Public Key (PKCS8): ${pkcs8KeyPair[0]}")
        println("Private Key (PKCS8): ${pkcs8KeyPair[1]}")

        getPublicKey(keyPair[0])
        getPrivateKey(keyPair[1])

        getPublicKey(pkcs8KeyPair[0])
        getPrivateKey(pkcs8KeyPair[1])
    }

    @Test
    fun test1() {
        val encryptContent = "Qg+vdIbdUsLPWnZ95EA/N+DVqOpS5UD6STrM7VtYwdYa53aZZgJgB+Obo1oDwc2kNeLOo7AnwPzb38teE6EC5zsdmw6w/KfOhMknYiZWzBQtziUpugHi90+RtxDtjSAKPzjZy5j5A516IWDpza/qV7XmE4DVxSwfKJTGrfjea0IQ57FnZfI1bWt/PiC2hoty2OgGQ63HLlPgtoVncphjkyl7mEaIeToXtuyHvCsEC/CoKMw/bmlz1nhbsqS5kutl20rNxSmfXYIZMZv3FGkzC6aGaQNFs+AlzeNLs8kWONbDUTunbq29xUK39k0laRc7mqo3g4U8mvp8lxafWIn4/A=="
        val key = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANCA/yhtSvdT7g+cZGNPxPDot5OxbqePGk1G5ynwo76BGbRvrLDmx5qDvw89+fSJww/a3OhS6CdyXi0L6a5lZyquYH6gDoyufWSU7/k5Ivw7MxXMG2VsepYtKJlZEp1DjwzEzdVMH/XCwjS1qADGD2QOMcUfAeLcXk/fdsBko24NAgMBAAECgYAsxQYEsDMAmEztnS8RA/fNoqqIU/jmkZucLDVGlB0UsrPKQpBaC7OgQdmsdCpPj6UKqnv0hpjCn5QJKB2tDKjx5ZyNd3vsrHwO+veIo2avk7ANAmjDH7XuM0Me11hkBLN0PqyErFoOuDn8JCQ7vfK3sKJRlqpXGs3cEZCL2jjhIQJBAPt9rpHgVDwc0RFm0VKwsug4QSj8PhCB7DI4amNg63zHqRAKOLf2/0+Ehb5BRsJ9iDG0HVp3jqs8vuiYp2Dksu8CQQDUPgIxOs58/Pc5e/3um9sb+TeOyXopTiHhlzjPuQ4+20+VUG5INnEYtDeDsT5pw9Ix4njjCB0V00mpW5kJev7DAkEA1ZHi+QDfp/j01ulQ4/8ov6peM5cagdxDoFZmiqSY9ut7uCJmDlxUbsvk5C/9DleanFMQBm63mtXIbjCNG+y7wwJBALA1EwjgM9KdCnvVL0tMZirhS3jmWN+2GHb8X5RFpUgWOApVDloxqM/Dv1s8af7RLs9voMGMWOln034hp/qw/JUCQQCzCG3OR3vSwtiVWBP3LrtW282a1eZGyIC4d88Jeq2EHpuruS8vdWAmusdfRCnw2GJJ+w7sJXtpxIQwsNTN0ev6"
        // 测试私钥解密
        val decryptContent = rsaPrivateDecrypt(encryptContent, key, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding, HashAlgorithm.SHA256, MGFHashAlgorithm.SHA1)
        println("Decrypt Content: $decryptContent")
    }

    @Test
    fun test2() {
        // 生成PKCS1密钥对

        // 生成2048位RSA密钥对
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()

        // 获取私钥和公钥
        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded

        val spkInfo = SubjectPublicKeyInfo.getInstance(publicKeyBytes)
        val primitive = spkInfo.parsePublicKey()
        val publicKeyPKCS1 = primitive.getEncoded()

        val pkInfo = PrivateKeyInfo.getInstance(privateKeyBytes)
        val encodable = pkInfo.parsePrivateKey()
        val privateKeyPrimitive = encodable.toASN1Primitive()
        val privateKeyPKCS1 = privateKeyPrimitive.getEncoded()

        // 打印私钥和公钥的Base64编码字符串
        val privateKeyString = Base64.getEncoder().encodeToString(privateKeyPKCS1)
        val publicKeyString = Base64.getEncoder().encodeToString(publicKeyPKCS1)

        println("Private Key (PKCS#1):\n$privateKeyString")
        println("\nPublic Key (PKCS#1):\n$publicKeyString")

        getPublicKey(publicKeyString)
        getPrivateKey(privateKeyString)
    }

    @Test
    fun test3() {
        val key = "MIGJAoGBANAapBMEK3oveAJ01Mkky5tarFnErNFQ35tyesHslj8svArfHhiJAugrwYfQSuWtFjc/PzQfM6E2b9f3ThFWGjebnNMn5iKOduuluMDRtzIAKyumfXises8HfNhjJKVZ4/uyNEC4qGRZuZ6UM5imqJqI0TaCiQ52a9vBnW8uYfnvAgMBAAE="
        getPublicKey(key)
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun test4() {
        Security.addProvider(BouncyCastleProvider())
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        val byteArray = "1234567812345678".toByteArray(Charsets.UTF_8)
        val keySpec = SecretKeySpec(byteArray, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec("8765432187654321".toByteArray(Charsets.UTF_8)))
        val content = "1qaz2wsx"
        val encrypted = cipher.doFinal(content.toByteArray(Charsets.UTF_8))
        println("Encrypted: ${encode(encrypted)}")
    }
}