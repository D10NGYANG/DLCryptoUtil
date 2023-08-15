package com.d10ng.crypto

import java.security.Key
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import kotlin.io.encoding.Base64.Default.decode
import kotlin.io.encoding.Base64.Default.encode
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * 生成RSA密钥对
 * @param keyFormat KeyFormat 密钥格式，默认PKCS1
 * @param keyLength Int 密钥长度，默认2048位，可以根据需要调整，建议2048及以上
 * @return Pair<String, String> 公钥和私钥
 */
@OptIn(ExperimentalEncodingApi::class)
actual fun generateRSAKeyPair(
    keyFormat: KeyFormat,
    keyLength: Int
): Pair<String, String> {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(keyLength)

    val keyPair = keyPairGenerator.generateKeyPair()

    return when (keyFormat) {
        KeyFormat.PKCS1 -> encode(keyPair.public.encoded) to encode(keyPair.private.encoded)
        KeyFormat.PKCS8 -> {
            val pkcs8PrivateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(PKCS8EncodedKeySpec(keyPair.private.encoded))
            encode(keyPair.public.encoded) to encode(pkcs8PrivateKey.encoded)
        }
    }
}

/**
 * 创建Cipher
 * @param rsaKey Key
 * @param encryptMode RSAEncryptMode
 * @param fillMode RSAFillMode
 * @param hashAlgorithm HashAlgorithm
 * @param mgfHashAlgorithm MGFHashAlgorithm
 * @param isEncrypt Boolean
 * @return Cipher
 */
@OptIn(ExperimentalEncodingApi::class)
private fun createCipher(
    rsaKey: Key,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?,
    isEncrypt: Boolean
): Cipher {
    val baseStr = buildString {
        append("RSA/${encryptMode.name}/${fillMode.name}")
        if (fillMode == RSAFillMode.OAEP) {
            append("With${hashAlgorithm?.text?: ""}And${mgfHashAlgorithm?.text?: ""}Padding")
        }
    }
    val cipher = Cipher.getInstance(baseStr)
    cipher.init(if (isEncrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, rsaKey)
    return cipher
}

/**
 * 获取公钥
 * @param keyStr String
 * @return PublicKey
 */
@OptIn(ExperimentalEncodingApi::class)
private fun getPublicKey(keyStr: String): PublicKey {
    var publicKey: PublicKey
    try {
        val keyFactory = KeyFactory.getInstance("RSA")
        publicKey = keyFactory.generatePublic(X509EncodedKeySpec(decode(keyStr)))
        println("public key format PKCS8")
    } catch (e: Exception) {
        try {
            val fullKey = "-----BEGIN RSA PUBLIC KEY-----\n${keyStr}\n-----END RSA PUBLIC KEY-----"
            val pemParser = PEMParser(fullKey.reader())
            val obj = pemParser.readObject() as SubjectPublicKeyInfo
            val rsa = PublicKeyFactory.createKey(obj) as RSAKeyParameters
            val rsaSpec = RSAPublicKeySpec(rsa.modulus, rsa.exponent)
            val keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider())
            publicKey = keyFactory.generatePublic(rsaSpec)
            println("public key format PKCS1")
        } catch (e: Exception) {
            e.printStackTrace()
            throw RuntimeException("public key format error")
        }
    }
    return publicKey
}

/**
 * 获取私钥
 * @param keyStr String
 * @return PrivateKey
 */
@OptIn(ExperimentalEncodingApi::class)
private fun getPrivateKey(keyStr: String): PrivateKey {
    val pemContent = decode(keyStr)
    var privateKey: PrivateKey
    val keyFactory = KeyFactory.getInstance("RSA")
    try {
        privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(pemContent))
        println("private key format PKCS8")
    } catch (e: Exception) {
        try {
            val asn1PrivateKey = RSAPrivateKey.getInstance(pemContent)
            val rsaPrivateKeySpec = RSAPrivateKeySpec(
                asn1PrivateKey.modulus,
                asn1PrivateKey.privateExponent
            )
            privateKey = keyFactory.generatePrivate(rsaPrivateKeySpec)
            println("private key format PKCS1")
        } catch (e: Exception) {
            e.printStackTrace()
            throw RuntimeException("private key format error")
        }
    }
    return privateKey
}

/**
 * # RSA公钥加密
 * > RSA加密解密算法支持三种填充模式，分别是NoPadding、OAEP、PKCS1Padding，RSA填充是为了和公钥等长。
 * - OAEP：最优非对称加密填充，英文为：Optimal Asymmetric Encryption Padding，是RSA加密和RSA解密最新最安全的推荐填充模式。当填充模式选择OAEP时，必须选择参数Hash和MGFHash。
 * - PKCS1Padding：随机填充数据模式，每次加密的结果都不一样，是RSA加密和RSA解密使用最为广泛的填充模式。当填充模式选择PKCS1Padding时，无须选择参数Hash和MGFHash。
 * - NoPadding：不填充模式，是RSA加密和RSA解密使用较少的填充模式。当填充模式选择NoPadding时，无须选择参数Hash和MGFHash。
 * @param data String 待加密数据
 * @param publicKey String 公钥
 * @param encryptMode RSAEncryptMode 加密模式，默认RSAEncryptMode.ECB
 * @param fillMode RSAFillMode 填充模式，默认RSAFillMode.PKCS1Padding
 * @param hashAlgorithm HashAlgorithm 哈希算法，默认null
 * @param mgfHashAlgorithm HashAlgorithm MGF哈希算法，默认null
 * @return String 加密后的数据
 */
@OptIn(ExperimentalEncodingApi::class)
actual fun rsaPublicEncrypt(
    data: String,
    publicKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String {
    val keyFactory = KeyFactory.getInstance("RSA")
    val rsaPublicKey = getPublicKey(publicKey)
    val cipher = createCipher(rsaPublicKey, encryptMode, fillMode, hashAlgorithm, mgfHashAlgorithm, true)
    val blockSize = keyFactory.getBlockSize(rsaPublicKey, true, fillMode)
    return encode(cipher.doLongFinal(data.toByteArray(), blockSize))
}

/**
 * # RSA私钥解密
 * > RSA加密解密算法支持三种填充模式，分别是NoPadding、OAEP、PKCS1Padding，RSA填充是为了和公钥等长。
 * - OAEP：最优非对称加密填充，英文为：Optimal Asymmetric Encryption Padding，是RSA加密和RSA解密最新最安全的推荐填充模式。当填充模式选择OAEP时，必须选择参数Hash和MGFHash。
 * - PKCS1Padding：随机填充数据模式，每次加密的结果都不一样，是RSA加密和RSA解密使用最为广泛的填充模式。当填充模式选择PKCS1Padding时，无须选择参数Hash和MGFHash。
 * - NoPadding：不填充模式，是RSA加密和RSA解密使用较少的填充模式。当填充模式选择NoPadding时，无须选择参数Hash和MGFHash。
 * @param data String 待解密数据
 * @param privateKey String 私钥
 * @param encryptMode RSAEncryptMode 加密模式，默认RSAEncryptMode.ECB
 * @param fillMode RSAFillMode 填充模式，默认RSAFillMode.PKCS1Padding
 * @param hashAlgorithm HashAlgorithm 哈希算法，默认null
 * @param mgfHashAlgorithm HashAlgorithm MGF哈希算法，默认null
 * @return String 解密后的数据
 */
@OptIn(ExperimentalEncodingApi::class)
actual fun rsaPrivateDecrypt(
    data: String,
    privateKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String {
    val keyFactory = KeyFactory.getInstance("RSA")
    val rsaPrivateKey = getPrivateKey(privateKey)
    val cipher = createCipher(rsaPrivateKey, encryptMode, fillMode, hashAlgorithm, mgfHashAlgorithm, false)
    val blockSize = keyFactory.getBlockSize(rsaPrivateKey, false, fillMode)
    return String(cipher.doLongFinal(decode(data), blockSize))
}

/**
 * RSA私钥加密
 * > OAEP填充模式下不支持
 * @param data String 待加密数据
 * @param privateKey String 私钥
 * @param encryptMode RSAEncryptMode 加密模式，默认RSAEncryptMode.ECB
 * @param fillMode RSAFillMode 填充模式，默认RSAFillMode.PKCS1Padding
 * @param hashAlgorithm HashAlgorithm 哈希算法，默认null
 * @param mgfHashAlgorithm HashAlgorithm MGF哈希算法，默认null
 * @return String 加密后的数据
 */
@OptIn(ExperimentalEncodingApi::class)
actual fun rsaPrivateEncrypt(
    data: String,
    privateKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String {
    val keyFactory = KeyFactory.getInstance("RSA")
    val rsaPrivateKey = getPrivateKey(privateKey)
    val cipher = createCipher(rsaPrivateKey, encryptMode, fillMode, hashAlgorithm, mgfHashAlgorithm, true)
    val blockSize = keyFactory.getBlockSize(rsaPrivateKey, true, fillMode)
    return encode(cipher.doLongFinal(data.toByteArray(), blockSize))
}

/**
 * RSA公钥解密
 * > OAEP填充模式下不支持
 * @param data String 待解密数据
 * @param publicKey String 公钥
 * @param encryptMode RSAEncryptMode 加密模式，默认RSAEncryptMode.ECB
 * @param fillMode RSAFillMode 填充模式，默认RSAFillMode.PKCS1Padding
 * @param hashAlgorithm HashAlgorithm 哈希算法，默认null
 * @param mgfHashAlgorithm HashAlgorithm MGF哈希算法，默认null
 * @return String 解密后的数据
 */
@OptIn(ExperimentalEncodingApi::class)
actual fun rsaPublicDecrypt(
    data: String,
    publicKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String {
    val keyFactory = KeyFactory.getInstance("RSA")
    val rsaPublicKey = getPublicKey(publicKey)
    val cipher = createCipher(rsaPublicKey, encryptMode, fillMode, hashAlgorithm, mgfHashAlgorithm, false)
    val blockSize = keyFactory.getBlockSize(rsaPublicKey, false, fillMode)
    return String(cipher.doLongFinal(decode(data), blockSize))
}

/**
 * 获取分包大小
 * @receiver KeyFactory
 * @param key Key
 * @param fillMode RSAFillMode
 * @return Int
 */
private fun KeyFactory.getBlockSize(key: Key, isEncrypt: Boolean, fillMode: RSAFillMode): Int {
    var keepSize = when (fillMode) {
        RSAFillMode.PKCS1Padding -> 11
        RSAFillMode.OAEP -> 66
        else -> 0
    }
    if (!isEncrypt) {
        keepSize = 0
    }

    return if (key is RSAPublicKey) {
        (getKeySpec(key, RSAPublicKeySpec::class.java).modulus.bitLength() + 7) / 8 - keepSize
    } else {
        (getKeySpec(key, RSAPrivateKeySpec::class.java).modulus.bitLength() + 7) / 8 - keepSize
    }
}

/**
 * 分包处理加密解密
 * @receiver Cipher
 * @param data ByteArray
 * @param blockSize Int
 * @return ByteArray
 */
private fun Cipher.doLongFinal(data: ByteArray, blockSize: Int): ByteArray {
    var offset = 0
    val blocks = mutableListOf<ByteArray>()

    while (offset < data.size) {
        val blockEnd = minOf(offset + blockSize, data.size)
        val block = doFinal(data, offset, blockEnd - offset)
        blocks.add(block)
        offset += blockSize
    }
    return blocks.reduce { acc, bytes -> acc + bytes }
}