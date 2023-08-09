package com.d10ng.crypto

import java.security.Key
import java.security.KeyFactory
import java.security.KeyPairGenerator
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
 * @param keyFormat KeyFormat 密钥格式
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
 * RSA公钥加密
 * @param data String 待加密数据
 * @param publicKey String 公钥
 * @param encryptMode RSAEncryptMode 加密模式，默认RSAEncryptMode.ECB
 * @param fillMode RSAFillMode 填充模式，默认RSAFillMode.OAEP
 * @param hashAlgorithm HashAlgorithm 哈希算法，默认HashAlgorithm.SHA256
 * @param mgfHashAlgorithm HashAlgorithm MGF哈希算法，默认HashAlgorithm.SHA1
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
    val rsaPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(decode(publicKey)))
    val cipher = createCipher(rsaPublicKey, encryptMode, fillMode, hashAlgorithm, mgfHashAlgorithm, true)
    val blockSize = keyFactory.getBlockSize(rsaPublicKey, true, fillMode)
    return encode(cipher.doLongFinal(data.toByteArray(), blockSize))
}

/**
 * RSA私钥解密
 * @param data String 待解密数据
 * @param privateKey String 私钥
 * @param encryptMode RSAEncryptMode 加密模式，默认RSAEncryptMode.ECB
 * @param fillMode RSAFillMode 填充模式，默认RSAFillMode.OAEP
 * @param hashAlgorithm HashAlgorithm 哈希算法，默认HashAlgorithm.SHA256
 * @param mgfHashAlgorithm HashAlgorithm MGF哈希算法，默认HashAlgorithm.SHA1
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
    val rsaPrivateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(decode(privateKey)))
    val cipher = createCipher(rsaPrivateKey, encryptMode, fillMode, hashAlgorithm, mgfHashAlgorithm, false)
    val blockSize = keyFactory.getBlockSize(rsaPrivateKey, false, fillMode)
    return String(cipher.doLongFinal(decode(data), blockSize))
}

/**
 * RSA私钥加密
 * @param data String 待加密数据
 * @param privateKey String 私钥
 * @param encryptMode RSAEncryptMode 加密模式，默认RSAEncryptMode.ECB
 * @param fillMode RSAFillMode 填充模式，默认RSAFillMode.OAEP
 * @param hashAlgorithm HashAlgorithm 哈希算法，默认HashAlgorithm.SHA256
 * @param mgfHashAlgorithm HashAlgorithm MGF哈希算法，默认HashAlgorithm.SHA1
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
    val rsaPrivateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(decode(privateKey)))
    val cipher = createCipher(rsaPrivateKey, encryptMode, fillMode, hashAlgorithm, mgfHashAlgorithm, true)
    val blockSize = keyFactory.getBlockSize(rsaPrivateKey, true, fillMode)
    return encode(cipher.doLongFinal(data.toByteArray(), blockSize))
}

/**
 * RSA公钥解密
 * @param data String 待解密数据
 * @param publicKey String 公钥
 * @param encryptMode RSAEncryptMode 加密模式，默认RSAEncryptMode.ECB
 * @param fillMode RSAFillMode 填充模式，默认RSAFillMode.OAEP
 * @param hashAlgorithm HashAlgorithm 哈希算法，默认HashAlgorithm.SHA256
 * @param mgfHashAlgorithm HashAlgorithm MGF哈希算法，默认HashAlgorithm.SHA1
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
    val rsaPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(decode(publicKey)))
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