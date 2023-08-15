package com.d10ng.crypto

import kotlin.io.encoding.ExperimentalEncodingApi

// 密钥格式
enum class KeyFormat {
    PKCS1, PKCS8
}
// 填充模式
enum class RSAFillMode {
    NoPadding, OAEP, PKCS1Padding
}
// 加密模式
enum class RSAEncryptMode {
    NONE, ECB
}
// 哈希算法
enum class HashAlgorithm(val text: String) {
    SHA1("SHA-1"), SHA256("SHA-256")
}
// MGF哈希算法
enum class MGFHashAlgorithm(val text: String) {
    SHA1("MGF1")
}

/**
 * 生成RSA密钥对
 * @param keyFormat KeyFormat 密钥格式，默认PKCS1
 * @param keyLength Int 密钥长度，默认2048位，可以根据需要调整，建议2048及以上
 * @return Pair<String, String> 公钥和私钥
 */
expect fun generateRSAKeyPair(keyFormat: KeyFormat = KeyFormat.PKCS1, keyLength: Int = 2048): Pair<String, String>


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
expect fun rsaPublicEncrypt(
    data: String,
    publicKey: String,
    encryptMode: RSAEncryptMode = RSAEncryptMode.ECB,
    fillMode: RSAFillMode = RSAFillMode.PKCS1Padding,
    hashAlgorithm: HashAlgorithm? = null,
    mgfHashAlgorithm: MGFHashAlgorithm? = null
): String

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
expect fun rsaPrivateDecrypt(
    data: String,
    privateKey: String,
    encryptMode: RSAEncryptMode = RSAEncryptMode.ECB,
    fillMode: RSAFillMode = RSAFillMode.PKCS1Padding,
    hashAlgorithm: HashAlgorithm? = null,
    mgfHashAlgorithm: MGFHashAlgorithm? = null
): String