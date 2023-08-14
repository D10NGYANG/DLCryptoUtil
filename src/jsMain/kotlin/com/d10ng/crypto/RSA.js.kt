package com.d10ng.crypto

import com.d10ng.crypto.thirdParties.NodeForge

/**
 * 生成RSA密钥对
 * @param keyFormat KeyFormat 密钥格式，默认PKCS1
 * @param keyLength Int 密钥长度，默认2048位，可以根据需要调整，建议2048及以上
 * @return Pair<String, String> 公钥和私钥
 */
actual fun generateRSAKeyPair(
    keyFormat: KeyFormat,
    keyLength: Int
): Pair<String, String> {
    val rsa = NodeForge.pki.rsa
    val keyPair = rsa.generateKeyPair(keyLength)
    var publicKey = NodeForge.pki.publicKeyToPem(keyPair.publicKey)
    var privateKey = NodeForge.pki.privateKeyToPem(keyPair.privateKey)
    if (keyFormat == KeyFormat.PKCS8) {
        val privateKeyInfo = NodeForge.pki.wrapRsaPrivateKey(NodeForge.pki.privateKeyToAsn1(keyPair.privateKey))
        privateKey = NodeForge.pki.privateKeyInfoToPem(privateKeyInfo)
    }
    // 将key的换行符去除，并且删除头尾的公钥和私钥标识
    val delTagFunc: (String) -> String = { str ->
        str.replace(Regex("[\\r\\n]"), "").replace(Regex("(-+)(([^\\s-]*(\\s)){2,3}[^\\s-]*)(-+)"), "")
    }
    publicKey = delTagFunc(publicKey)
    privateKey = delTagFunc(privateKey)
    return publicKey to privateKey
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
actual fun rsaPublicEncrypt(
    data: String,
    publicKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String {
    // 对公钥进行补全
    val publicKeyFull = "-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----"
    val publicKeyParse = NodeForge.pki.publicKeyFromPem(publicKeyFull)
    val fillModeStr = when(fillMode) {
        RSAFillMode.PKCS1Padding -> "RSAES-PKCS1-V1_5"
        RSAFillMode.OAEP -> "RSA-OAEP"
        RSAFillMode.NoPadding -> "RSAES-PKCS1-V1_5"
    }
    val option = when(fillMode) {
        RSAFillMode.PKCS1Padding -> null
        RSAFillMode.OAEP -> {
            val hashAlgorithmMd = when(hashAlgorithm) {
                HashAlgorithm.SHA1 -> NodeForge.md.sha1.create()
                HashAlgorithm.SHA256 -> NodeForge.md.sha256.create()
                else -> null
            }
            val mgfHashAlgorithmMd = when(mgfHashAlgorithm) {
                MGFHashAlgorithm.SHA1 -> NodeForge.md.sha1.create()
                else -> null
            }
            js("{md: hashAlgorithmMd, mgf1: { md: mgfHashAlgorithmMd }}")
        }
        RSAFillMode.NoPadding -> null
    }
    val buffer = NodeForge.util.createBuffer()
    buffer.data = NodeForge.util.encodeUtf8(data)
    val blockSize = getBlockSize(publicKey, true, true, fillMode)
    val encrypted = doLongFinal(buffer.bytes(), blockSize) { str -> publicKeyParse.encrypt(str, fillModeStr, option) }
    return NodeForge.util.encode64(encrypted)
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
actual fun rsaPrivateDecrypt(
    data: String,
    privateKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String {
    // 对私钥进行补全
    val privateKeyFull = "-----BEGIN RSA PRIVATE KEY-----\n${privateKey}\n-----END RSA PRIVATE KEY-----"
    val privateKeyParse = NodeForge.pki.privateKeyFromPem(privateKeyFull)
    val fillModeStr = when(fillMode) {
        RSAFillMode.PKCS1Padding -> "RSAES-PKCS1-V1_5"
        RSAFillMode.OAEP -> "RSA-OAEP"
        RSAFillMode.NoPadding -> "RSAES-PKCS1-V1_5"
    }
    val option = when(fillMode) {
        RSAFillMode.PKCS1Padding -> null
        RSAFillMode.OAEP -> {
            val hashAlgorithmMd = when(hashAlgorithm) {
                HashAlgorithm.SHA1 -> NodeForge.md.sha1.create()
                HashAlgorithm.SHA256 -> NodeForge.md.sha256.create()
                else -> null
            }
            val mgfHashAlgorithmMd = when(mgfHashAlgorithm) {
                MGFHashAlgorithm.SHA1 -> NodeForge.md.sha1.create()
                else -> null
            }
            js("{md: hashAlgorithmMd, mgf1: { md: mgfHashAlgorithmMd }}")
        }
        RSAFillMode.NoPadding -> null
    }
    val blockSize = getBlockSize(privateKey, false, false, fillMode)
    return NodeForge.util.decodeUtf8(doLongFinal(NodeForge.util.decode64(data), blockSize) { str -> privateKeyParse.decrypt(str, fillModeStr, option) })
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
actual fun rsaPrivateEncrypt(
    data: String,
    privateKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String {
    TODO("Not yet implemented")
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
actual fun rsaPublicDecrypt(
    data: String,
    publicKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String {
    TODO("Not yet implemented")
}

/**
 * 获取分包大小
 * @param key String
 * @param isPublicKey Boolean
 * @param isEncrypt Boolean
 * @param fillMode RSAFillMode
 * @return Int
 */
private fun getBlockSize(key: String, isPublicKey: Boolean, isEncrypt: Boolean, fillMode: RSAFillMode): Int {
    var keepSize = when (fillMode) {
        RSAFillMode.PKCS1Padding -> 11
        RSAFillMode.OAEP -> 66
        else -> 0
    }
    if (!isEncrypt) {
        keepSize = 0
    }
    val keyBytes = NodeForge.util.decode64(key)
    val keyDer = NodeForge.asn1.fromDer(keyBytes)
    val bitLength =  if (isPublicKey) {
        NodeForge.pki.publicKeyFromAsn1(keyDer).n.bitLength()
    } else {
        NodeForge.pki.privateKeyFromAsn1(keyDer).n.bitLength()
    }
    return (bitLength + 7) / 8 - keepSize
}

/**
 * 分包处理加密解密
 * @param data String
 * @param blockSize Int
 * @param handle Function1<String, String>
 * @return String
 */
private fun doLongFinal(data: String, blockSize: Int, handle: (String) -> String): String {
    var offset = 0
    val blocks = mutableListOf<String>()

    while (offset < data.length) {
        val blockEnd = minOf(offset + blockSize, data.length)
        val part = data.substring(offset, blockEnd)
        val block = handle(part)
        blocks.add(block)
        offset += blockSize
    }
    return blocks.joinToString("")
}