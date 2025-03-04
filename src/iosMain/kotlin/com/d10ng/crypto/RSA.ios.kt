package com.d10ng.crypto

import platform.Foundation.*
import platform.Security.*
import platform.CoreFoundation.*
import kotlinx.cinterop.*
import platform.darwin.UInt8Var

/**
 * 生成RSA密钥对
 * @param keyFormat KeyFormat 密钥格式，默认PKCS1
 * @param keyLength Int 密钥长度，默认2048位，可以根据需要调整，建议2048及以上
 * @return Array<String> 公钥和私钥
 */
@OptIn(ExperimentalForeignApi::class)
actual fun generateRSAKeyPair(
    keyFormat: KeyFormat,
    keyLength: Int
): Array<String> = memScoped {
    // 创建密钥对生成参数
    val attributes = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        2L,
        null,
        null
    )
    CFDictionaryAddValue(
        attributes,
        kSecAttrKeyType as CFTypeRef,
        kSecAttrKeyTypeRSA
    )
    CFDictionaryAddValue(
        attributes,
        kSecAttrKeySizeInBits as CFTypeRef,
        CFNumberCreate(null, kCFNumberSInt32Type, alloc<IntVar>().apply { value = keyLength }.ptr)
    )
    
    // 生成密钥对
    val keyPair = SecKeyCreateRandomKey(attributes, null) ?:
        throw RuntimeException("密钥生成失败")
    
    // 获取公钥和私钥
    val publicKey = SecKeyCopyPublicKey(keyPair) ?: 
        throw RuntimeException("获取公钥失败")
    
    // 转换为数据
    val publicKeyData = SecKeyCopyExternalRepresentation(publicKey, null)?.toNSData() ?:
        throw RuntimeException("公钥数据转换失败")
    val privateKeyData = SecKeyCopyExternalRepresentation(keyPair, null)?.toNSData() ?:
        throw RuntimeException("私钥数据转换失败")
    
    // 根据密钥格式转换
    val publicKeyString = when (keyFormat) {
        KeyFormat.PKCS1 -> convertToPKCS1PublicKey(publicKeyData)
        KeyFormat.PKCS8 -> convertToPKCS8PublicKey(publicKeyData)
    }
    
    val privateKeyString = when (keyFormat) {
        KeyFormat.PKCS1 -> convertToPKCS1PrivateKey(privateKeyData)
        KeyFormat.PKCS8 -> convertToPKCS8PrivateKey(privateKeyData)
    }
    
    arrayOf(publicKeyString, privateKeyString)
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
@OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)
actual fun rsaPublicEncrypt(
    data: String,
    publicKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String = memScoped {
    // 去除PEM头尾和换行符
    val cleanedPublicKey = cleanPEMKey(publicKey)
    
    // Base64解码公钥
    val keyData = NSData.create(base64EncodedString = cleanedPublicKey, options = 0u) ?:
        throw RuntimeException("无效的Base64字符串")
    
    // 创建SecKey对象
    val keyDict = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        4L,
        null,
        null
    )
    CFDictionaryAddValue(
        keyDict,
        kSecAttrKeyType as CFTypeRef,
        kSecAttrKeyTypeRSA
    )
    CFDictionaryAddValue(
        keyDict,
        kSecAttrKeyClass as CFTypeRef,
        kSecAttrKeyClassPublic
    )
    CFDictionaryAddValue(
        keyDict,
        kSecAttrKeySizeInBits as CFTypeRef,
        CFNumberCreate(null, kCFNumberSInt32Type, alloc<IntVar>().apply { value = (keyData.length * 8u).toInt() }.ptr)
    )
    CFDictionaryAddValue(
        keyDict,
        kSecReturnPersistentRef as CFTypeRef,
        kCFBooleanTrue
    )

    val secKey = SecKeyCreateWithData(keyData.toCFDataRef(), keyDict, null) ?:
        throw RuntimeException("密钥创建失败")
    
    // 准备加密算法
    val algorithm = getSecKeyAlgorithm(fillMode, hashAlgorithm)
    
    // 确保算法支持此密钥
    if (!SecKeyIsAlgorithmSupported(secKey, kSecKeyOperationTypeEncrypt, algorithm)) {
        throw RuntimeException("不支持的加密配置")
    }
    
    // 计算每个块的最大加密大小
    val blockSize = calculateEncryptionBlockSize(secKey, fillMode, hashAlgorithm)
    
    // 将输入数据转换为UTF-8编码
    val inputData = data.encodeToByteArray()
    
    // 分块加密
    val encryptedBlocks = mutableListOf<String>()
    
    var currentIndex = 0
    while (currentIndex < inputData.size) {
        // 计算当前块的大小
        val chunkSize = minOf(blockSize, inputData.size - currentIndex)
        val endIndex = currentIndex + chunkSize
        
        // 提取当前块的数据
        val chunk = inputData.slice(currentIndex until endIndex).toByteArray()
        val chunkData = chunk.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = chunk.size.toULong())
        }
        
        // 加密当前块
        val encryptedData = SecKeyCreateEncryptedData(secKey, algorithm, chunkData.toCFDataRef(), null)?.toNSData() ?:
            throw RuntimeException("加密失败")
        
        // 将加密后的块转换为Base64并添加到结果列表
        val encryptedChunk = encryptedData.base64EncodedStringWithOptions(0u)
        encryptedBlocks.add(encryptedChunk)
        
        // 移动到下一块
        currentIndex = endIndex
    }
    
    // 将所有加密块连接起来，以 | 分隔
    encryptedBlocks.joinToString("|")
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
@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual fun rsaPrivateDecrypt(
    data: String,
    privateKey: String,
    encryptMode: RSAEncryptMode,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?,
    mgfHashAlgorithm: MGFHashAlgorithm?
): String = memScoped {
    // 去除PEM头尾和换行符
    val cleanedPrivateKey = cleanPEMKey(privateKey)
    
    // Base64解码私钥
    val keyData = NSData.create(base64EncodedString = cleanedPrivateKey, options = 0u) ?:
        throw RuntimeException("无效的Base64字符串")
    
    // 创建SecKey对象
    val keyDict = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        3L,
        null,
        null
    )
    CFDictionaryAddValue(
        keyDict,
        kSecAttrKeyType as CFTypeRef,
        kSecAttrKeyTypeRSA
    )
    CFDictionaryAddValue(
        keyDict,
        kSecAttrKeyClass as CFTypeRef,
        kSecAttrKeyClassPrivate
    )
    CFDictionaryAddValue(
        keyDict,
        kSecReturnPersistentRef as CFTypeRef,
        kCFBooleanTrue
    )

    val secKey = SecKeyCreateWithData(keyData.toCFDataRef(), keyDict, null) ?:
        throw RuntimeException("密钥创建失败")
    
    // 准备解密算法
    val algorithm = getSecKeyAlgorithm(fillMode, hashAlgorithm)
    
    // 确保算法支持此密钥
    if (!SecKeyIsAlgorithmSupported(secKey, kSecKeyOperationTypeDecrypt, algorithm)) {
        throw RuntimeException("不支持的解密配置")
    }
    
    // 分割加密数据块
    val encryptedBlocks = data.split("|")
    
    // 解密每个块
    val decryptedData = NSMutableData()
    
    for (block in encryptedBlocks) {
        // Base64解码当前块
        val blockData = NSData.create(base64EncodedString = block, options = 0u) ?:
            throw RuntimeException("无效的Base64加密块")
        
        // 解密当前块
        val decryptedBlock = SecKeyCreateDecryptedData(secKey, algorithm, blockData.toCFDataRef(), null)?.toNSData() ?:
            throw RuntimeException("解密失败")
        
        // 将解密后的块添加到结果中
        decryptedData.appendData(decryptedBlock)
    }
    
    // 将解密后的数据转换为字符串
    val length = decryptedData.length.toInt()
    val buffer = ByteArray(length)
    buffer.usePinned { pinned ->
        decryptedData.getBytes(pinned.addressOf(0), length.toULong())
    }
    buffer.decodeToString()
}

// 辅助函数：清理PEM密钥中的头尾和换行符
private fun cleanPEMKey(key: String): String {
    return key
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("-----BEGIN RSA PUBLIC KEY-----", "")
        .replace("-----END RSA PUBLIC KEY-----", "")
        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace(" ", "")
}

// 辅助函数：计算加密块大小
@OptIn(ExperimentalForeignApi::class)
private fun calculateEncryptionBlockSize(
    secKey: SecKeyRef,
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?
): Int {
    val keySize = SecKeyGetBlockSize(secKey)
    
    return (when (fillMode) {
        RSAFillMode.NoPadding -> keySize
        RSAFillMode.PKCS1Padding -> keySize - 11u
        RSAFillMode.OAEP -> {
            requireNotNull(hashAlgorithm) { "OAEP模式需要指定哈希算法" }
            val hashSize = when (hashAlgorithm) {
                HashAlgorithm.SHA1 -> 20 // SHA-1哈希长度为20字节
                HashAlgorithm.SHA256 -> 32 // SHA-256哈希长度为32字节
            }
            keySize - ((2 * hashSize + 2).toUInt())
        }
    }).toInt()
}

// 辅助函数：获取加密算法
@OptIn(ExperimentalForeignApi::class)
private fun getSecKeyAlgorithm(
    fillMode: RSAFillMode,
    hashAlgorithm: HashAlgorithm?
): SecKeyAlgorithm? {
    return when (fillMode) {
        RSAFillMode.PKCS1Padding -> kSecKeyAlgorithmRSAEncryptionPKCS1
        RSAFillMode.OAEP -> {
            requireNotNull(hashAlgorithm) { "OAEP模式需要指定哈希算法" }
            when (hashAlgorithm) {
                HashAlgorithm.SHA1 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA1
                HashAlgorithm.SHA256 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA256
            }
        }
        RSAFillMode.NoPadding -> kSecKeyAlgorithmRSAEncryptionRaw
    }
}

// 辅助函数：转换为PKCS1格式
private fun convertToPKCS1PublicKey(keyData: NSData): String {
    val pemHeader = "-----BEGIN RSA PUBLIC KEY-----\n"
    val pemFooter = "\n-----END RSA PUBLIC KEY-----"
    
    val keyString = keyData.base64EncodedStringWithOptions(0u)
    val lines = keyString.chunked(64)
    return pemHeader + lines.joinToString("\n") + pemFooter
}

private fun convertToPKCS1PrivateKey(keyData: NSData): String {
    val pemHeader = "-----BEGIN RSA PRIVATE KEY-----\n"
    val pemFooter = "\n-----END RSA PRIVATE KEY-----"
    
    val keyString = keyData.base64EncodedStringWithOptions(0u)
    val lines = keyString.chunked(64)
    return pemHeader + lines.joinToString("\n") + pemFooter
}

// 辅助函数：转换为PKCS8格式
private fun convertToPKCS8PublicKey(keyData: NSData): String {
    val pemHeader = "-----BEGIN PUBLIC KEY-----\n"
    val pemFooter = "\n-----END PUBLIC KEY-----"
    
    val keyString = keyData.base64EncodedStringWithOptions(0u)
    val lines = keyString.chunked(64)
    return pemHeader + lines.joinToString("\n") + pemFooter
}

private fun convertToPKCS8PrivateKey(keyData: NSData): String {
    val pemHeader = "-----BEGIN PRIVATE KEY-----\n"
    val pemFooter = "\n-----END PRIVATE KEY-----"
    
    val keyString = keyData.base64EncodedStringWithOptions(0u)
    val lines = keyString.chunked(64)
    return pemHeader + lines.joinToString("\n") + pemFooter
}

@OptIn(ExperimentalForeignApi::class)
private fun CFDataRef.toNSData(): NSData {
    val length = CFDataGetLength(this).toInt()
    val bytes = CFDataGetBytePtr(this)
    return NSData.dataWithBytes(bytes, length.toULong())
}

@Suppress("UNCHECKED_CAST")
@OptIn(ExperimentalForeignApi::class)
private fun NSData.toCFDataRef(): CFDataRef? {
    val length = length.toLong()
    val bytes = bytes
    return CFDataCreate(kCFAllocatorDefault, bytes as? CPointer<UInt8Var>, length)
}
