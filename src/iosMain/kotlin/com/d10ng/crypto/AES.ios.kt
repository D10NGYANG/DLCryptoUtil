package com.d10ng.crypto

import kotlinx.cinterop.*
import platform.CoreCrypto.*

@OptIn(ExperimentalForeignApi::class)
internal actual fun aesEncryptDo(
    content: String,
    aesMode: AESMode,
    fillMode: AESFillMode,
    key: String,
    iv: String
): String {
    // 将 content 转换为字节数组
    val contentBytes = content.encodeToByteArray()
    val keyBytes = key.encodeToByteArray()
    val ivBytes = iv.encodeToByteArray()

    // 加密结果缓冲区
    val bufferSize = contentBytes.size.toUInt() + kCCBlockSizeAES128
    val buffer = ByteArray(bufferSize.toInt())

    // 使用 memScoped 管理 numBytesEncrypted 的内存
    val numBytesEncrypted = memScoped {
        val numBytesEncryptedPtr = alloc<ULongVar>() // 用于存储实际加密的字节数

        // 调用 CCCrypt
        val status = contentBytes.usePinned { contentPinned ->
            keyBytes.usePinned { keyPinned ->
                ivBytes.usePinned { ivPinned ->
                    buffer.usePinned { bufferPinned ->
                        CCCrypt(
                            op = kCCEncrypt, // 加密操作
                            alg = kCCAlgorithmAES, // AES 算法
                            options = (when (aesMode) {
                                AESMode.ECB -> kCCOptionECBMode.toInt() // ECB 模式
                                AESMode.CBC -> 0 // CBC 模式（需要 IV）
                            } or when (fillMode) {
                                AESFillMode.PKCS7Padding -> kCCOptionPKCS7Padding.toInt() // PKCS7 填充模式
                            }).toUInt(),
                            key = keyPinned.addressOf(0), // 密钥地址
                            keyLength = keyBytes.size.convert(), // 密钥长度
                            iv = if (aesMode == AESMode.CBC) ivPinned.addressOf(0) else null, // IV 地址（仅 CBC 模式需要）
                            dataIn = contentPinned.addressOf(0), // 输入数据地址
                            dataInLength = contentBytes.size.convert(), // 输入数据长度
                            dataOut = bufferPinned.addressOf(0), // 输出数据地址
                            dataOutAvailable = buffer.size.convert(), // 输出缓冲区大小
                            dataOutMoved = numBytesEncryptedPtr.ptr // 实际输出数据大小的指针
                        )
                    }
                }
            }
        }

        // 检查加密状态
        require(status == kCCSuccess) { "AES encryption failed with status: $status" }

        numBytesEncryptedPtr.value.toInt() // 返回实际加密的字节数
    }

    // 将加密结果裁剪到实际大小并转为 Base64
    return buffer.copyOf(numBytesEncrypted).encodeBase64ToString()
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun aesDecryptDo(
    content: String,
    aesMode: AESMode,
    fillMode: AESFillMode,
    key: String,
    iv: String
): String {

    // 将 Base64 编码的密文解码为字节数组
    val contentBytes = content.decodeBase64ToByteArray()

    val keyBytes = key.encodeToByteArray()
    val ivBytes = iv.encodeToByteArray()

    // 解密结果缓冲区
    val bufferSize = contentBytes.size + kCCBlockSizeAES128.toInt()
    val buffer = ByteArray(bufferSize)

    // 使用 memScoped 管理 numBytesDecrypted 的内存
    val numBytesDecrypted = memScoped {
        val numBytesDecryptedPtr = alloc<ULongVar>() // 用于存储实际解密的字节数

        // 调用 CCCrypt
        val status = contentBytes.usePinned { contentPinned ->
            keyBytes.usePinned { keyPinned ->
                ivBytes.usePinned { ivPinned ->
                    buffer.usePinned { bufferPinned ->
                        CCCrypt(
                            op = kCCDecrypt, // 解密操作
                            alg = kCCAlgorithmAES, // AES 算法
                            options = (when (aesMode) {
                                AESMode.ECB -> kCCOptionECBMode.toInt() // ECB 模式
                                AESMode.CBC -> 0 // CBC 模式（需要 IV）
                            } or when (fillMode) {
                                AESFillMode.PKCS7Padding -> kCCOptionPKCS7Padding.toInt() // PKCS7 填充模式
                            }).toUInt(),
                            key = keyPinned.addressOf(0), // 密钥地址
                            keyLength = keyBytes.size.convert(), // 密钥长度
                            iv = if (aesMode == AESMode.CBC) ivPinned.addressOf(0) else null, // IV 地址（仅 CBC 模式需要）
                            dataIn = contentPinned.addressOf(0), // 输入数据地址
                            dataInLength = contentBytes.size.convert(), // 输入数据长度
                            dataOut = bufferPinned.addressOf(0), // 输出数据地址
                            dataOutAvailable = buffer.size.convert(), // 输出缓冲区大小
                            dataOutMoved = numBytesDecryptedPtr.ptr // 实际输出数据大小的指针
                        )
                    }
                }
            }
        }

        // 检查解密状态
        require(status == kCCSuccess) { "AES decryption failed with status: $status" }

        numBytesDecryptedPtr.value.toInt() // 返回实际解密的字节数
    }

    // 将解密结果裁剪到实际大小并转换为字符串
    return buffer.copyOf(numBytesDecrypted).decodeToString()
}