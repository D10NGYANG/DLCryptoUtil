package com.d10ng.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_MD5
import platform.CoreCrypto.CC_MD5_DIGEST_LENGTH

/**
 * MD5加密
 * @param data String 待加密数据
 * @return String 加密后的数据, 32位小写
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalStdlibApi::class)
actual fun md5(data: String): String {
    // 将输入的字符串转换为 UTF-8 编码的字节数据
    val bytes = data.encodeToByteArray()
    val digest = UByteArray(CC_MD5_DIGEST_LENGTH)

    // 使用 CommonCrypto 的 CC_MD5 方法进行加密
    bytes.usePinned { pinnedBytes ->
        digest.usePinned { pinnedDigest ->
            CC_MD5(
                pinnedBytes.addressOf(0),
                bytes.size.convert(),
                pinnedDigest.addressOf(0)
            )
        }
    }
    // 将结果转换为 32 位小写的十六进制字符串
    return digest.toHexString()
}