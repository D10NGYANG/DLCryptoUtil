package com.d10ng.crypto

import java.security.MessageDigest

/**
 * MD5加密
 * @param data String 待加密数据
 * @return String 加密后的数据, 32位小写
 */
actual fun md5(data: String): String {
    val md = MessageDigest.getInstance("MD5")
    val digest = md.digest(data.toByteArray())
    return digest.joinToString("") { "%02x".format(it) }
}