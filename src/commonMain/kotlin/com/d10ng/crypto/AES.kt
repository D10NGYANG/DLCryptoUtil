package com.d10ng.crypto

import kotlin.js.JsExport

// 工作模式
@JsExport
enum class AESMode {
    ECB, CBC
}

// 填充模式
@JsExport
enum class AESFillMode {
    PKCS7Padding
}

/**
 * 对密钥进行校验与补位
 * > 校验：
 * - 判断密钥是否为空，如果为空则抛出异常
 * - 判断密钥长度是否超过32位，如果超过则抛出异常
 * - 判断密钥是否只包含字母和数字，如果不是则抛出异常
 * > 补位：
 * - 如果密钥长度不足最近标准长度的（如16、24、32），则在前面补0
 * @param key String
 * @return String
 */
private fun checkAndFillKey(key: String): String {
    if (key.isEmpty()) {
        throw IllegalArgumentException("密钥不能为空")
    }
    if (key.length > 32) {
        throw IllegalArgumentException("密钥长度不能超过32位")
    }
    if (!key.matches(Regex("[a-zA-Z0-9]+"))) {
        throw IllegalArgumentException("密钥只能包含字母和数字")
    }
    val keyLength = key.length
    return when {
        keyLength <= 16 -> key.padStart(16, '0')
        keyLength <= 24 -> key.padStart(24, '0')
        else -> key.padStart(32, '0')
    }
}

/**
 * 对向量进行校验
 * > 校验：
 * - 判断向量是否为null或者空字符串，如果为是则使用密钥并截取前16位作为向量
 * - 判断向量长度是否超过16位，如果超过则抛出异常
 * - 判断向量是否只包含字母和数字，如果不是则抛出异常
 * @param iv String?
 * @param key String
 * @return String
 */
private fun checkAndFillIv(iv: String?, key: String): String {
    if (iv.isNullOrEmpty()) {
        return key.substring(0, 16)
    }
    if (iv.length > 16) {
        throw IllegalArgumentException("向量长度不能超过16位")
    }
    if (!iv.matches(Regex("[a-zA-Z0-9]+"))) {
        throw IllegalArgumentException("向量只能包含字母和数字")
    }
    return iv
}


/**
 * AES加密
 * @param content String 待加密内容
 * @param aesMode AESMode 工作模式
 * @param fillMode AESFillMode 填充模式
 * @param key String 密钥，只支持字母与数字，密钥长度支持128位、192位、256位，默认128位，输入的密钥长度不足时，会自动在前面补0
 * @param iv String? 向量，只支持字母与数字，最大长度为16位，如果为null或者空则使用密钥并截取前16位
 * @return String
 */
@JsExport
fun aesEncrypt(
    content: String,
    aesMode: AESMode = AESMode.CBC,
    fillMode: AESFillMode = AESFillMode.PKCS7Padding,
    key: String,
    iv: String? = null
): String {
    val keyStr = checkAndFillKey(key)
    val ivStr = checkAndFillIv(iv, keyStr)
    return aesEncryptDo(content, aesMode, fillMode, keyStr, ivStr)
}

internal expect fun aesEncryptDo(
    content: String,
    aesMode: AESMode = AESMode.CBC,
    fillMode: AESFillMode = AESFillMode.PKCS7Padding,
    key: String,
    iv: String
): String


/**
 * AES解密
 * @param content String 待解密内容
 * @param aesMode AESMode 工作模式
 * @param fillMode AESFillMode 填充模式
 * @param key String 密钥，只支持字母与数字，密钥长度支持128位、192位、256位，默认128位，输入的密钥长度不足时，会自动在前面补0
 * @param iv String? 向量，只支持字母与数字，最大长度为16位，如果为null或者空则使用密钥并截取前16位
 * @return String
 */
@JsExport
fun aesDecrypt(
    content: String,
    aesMode: AESMode = AESMode.CBC,
    fillMode: AESFillMode = AESFillMode.PKCS7Padding,
    key: String,
    iv: String? = null
): String {
    val keyStr = checkAndFillKey(key)
    val ivStr = checkAndFillIv(iv, keyStr)
    return aesDecryptDo(content, aesMode, fillMode, keyStr, ivStr)
}

internal expect fun aesDecryptDo(
    content: String,
    aesMode: AESMode = AESMode.CBC,
    fillMode: AESFillMode = AESFillMode.PKCS7Padding,
    key: String,
    iv: String
): String