package com.d10ng.crypto

/**
 * AES加密
 * @param content String 待加密内容
 * @param aesMode AESMode 工作模式
 * @param fillMode AESFillMode 填充模式
 * @param key String 密钥，密钥长度支持128位、192位、256位，默认128位，输入的密钥长度不足时，会自动在前面补0
 * @param iv String? 向量，如果为null则使用密钥
 * @return String
 */
actual fun aesEncrypt(
    content: String,
    aesMode: AESMode,
    fillMode: AESFillMode,
    key: String,
    iv: String?
): String {
    TODO("Not yet implemented")
}

/**
 * AES解密
 * @param content String 待解密内容
 * @param aesMode AESMode 工作模式
 * @param fillMode AESFillMode 填充模式
 * @param key String 密钥，密钥长度支持128位、192位、256位，默认128位，输入的密钥长度不足时，会自动在前面补0
 * @param iv String? 向量，如果为null则使用密钥
 * @return String
 */
actual fun aesDecrypt(
    content: String,
    aesMode: AESMode,
    fillMode: AESFillMode,
    key: String,
    iv: String?
): String {
    TODO("Not yet implemented")
}