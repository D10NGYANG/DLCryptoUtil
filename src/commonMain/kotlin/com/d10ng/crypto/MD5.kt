package com.d10ng.crypto

/**
 * MD5加密
 * @param data String 待加密数据
 * @return String 加密后的数据, 32位小写
 */
expect fun md5(data: String): String