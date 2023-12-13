package com.d10ng.crypto

import com.d10ng.crypto.thirdParties.NodeForge

/**
 * MD5加密
 * @param data String 待加密数据
 * @return String 加密后的数据, 32位小写
 */
@JsExport
actual fun md5(data: String): String {
    val mdF = NodeForge.md.md5.create()
    mdF.update(data)
    return mdF.digest().toHex()
}