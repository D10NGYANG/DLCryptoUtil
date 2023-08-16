package com.d10ng.crypto

import com.d10ng.crypto.thirdParties.NodeForge
import com.d10ng.crypto.thirdParties.StartOptions

actual fun aesEncryptDo(
    content: String,
    aesMode: AESMode,
    fillMode: AESFillMode,
    key: String,
    iv: String
): String {
    val cipher = NodeForge.cipher.createCipher("AES-${aesMode.name}", NodeForge.util.createBuffer(key)).apply {
        start(StartOptions().apply {
            this.iv = NodeForge.util.createBuffer(iv)
        })
        update(NodeForge.util.createBuffer(content))
        finish()
    }
    return NodeForge.util.encode64(cipher.output.getBytes())
}

actual fun aesDecryptDo(
    content: String,
    aesMode: AESMode,
    fillMode: AESFillMode,
    key: String,
    iv: String
): String {
    val decipher = NodeForge.cipher.createDecipher("AES-${aesMode.name}", NodeForge.util.createBuffer(key)).apply {
        start(StartOptions().apply {
            this.iv = NodeForge.util.createBuffer(iv)
        })
        update(NodeForge.util.createBuffer(NodeForge.util.decode64(content)))
        finish()
    }
    return decipher.output.getBytes()
}