package com.d10ng.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64.Default.decode
import kotlin.io.encoding.Base64.Default.encode
import kotlin.io.encoding.ExperimentalEncodingApi

private val CHARSET = Charsets.UTF_8

@OptIn(ExperimentalEncodingApi::class)
actual fun aesEncryptDo(
    content: String,
    aesMode: AESMode,
    fillMode: AESFillMode,
    key: String,
    iv: String
): String {
    Security.addProvider(BouncyCastleProvider())
    val cipher = Cipher.getInstance("AES/${aesMode.name}/${fillMode.name}")
    val keySpec = SecretKeySpec(key.toByteArray(CHARSET), "AES")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(iv.toByteArray(CHARSET)))
    return encode(cipher.doFinal(content.toByteArray(CHARSET)))
}

@OptIn(ExperimentalEncodingApi::class)
actual fun aesDecryptDo(
    content: String,
    aesMode: AESMode,
    fillMode: AESFillMode,
    key: String,
    iv: String
): String {
    val encrypted = decode(content.toByteArray(CHARSET))
    val cipher = Cipher.getInstance("AES/${aesMode.name}/${fillMode.name}")
    val keySpec = SecretKeySpec(key.toByteArray(CHARSET), "AES")
    cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv.toByteArray(CHARSET)))
    val original = cipher.doFinal(encrypted)
    return String(original, CHARSET)
}