@file:JsExport
package com.d10ng.crypto

import kotlin.io.encoding.Base64.Default.decode
import kotlin.io.encoding.Base64.Default.encodeToByteArray
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.js.JsExport

@OptIn(ExperimentalEncodingApi::class)
fun String.decodeBase64ToByteArray() = decode(this)

fun String.decodeBase64(): String =
    decodeBase64ToByteArray().decodeToString()

fun ByteArray.decodeBase64ByteArray(): ByteArray =
    decodeToString().decodeBase64ToByteArray()

fun ByteArray.decodeBase64ToString(): String =
    decodeBase64ByteArray().decodeToString()

@OptIn(ExperimentalEncodingApi::class)
fun ByteArray.encodeBase64ByteArray() = encodeToByteArray(this)

fun ByteArray.encodeBase64ToString(): String =
    encodeBase64ByteArray().decodeToString()

fun String.encodeBase64(): String =
    encodeToByteArray().encodeBase64ToString()

fun String.encodeBase64ToByteArray(): ByteArray =
    encodeBase64().encodeToByteArray()
