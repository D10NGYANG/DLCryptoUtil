import com.d10ng.crypto.AESFillMode
import com.d10ng.crypto.AESMode
import com.d10ng.crypto.aesDecrypt
import com.d10ng.crypto.aesEncrypt
import kotlin.test.Test
import kotlin.test.assertEquals

class AES_Test {

    /**
     * 测试加密与解密
     */
    @Test
    fun test() {
        AESMode.entries.forEach { aesMode ->
            println("AESMode: ${aesMode.name}")
            AESFillMode.entries.forEach { aesFillMode ->
                println("AESFillMode: ${aesFillMode.name}")
                val content = "1qaz2wsx3edc4rfv"
                val key = "1234567812345678"
                val iv = "8765432187654321"
                val encryptContent = aesEncrypt(content, aesMode, aesFillMode, key, iv)
                println("加密后：$encryptContent")
                assertEquals(aesDecrypt(encryptContent, aesMode, aesFillMode, key, iv), content)
            }
        }
    }

}