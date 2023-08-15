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
        val content = "1qaz2wsx3edc4rfv"
        val key = "1234567812345678"
        val encryptContent = aesEncrypt(content, key = key)
        println(encryptContent)
        assertEquals(aesDecrypt(encryptContent, key = key), content)
    }

}