import com.d10ng.crypto.decodeBase64
import com.d10ng.crypto.encodeBase64
import kotlin.test.Test
import kotlin.test.assertEquals

class Base64_Test {

    private val map = mapOf(
        "中文测试" to "5Lit5paH5rWL6K+V",
        "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM" to "cXdlcnR5dWlvcGFzZGZnaGprbHp4Y3Zibm1RV0VSVFlVSU9QQVNERkdISktMWlhDVkJOTQ==",
        "1234567890" to "MTIzNDU2Nzg5MA==",
        "~`!@#$%^&*()_-+={[}]|\\:;\"'<,>.?/" to "fmAhQCMkJV4mKigpXy0rPXtbfV18XDo7Iic8LD4uPy8=",
        "～·！@#¥%……&*（）-=——+【】「」｜、：；\"'《，》。？/" to "772ewrfvvIFAI8KlJeKApuKApiYq77yI77yJLT3igJTigJQr44CQ44CR44CM44CN772c44CB77ya77ybIifjgIrvvIzjgIvjgILvvJ8v",
    )

    @Test
    fun encode() {
        map.forEach { item ->
            println(item)
            val base64 = item.key.encodeBase64()
            assertEquals(base64, item.value)
        }
    }

    @Test
    fun decode() {
        map.forEach { item ->
            println(item)
            val base64 = item.value.decodeBase64()
            assertEquals(base64, item.key)
        }
    }
}