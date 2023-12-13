import com.d10ng.crypto.md5
import kotlin.test.Test
import kotlin.test.assertEquals

class MD5_Test {

    @Test
    fun test() {
        val content = "1qaz2wsx3edc4rfv"
        assertEquals(md5(content), "ef0365c0797daf1405b5aea0da037dfe")
    }
}