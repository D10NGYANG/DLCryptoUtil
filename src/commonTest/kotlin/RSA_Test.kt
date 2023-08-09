import com.d10ng.crypto.*
import kotlin.test.Test
import kotlin.test.assertEquals

class RSA_Test {

    @Test
    fun test() {
        // 生成密钥对
        val keyPair = generateRSAKeyPair(KeyFormat.PKCS1)
        println("Public Key: \n${keyPair.first}")
        println("Private Key: \n${keyPair.second}")

        val pkcs8KeyPair = generateRSAKeyPair(KeyFormat.PKCS8)
        println("Public Key (PKCS8): \n${pkcs8KeyPair.first}")
        println("Private Key (PKCS8): \n${pkcs8KeyPair.second}")

//        // 测试公钥加密
//        val content = "1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv"
//        val encryptContent = rsaPublicEncrypt(content, pkcs8KeyPair.first, RSAEncryptMode.ECB, RSAFillMode.OAEP)
//        println("Encrypt Content: $encryptContent")
//
//        // 测试私钥解密
//        val decryptContent = rsaPrivateDecrypt(encryptContent, pkcs8KeyPair.second, RSAEncryptMode.ECB, RSAFillMode.OAEP)
//        assertEquals(content, decryptContent)
//
//        // 测试私钥加密
//        val encryptContent2 = rsaPrivateEncrypt(content, pkcs8KeyPair.second, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding)
//        println("Encrypt Content: $encryptContent2")
//
//        // 测试公钥解密
//        val decryptContent2 = rsaPublicDecrypt(encryptContent2, pkcs8KeyPair.first, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding)
//        assertEquals(content, decryptContent2)
    }
}