package com.d10ng.crypto.test

import com.d10ng.crypto.*
import org.junit.Test

class Test {

    @Test
    fun test() {
        // 生成密钥对
        val keyPair = generateRSAKeyPair(KeyFormat.PKCS1)
        println("Public Key: ${keyPair.first}")
        println("Private Key: ${keyPair.second}")

        val pkcs8KeyPair = generateRSAKeyPair(KeyFormat.PKCS8)
        println("Public Key (PKCS8): ${pkcs8KeyPair.first}")
        println("Private Key (PKCS8): ${pkcs8KeyPair.second}")

        // 测试公钥加密
        val content = "1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv1qaz2wsx3edc4rfv"
        val encryptContent = rsaPublicEncrypt(content, pkcs8KeyPair.first, RSAEncryptMode.ECB, RSAFillMode.OAEP)
        println("Encrypt Content: $encryptContent")

        // 测试私钥解密
        val decryptContent = rsaPrivateDecrypt(encryptContent, pkcs8KeyPair.second, RSAEncryptMode.ECB, RSAFillMode.OAEP)
        assert(content == decryptContent)

        // 测试私钥加密
        val encryptContent2 = rsaPrivateEncrypt(content, pkcs8KeyPair.second, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding)
        println("Encrypt Content: $encryptContent2")

        // 测试公钥解密
        val decryptContent2 = rsaPublicDecrypt(encryptContent2, pkcs8KeyPair.first, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding)
        assert(content == decryptContent2)
    }

    @Test
    fun test1() {
        val encryptContent = "QYSu2gq2HffvsT2DqJGr/fG8mUzPHizejSOd21tqkpRC6H1rp/VMQFddY0RDwKjHmYt3Xe0fmS7X5BOWxkR5myvCJS1k/8ABw7Jk2R90edznwe6QDbtKIzrXjRFvAHI9E5YS1EFcUzre/UWRsS2RDc5jfidCVmx2ouYHL/5ByyNeNWsez3RUkDVEgwzRNMjAKASShxFOp0gwWcUHV1A/PBZMZjz3uatJ/YSbUNDfeejRSYKf6XkjwLJejc5m96tHKe8aWE497V4SC/Hh5/7ytb3dPRnr4wxjg+ScuDmh7LejW1/qYkW2mSNLsi9k/4sO5iTvxYbu3H5vg4f8EwvoIA=="
        val key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+mGph2xSO2wo+B7f/mYyXhL4W+jcCZCwUVbRRU/AR9npkXK8ehyRDv55eZMZkhPufsS8gGNFr7xnnLGmglf7wgsinqL0B9CxWXit7ItMDc1nTB/wWbZNOBTMzRgCdFzSfl+oIEqx3TiPiAAai+QCl93lY1JuqnJTIHS9pDaaC6eydUsNkqOri0li2YdkPDG1SXlnSU4Q1rrIWEkYsPZHRCzkoTrURuD2PSYmWPelMIvad44H0Uo4UiziU6AUEdCASOzR0ba3qwkXuQCfQpvuukCxLeWYVjioTv+23D5Ms/EQuU5yShZs0VXfLVUHrSgx6IJns0v6MpOsA16Oq8iV1AgMBAAECggEBAKSR3mmYTWv8Xh+pcorU/rxl9ezJKG58KEN2rTf8DjK0bIH0NZFah0moTwqaYWOyH8KHr3U7eLiFwAwIITxzx6nMg42g+XKSbyY0Mb8lFqbIFytMnbKP8r1PaCJBs43w15NmDMHjvd9WLU2bUB+weYrU4IZ/LdpnUWBpMuK20qv96I+N65opuyS19kaytR6lMLgzKvytAAtGvLOcNVJfFvvaIjPlAA5mEGIITBhoOIe0vEFJHhb1TAxBFAV+u2ZKoDME8saTYk8BsAREgyDlXlqZttEEM/aqpBJ2nffwoOzszoaTdfYKZWzyzFL5qyVkKPWO+HqyBLtUq2Ut7rGMRAECgYEA9gSlZInHiV1AcPHouAFgi2Crm2h+1MiWWrHgfOnnFLpKfl8xadHhqqFCDK2qb2FcbCZ0CuyQvlsK14NAf8yhUdt1u36cXBjSZJAlrGwLwCDQYyZYusLN3LUMX7mVAlDKy11FVZQgTzFtqknvXeVBlAQba7yFbkX7bbEo1Ul3ScECgYEAxlQZ8tdhw5uIe2hKBtzf+6bfeuYl/GwRs0nzmueDfI0A1VvpEegjBAcNcyt5d+1I/jc1IJGTp1058w2ycjaC63efB3Kvtj2NXyj9ejE6/CV/3YIpftlfGQg6WP6NghZFy8CGgLZWQwVPqpc/pRdIDFl3LJa2oT5i0DxL3AJbALUCgYEAh+fRJlUmsa+eJca9dMjt+JESu+tiBVI6HSgeh2L/kOfItz8HIRocvBIRVsepW5ZBZE1p1Y8R9tZ8ismrG+6DP6EozMcIwafEsmEfLr0RULXP6LYKVkG/T6mEiG0Q8BKJtQZ1gu0tXBJGLshhP1GihI4wR7gBTgXC+7negNTw3QECgYBmTc+s0qldi4dVkTBOZfUsDKJO9RU3Jk/jGgyNJUtQHjQF2wlY8VPOqgyoEg7wa/gxGi1PhYiS1qYj2Dbqb3ANIoFoCCLXcNzR74UBWQ/CLV3N12ysQFirwvDGI1i/d9m9BqzbDDNnEwBLUQXFlULXC/dLitreRh4WqGPBM33Z2QKBgBNdiB3BISszUOPBifmCNiL2/qNproTaMalOrzr07s1wy3TFkzvMrKXrO59938xXyOhW+nMgghiNxmdkPUtTWC78XUpuNZUGM75r6uXvsqpGq3lJLypgWWwpt3IXrU+iYT6IwF5l78x4mQfNz2aBkKb3ZE5ni4r4JhTczfjVwur3"
        // 测试私钥解密
        val decryptContent = rsaPrivateDecrypt(encryptContent, key, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding)
        println("Decrypt Content: $decryptContent")
        assert(decryptContent == "1qaz2wsx3edc4rfv")
    }
}