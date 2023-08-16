import com.d10ng.crypto.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RSA_Test {

    enum class KeyMap(val bitLength: Int, val publicKey: String, val privateKey: String) {
        PKCS1_1024(
            1024,
            "MIGJAoGBAJuo2/vX+6552kgkhvD7xxiZdo44AfoMtIyGb7KTuOmD3/T+nV1MR8YEMU8k48XrZ6se3AGYJezmSKKcGf0HofdncB8CKWcotoGkso0MRNiGkNtPzDnHv6I0HUcHXHVYYHM8fpGzRMrhZqBRcdEhKzFgQmkCO7WTlLPAKlBYak1hAgMBAAE=",
            "MIICXAIBAAKBgQCbqNv71/uuedpIJIbw+8cYmXaOOAH6DLSMhm+yk7jpg9/0/p1dTEfGBDFPJOPF62erHtwBmCXs5kiinBn9B6H3Z3AfAilnKLaBpLKNDETYhpDbT8w5x7+iNB1HB1x1WGBzPH6Rs0TK4WagUXHRISsxYEJpAju1k5SzwCpQWGpNYQIDAQABAoGAFoEkRNXmEkSVtWZqh/6uuzS8ujUIvCEIHWT2UygeTMx/HYmOMMXtfohupJWdxKiTFV9hyW041nY4vCG7dCSdWtDESdDM8wjK9EAFb4/zAGi9DGlYMwxDbz3KzQxvj43ldfotdysm6bjshnrrjEqWi0iBZjtHzj0D7SNh3n2AAkECQQDKmgi6qnuffV+WOV4WdMrnGa0WHDwEsZLTkQq85cnKdmQjqfb1Gp75XuBd+Fk7zmNfadmr/YXuO5ieuz8bzsPZAkEAxK+K/yWMJAoQ0cV3w7t0mOoqyItstttHWnDDFGIVE35COcfzUdhxrCaRJJ7NWghgHitn2DNkSF+BVUg33PnIyQJAG9aQbn2wYNjMQor9Z56CpsB7bPdSM97matWaIRx93qjn15KqEUGoKGGl+KOAN1yDgP+9XgmG1pYvwVe/MyX0+QJARm/PSVx6+ZUZPOaI43HIadLCi5tSzZFt1je3xR7zCU4YDXVL8C2hV9Nf+0tboziIo4VL5SNScJCzUoVQbDSP8QJBAJg+8jK0XbdPujcRvhUWnpYhM7q4dPzE2HnR7+W7yRVy6625taxszWau+O1I6zRrTuG1VkuPaq0bl4gXJtHt3OI="
        ),
        PKCS1_2048(
            2048,
            "MIIBCgKCAQEAvHx3Wlni0G+2RGzxxGtHrBRivN44A421LxEdGYUM9Cg7bz0DjqeMWiLePrIXzNVFDP3DeFxcma5kMpxkCqt7DuuTt29JJbTsOBFx06bABoQnzdzErnCiyEFWm9i0cCq2z1O/fnwzy+hAljvFZP0dadTAVFcl3UgThkzuWsXPqqmejN19DwVPyhFY8B3GBxtuco3AHLuXufqc1Oyc1mmpCx8Vqvg0Y98dOkcS/f+mG0fNB7Tb5UlWMyN3ZQUJgZTb6MTAWLiMgTmHJE+Lg2MYBfV2uOmZa5uYIAEzPwnZA2bj6OfPu43lqRCX3G6n7A0alZKeKhA94sQUBW1ep3+bYwIDAQAB",
            "MIIEpAIBAAKCAQEAvHx3Wlni0G+2RGzxxGtHrBRivN44A421LxEdGYUM9Cg7bz0DjqeMWiLePrIXzNVFDP3DeFxcma5kMpxkCqt7DuuTt29JJbTsOBFx06bABoQnzdzErnCiyEFWm9i0cCq2z1O/fnwzy+hAljvFZP0dadTAVFcl3UgThkzuWsXPqqmejN19DwVPyhFY8B3GBxtuco3AHLuXufqc1Oyc1mmpCx8Vqvg0Y98dOkcS/f+mG0fNB7Tb5UlWMyN3ZQUJgZTb6MTAWLiMgTmHJE+Lg2MYBfV2uOmZa5uYIAEzPwnZA2bj6OfPu43lqRCX3G6n7A0alZKeKhA94sQUBW1ep3+bYwIDAQABAoIBAAmBWV+EEu0iBRYUTGj0ZAvoh0YxCrAbMFzsRwRnckzJzp2AfTJvfqN5CK4uuwaIZtAN6BKkzcKuSb1Hp7/l//GzraJdiVnOcu8s6gmbaimp9nvqOzz0zzC8Isr/NbJGZSu1dH3Dc7U/xCoPX5gFL7uLkBtwvacYIGvwa0DGov9fMjJLK0kDjeZdOGUSZdLX5kP/OdMspJhczKWZaMSrCq5W8i4/E35qrdAp+LHHfN4RrHTLEovnX15T8hEDd1j3JNSXCoqGg81k7qimegZwFm+OoSGM2ts4PRPWa/9j7BcuYMgj1w8A3c1rGKgbc+fpqj0xPlQwdjDI3d3lTMpVqpkCgYEA8Cz2Rq2hCqyaObuthPAUTi4Slysg0irJrhr29EH9LhahVcnHClRyaSvfJcP42sFw6qfQd707O/v7/ry+OCPx3qOzPYJ/KvbOQEbEZ+6qfXKGArbWoIVOnyZyi7mXQXYP5BilpKcN1rMh7T+IaTJenVTCwXeV3dT7+afZsPj8HGUCgYEAyOeo0EauU68AFkZFHjcKI3OJqJBvfYXJwdjcdMEN9DmwwRqlcxC6YFX+hEozg+QjX1s0JaY9t93SARCSY6a4JrsMKAL9opzf7NBJomMPwRmqbFNoEUsREv61UaJsW6sz1gX3Z9HQea0hFggruWQfkRf0Oifr0oStBQFjcjjRqCcCgYEAp8lBY674ylQ6igqq9iwig1t8cU8X5rstmgwMaiePkBsPKreD7ZuBMigMBH4b4/cvwz7pTD1OnGE1coi4+s9hsX/7QAVigclZ3V2S6Gi7glf3dv30gr+eZWCetS46lOi9wUPWtGhgKpWKJgw0aAlgP9lvFWlNsWORhJ/WXOQUfGECgYBl+9LiBz8vE8LDi+BCOkZXQKs8ejVeTq/gSyl9yxI+S5rCK7iY9IDnrj+I//GunfymxzFtezoRP/T+vV7SXytT3deJ6BrAlUnGeOUoHYk9yL2OR7ioLqb4MXvxeLXwwrOJjXXNqeBeI9iLypIHhh/QE4zSiLlZICiERfQpY1ZqOQKBgQCGpbj8TTOUuZ/MYsIxyLUocPB/vcjtDPzf2+CncKH/YWmSV788X/kphF7fBzy5UpX07rOEo5/9Fd164ioJWa/5ftyEkT2U0EoJzACfODsqab2UcygY5NgZBdFnkNqiQS5j2SFiC9kmd3qDffy+aBOSmmt1eTg49aJI1GUvKfhLmg=="
        ),
        PKCS8_1024(
            1024,
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJ262X05SrXiz+4AMHH+RudVUL1mvq38H0ka04/reZilWv73swQPqTo1gvgCJwe0k23UDQpL2/ca24fh0kkxVCV5Z2sT1OLys+tJomcFBHAXEj3n9Ie+LPiBbLot94GpxzVnFivy9wgobRBpPKh9iSHefayR6yn7nKj68RGFxDhwIDAQAB",
            "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMnbrZfTlKteLP7gAwcf5G51VQvWa+rfwfSRrTj+t5mKVa/vezBA+pOjWC+AInB7STbdQNCkvb9xrbh+HSSTFUJXlnaxPU4vKz60miZwUEcBcSPef0h74s+IFsui33ganHNWcWK/L3CChtEGk8qH2JId59rJHrKfucqPrxEYXEOHAgMBAAECgYBZywfoju0GYik/46RVKgGyhS0ky+hLneeohJj6zowbl+bQEYbKC02sGTBkSOqJAL6r0jY/2diybb4qYKdUGr2McCvwzqZDjsIQ2su/XL+dK6o2HhW9Gxydi/2UY+IfWNGgcIZvBW4r16LPn5ZsfuJpl814SsA6xqckWjeVfC2NCQJBAOUJzgFkK8dRcOVrZesC1N7okWK+BxfzQN0CFEnbHm9k/QS0T74v1DORqaod5wfWvsVtLKwzN51l9w/esV/rdMsCQQDhnsicQa6mo900PacGPOlUSOR2b0ocia4eD8Td5jYCNnn2UWlFrM0JjbnPvY1Br/ZmBPUvwEWnu1/tDakyAhC1AkB70SoZ3HJCRUe37rBhNN2pR6bY74vcKbfGAoq/RoKUi86wjV2Snj6kRjmnapTryu7Ewflleia1o1rFrIjNJvezAkBoZeWj0Ay1lPtFMgX4L/Uzh+sXFlXvsJF93YQVvXFeQsDahj80+0mA0zCYfLhBHd/gwwiFCO3yOBSiBwE0X5pFAkBVKAlVdIVTDSuJYsBnvdIKcOtDCn+OGq8lzazlymerbs6lZmrpAMkYDzpqTWogcDq4ILdiz002h0Bx69QLhomR"
        ),
        PKCS8_2048(
            2048,
            "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"
        ),

    }

    /**
     * 测试生成密钥对
     */
    @Test
    fun testGenerateRSAKeyPair() {
        val keyPair1024 = generateRSAKeyPair(KeyFormat.PKCS1, 1024)
        println("Public Key  1024: \n${keyPair1024[0]}")
        println("Private Key 1024: \n${keyPair1024[1]}")
        assertTrue(keyPair1024[0].isNotEmpty())
        assertTrue(keyPair1024[1].isNotEmpty())

        val pkcs8KeyPair1024 = generateRSAKeyPair(KeyFormat.PKCS8, 1024)
        println("Public Key (PKCS8)  1024: \n${pkcs8KeyPair1024[0]}")
        println("Private Key (PKCS8) 1024: \n${pkcs8KeyPair1024[1]}")
        assertTrue(pkcs8KeyPair1024[0].isNotEmpty())
        assertTrue(pkcs8KeyPair1024[1].isNotEmpty())

        val keyPair2048 = generateRSAKeyPair(KeyFormat.PKCS1, 2048)
        println("Public Key  2048: \n${keyPair2048[0]}")
        println("Private Key 2048: \n${keyPair2048[1]}")
        assertTrue(keyPair2048[0].isNotEmpty())
        assertTrue(keyPair2048[1].isNotEmpty())

        val pkcs8KeyPair2048 = generateRSAKeyPair(KeyFormat.PKCS8, 2048)
        println("Public Key (PKCS8)  2048: \n${pkcs8KeyPair2048[0]}")
        println("Private Key (PKCS8) 2048: \n${pkcs8KeyPair2048[1]}")
        assertTrue(pkcs8KeyPair2048[0].isNotEmpty())
        assertTrue(pkcs8KeyPair2048[1].isNotEmpty())
    }

    /**
     * 测试公钥加密、私钥解密
     */
    @Test
    fun testRSAEncryptAndDecrypt() {
        val contentList = listOf(
            // 短文本
            "1qaz2wsx",
            // 长文本
            (0..30).joinToString("") { "1qaz2wsx3EDC4RFV" },
            // 带汉字的文本
            "1qaz2wsx一二三四五六七八九十",
            // 带特殊字符的文本
            "1qaz2wsx3EDC4RFV一二三四五六七八九十,.!@#$%^&*()_+{}[]|\\;':\"<>?/"
        )

        // PKCS1Padding模式
        println("PKCS1Padding模式")
        KeyMap.entries.forEach { key ->
            println("key: ${key.name}")
            contentList.forEach { content ->
                println("content: $content")
                val encryptContent = rsaPublicEncrypt(
                    content,
                    key.publicKey,
                    RSAEncryptMode.ECB,
                    RSAFillMode.PKCS1Padding
                )
                val decryptContent = rsaPrivateDecrypt(
                    encryptContent,
                    key.privateKey,
                    RSAEncryptMode.ECB,
                    RSAFillMode.PKCS1Padding
                )
                assertEquals(content, decryptContent)
            }
        }

        // OAEP模式
        println("OAEP模式")
        KeyMap.entries.forEach { key ->
            println("key: ${key.name}")
            contentList.forEach { content ->
                println("content: $content")
                HashAlgorithm.values().forEach { hash ->
                    println("hash: ${hash.name}")
                    MGFHashAlgorithm.values().forEach { mgfHash ->
                        println("mgfHash: ${mgfHash.name}")
                        val encryptContent = rsaPublicEncrypt(
                            content,
                            key.publicKey,
                            RSAEncryptMode.ECB,
                            RSAFillMode.OAEP,
                            hash,
                            mgfHash
                        )
                        val decryptContent = rsaPrivateDecrypt(
                            encryptContent,
                            key.privateKey,
                            RSAEncryptMode.ECB,
                            RSAFillMode.OAEP,
                            hash,
                            mgfHash
                        )
                        assertEquals(content, decryptContent)
                    }
                }
            }
        }
    }
}