import com.d10ng.crypto.*;

public class JavaDemo {

    public static void main(String[] args) {
        System.out.println("Hello from Java!");
    }

    public static void rsaDemo() {
        // 生成密钥对
        String[] keyPair = RSA_jvmKt.generateRSAKeyPair(KeyFormat.PKCS8, 2048);
        // 获取公钥
        String publicKey = keyPair[0];
        // 获取私钥
        String privateKey = keyPair[1];

        // 公钥加密 RSA/ECB/PKCS1Padding
        String encrypted = RSA_jvmKt.rsaPublicEncrypt("Hello World!", publicKey, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding, null, null);
        // 公钥加密 RSA/ECB/OAEPWithSHA-256AndMGF1Padding
        String encrypted2 = RSA_jvmKt.rsaPublicEncrypt("Hello World!", publicKey, RSAEncryptMode.ECB, RSAFillMode.OAEP, HashAlgorithm.SHA256, MGFHashAlgorithm.SHA1);

        // 私钥解密 RSA/ECB/PKCS1Padding
        String decrypted = RSA_jvmKt.rsaPrivateDecrypt(encrypted, privateKey, RSAEncryptMode.ECB, RSAFillMode.PKCS1Padding, null, null);
        // 私钥解密 RSA/ECB/OAEPWithSHA-256AndMGF1Padding
        String decrypted2 = RSA_jvmKt.rsaPrivateDecrypt(encrypted2, privateKey, RSAEncryptMode.ECB, RSAFillMode.OAEP, HashAlgorithm.SHA256, MGFHashAlgorithm.SHA1);
    }

    public static void aesDemo() {
        String content = "Hello World!";
        String key = "1234567812345678";
        String iv = "8765432187654321";

        // 加密 AES/CBC/PKCS7Padding
        String encrypted = AESKt.aesEncrypt(content, AESMode.CBC, AESFillMode.PKCS7Padding, key, iv);
        // 加密 AES/ECB/PKCS7Padding
        String encrypted2 = AESKt.aesEncrypt(content, AESMode.ECB, AESFillMode.PKCS7Padding, key, iv);

        // 解密 AES/CBC/PKCS7Padding
        String decrypted = AESKt.aesDecrypt(encrypted, AESMode.CBC, AESFillMode.PKCS7Padding, key, iv);
        // 解密 AES/ECB/PKCS7Padding
        String decrypted2 = AESKt.aesDecrypt(encrypted2, AESMode.ECB, AESFillMode.PKCS7Padding, key, iv);
    }
}
