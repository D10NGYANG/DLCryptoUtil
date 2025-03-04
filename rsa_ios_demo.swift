import Foundation
import Security
import CommonCrypto

enum KeyFormat {
    case PKCS1, PKCS8
}

enum RSAFillMode {
    case NoPadding, OAEP, PKCS1Padding
}

enum RSAEncryptMode {
    case NONE, ECB
}

enum HashAlgorithm {
    case SHA1, SHA256
    
    func secKeyAlgorithm() -> SecKeyAlgorithm {
        switch self {
        case .SHA1:
            return .rsaEncryptionOAEPSHA1
        case .SHA256:
            return .rsaEncryptionOAEPSHA256
        }
    }
}

enum MGFHashAlgorithm {
    case SHA1
}

enum RSAError: Error {
    case invalidBase64String
    case keyCreationFailed
    case encryptionFailed
    case decryptionFailed
    case dataConversionFailed
    case invalidParameters
    case unsupportedConfiguration
    case blockSizeCalculationFailed
}

/**
 * 生成RSA密钥对
 * @param keyFormat KeyFormat 密钥格式，默认PKCS1
 * @param keyLength Int 密钥长度，默认2048位
 * @return Array<String> 公钥和私钥
 */
func generateRSAKeyPair(
    keyFormat: KeyFormat = .PKCS1,
    keyLength: Int = 2048
) throws -> [String] {
    // 创建密钥对生成参数
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: keyLength
    ]
    
    // 生成密钥对
    var publicKey, privateKey: SecKey?
    var error: Unmanaged<CFError>?
    
    // 生成密钥对
    guard let keyPair = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw RSAError.keyCreationFailed
    }
    
    // 获取公钥和私钥
    privateKey = keyPair
    publicKey = SecKeyCopyPublicKey(keyPair)
    
    // 转换为数据
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey!, &error),
          let privateKeyData = SecKeyCopyExternalRepresentation(privateKey!, &error) else {
        throw RSAError.keyCreationFailed
    }
    
    // 根据密钥格式转换
    var publicKeyString: String
    var privateKeyString: String
    
    switch keyFormat {
    case .PKCS1:
        publicKeyString = convertToPKCS1PublicKey(Data(referencing: publicKeyData))
        privateKeyString = convertToPKCS1PrivateKey(Data(referencing: privateKeyData))
    case .PKCS8:
        publicKeyString = convertToPKCS8PublicKey(Data(referencing: publicKeyData))
        privateKeyString = convertToPKCS8PrivateKey(Data(referencing: privateKeyData))
    }
    
    return [publicKeyString, privateKeyString]
}

/**
 * RSA公钥加密 - 支持长文本分块处理
 */
func rsaPublicEncrypt(
    data: String,
    publicKey: String,
    encryptMode: RSAEncryptMode = .ECB,
    fillMode: RSAFillMode = .PKCS1Padding,
    hashAlgorithm: HashAlgorithm? = nil,
    mgfHashAlgorithm: MGFHashAlgorithm? = nil
) throws -> String {
    // 去除PEM头尾和换行符
    let cleanedPublicKey = cleanPEMKey(publicKey)
    
    // Base64解码公钥
    guard let keyData = Data(base64Encoded: cleanedPublicKey) else {
        throw RSAError.invalidBase64String
    }
    
    // 创建SecKey对象
    let keyDict: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: keyData.count * 8,
        kSecReturnPersistentRef as String: true
    ]
    
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) else {
        throw RSAError.keyCreationFailed
    }
    
    // 准备加密算法
    var algorithm: SecKeyAlgorithm
    
    switch fillMode {
    case .PKCS1Padding:
        algorithm = .rsaEncryptionPKCS1
    case .OAEP:
        if let hash = hashAlgorithm {
            algorithm = hash.secKeyAlgorithm()
        } else {
            throw RSAError.invalidParameters
        }
    case .NoPadding:
        algorithm = .rsaEncryptionRaw
    }
    
    // 确保算法支持此密钥
    guard SecKeyIsAlgorithmSupported(secKey, .encrypt, algorithm) else {
        throw RSAError.unsupportedConfiguration
    }
    
    // 计算每个块的最大加密大小，传递哈希算法
    let blockSize = try calculateEncryptionBlockSize(secKey: secKey, fillMode: fillMode, hashAlgorithm: hashAlgorithm)
    
    // 将输入数据转换为UTF-8编码
    guard let inputData = data.data(using: .utf8) else {
        throw RSAError.dataConversionFailed
    }
    
    // 分块加密
    var encryptedBlocks: [String] = []
    
    var currentIndex = 0
    while currentIndex < inputData.count {
        // 计算当前块的大小
        let chunkSize = min(blockSize, inputData.count - currentIndex)
        let endIndex = currentIndex + chunkSize
        
        // 提取当前块的数据
        let range = currentIndex..<endIndex
        let chunk = inputData.subdata(in: range)
        
        // 加密当前块
        guard let encryptedData = SecKeyCreateEncryptedData(secKey, algorithm, chunk as CFData, &error) else {
            throw RSAError.encryptionFailed
        }
        
        // 将加密后的块转换为Base64并添加到结果列表
        let encryptedChunk = Data(referencing: encryptedData).base64EncodedString()
        encryptedBlocks.append(encryptedChunk)
        
        // 移动到下一块
        currentIndex = endIndex
    }
    
    // 将所有加密块连接起来，以 | 分隔
    return encryptedBlocks.joined(separator: "|")
}

/**
 * RSA私钥解密 - 支持长文本分块处理
 */
func rsaPrivateDecrypt(
    data: String,
    privateKey: String,
    encryptMode: RSAEncryptMode = .ECB,
    fillMode: RSAFillMode = .PKCS1Padding,
    hashAlgorithm: HashAlgorithm? = nil,
    mgfHashAlgorithm: MGFHashAlgorithm? = nil
) throws -> String {
    // 去除PEM头尾和换行符
    let cleanedPrivateKey = cleanPEMKey(privateKey)
    
    // Base64解码私钥
    guard let keyData = Data(base64Encoded: cleanedPrivateKey) else {
        throw RSAError.invalidBase64String
    }
    
    // 创建SecKey对象
    let keyDict: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecReturnPersistentRef as String: true
    ]
    
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) else {
        throw RSAError.keyCreationFailed
    }
    
    // 准备解密算法
    var algorithm: SecKeyAlgorithm
    
    switch fillMode {
    case .PKCS1Padding:
        algorithm = .rsaEncryptionPKCS1
    case .OAEP:
        if let hash = hashAlgorithm {
            algorithm = hash.secKeyAlgorithm()
        } else {
            throw RSAError.invalidParameters
        }
    case .NoPadding:
        algorithm = .rsaEncryptionRaw
    }
    
    // 确保算法支持此密钥
    guard SecKeyIsAlgorithmSupported(secKey, .decrypt, algorithm) else {
        throw RSAError.unsupportedConfiguration
    }
    
    // 分割加密数据块
    let encryptedBlocks = data.components(separatedBy: "|")
    
    // 解密每个块
    var decryptedData = Data()
    
    for block in encryptedBlocks {
        guard let blockData = Data(base64Encoded: block) else {
            throw RSAError.invalidBase64String
        }
        
        guard let decryptedBlock = SecKeyCreateDecryptedData(secKey, algorithm, blockData as CFData, &error) else {
            throw RSAError.decryptionFailed
        }
        
        // 将解密后的块添加到结果中
        decryptedData.append(Data(referencing: decryptedBlock))
    }
    
    // 将解密后的数据转换为字符串
    guard let result = String(data: decryptedData, encoding: .utf8) else {
        throw RSAError.dataConversionFailed
    }
    
    return result
}

// 辅助函数：计算加密块大小
func calculateEncryptionBlockSize(secKey: SecKey, fillMode: RSAFillMode, hashAlgorithm: HashAlgorithm? = nil) throws -> Int {
    // 获取密钥大小（以字节为单位）
    let keySize = SecKeyGetBlockSize(secKey)
    
    // 根据填充模式计算块大小
    switch fillMode {
    case .NoPadding:
        return keySize
    case .PKCS1Padding:
        // PKCS1填充需要至少11字节
        return keySize - 11
    case .OAEP:
        guard let hash = hashAlgorithm else {
            throw RSAError.invalidParameters
        }
        
        // 计算OAEP需要的填充大小
        // OAEP填充大小 = 2 * 哈希值长度 + 2
        let hashSize: Int
        switch hash {
        case .SHA1:
            hashSize = 20  // SHA-1哈希长度为20字节
        case .SHA256:
            hashSize = 32  // SHA-256哈希长度为32字节
        }
        
        let paddingSize = 2 * hashSize + 2
        return keySize - paddingSize
    }
}

// 辅助函数：清理PEM密钥中的头尾和换行符
func cleanPEMKey(_ key: String) -> String {
    var cleanedKey = key
        .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
        .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
        .replacingOccurrences(of: "-----BEGIN RSA PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "-----END RSA PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
        .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
        .replacingOccurrences(of: "\n", with: "")
        .replacingOccurrences(of: "\r", with: "")
        .replacingOccurrences(of: " ", with: "")
    
    return cleanedKey
}

// PKCS1/PKCS8 转换辅助函数
func convertToPKCS1PublicKey(_ keyData: Data) -> String {
    let pemHeader = "-----BEGIN RSA PUBLIC KEY-----\n"
    let pemFooter = "\n-----END RSA PUBLIC KEY-----"
    
    var keyString = keyData.base64EncodedString()
    let lines = stride(from: 0, to: keyString.count, by: 64).map {
        let startIndex = keyString.index(keyString.startIndex, offsetBy: $0)
        let endIndex = keyString.index(startIndex, offsetBy: min(64, keyString.count - $0))
        return String(keyString[startIndex..<endIndex])
    }
    keyString = lines.joined(separator: "\n")
    
    return pemHeader + keyString + pemFooter
}

func convertToPKCS1PrivateKey(_ keyData: Data) -> String {
    let pemHeader = "-----BEGIN RSA PRIVATE KEY-----\n"
    let pemFooter = "\n-----END RSA PRIVATE KEY-----"
    
    var keyString = keyData.base64EncodedString()
    let lines = stride(from: 0, to: keyString.count, by: 64).map {
        let startIndex = keyString.index(keyString.startIndex, offsetBy: $0)
        let endIndex = keyString.index(startIndex, offsetBy: min(64, keyString.count - $0))
        return String(keyString[startIndex..<endIndex])
    }
    keyString = lines.joined(separator: "\n")
    
    return pemHeader + keyString + pemFooter
}

func convertToPKCS8PublicKey(_ keyData: Data) -> String {
    let pemHeader = "-----BEGIN PUBLIC KEY-----\n"
    let pemFooter = "\n-----END PUBLIC KEY-----"
    
    var keyString = keyData.base64EncodedString()
    let lines = stride(from: 0, to: keyString.count, by: 64).map {
        let startIndex = keyString.index(keyString.startIndex, offsetBy: $0)
        let endIndex = keyString.index(startIndex, offsetBy: min(64, keyString.count - $0))
        return String(keyString[startIndex..<endIndex])
    }
    keyString = lines.joined(separator: "\n")
    
    return pemHeader + keyString + pemFooter
}

func convertToPKCS8PrivateKey(_ keyData: Data) -> String {
    let pemHeader = "-----BEGIN PRIVATE KEY-----\n"
    let pemFooter = "\n-----END PRIVATE KEY-----"
    
    var keyString = keyData.base64EncodedString()
    let lines = stride(from: 0, to: keyString.count, by: 64).map {
        let startIndex = keyString.index(keyString.startIndex, offsetBy: $0)
        let endIndex = keyString.index(startIndex, offsetBy: min(64, keyString.count - $0))
        return String(keyString[startIndex..<endIndex])
    }
    keyString = lines.joined(separator: "\n")
    
    return pemHeader + keyString + pemFooter
}

func testKeyGeneration() {
    print("\n===== 测试密钥生成 =====")
    do {
        print("生成PKCS1格式密钥对...")
        let keyPairPKCS1 = try generateRSAKeyPair(keyFormat: .PKCS1, keyLength: 2048)
        print("✅ 成功生成PKCS1格式密钥对")
        print("公钥片段: \(String(keyPairPKCS1[0].prefix(40)))...")
        print("私钥片段: \(String(keyPairPKCS1[1].prefix(40)))...")
        
        print("\n生成PKCS8格式密钥对...")
        let keyPairPKCS8 = try generateRSAKeyPair(keyFormat: .PKCS8, keyLength: 2048)
        print("✅ 成功生成PKCS8格式密钥对")
        print("公钥片段: \(String(keyPairPKCS8[0].prefix(40)))...")
        print("私钥片段: \(String(keyPairPKCS8[1].prefix(40)))...")
    } catch {
        print("❌ 密钥生成失败: \(error)")
    }
}

func testEncryptionDecryption() {
    print("\n===== 测试加密解密 =====")
    do {
        // 生成密钥对
        let keyPair = try generateRSAKeyPair(keyFormat: .PKCS1, keyLength: 2048)
        let publicKey = keyPair[0]
        let privateKey = keyPair[1]
        
        // 测试数据
        let testData = "这是一个测试字符串，用于RSA加密解密验证"
        print("原始数据: \"\(testData)\"")
        
        // PKCS1Padding模式测试
        print("\n>> 测试PKCS1Padding模式:")
        let encryptedPKCS1 = try rsaPublicEncrypt(
            data: testData,
            publicKey: publicKey,
            encryptMode: .ECB,
            fillMode: .PKCS1Padding,
            hashAlgorithm: nil,
            mgfHashAlgorithm: nil
        )
        print("加密后数据: \(encryptedPKCS1.prefix(40))...")
        
        let decryptedPKCS1 = try rsaPrivateDecrypt(
            data: encryptedPKCS1,
            privateKey: privateKey,
            encryptMode: .ECB,
            fillMode: .PKCS1Padding,
            hashAlgorithm: nil,
            mgfHashAlgorithm: nil
        )
        print("解密后数据: \"\(decryptedPKCS1)\"")
        print("解密是否成功: \(decryptedPKCS1 == testData ? "✅" : "❌")")
        
        // OAEP模式测试
        print("\n>> 测试OAEP-SHA256模式:")
        let encryptedOAEP = try rsaPublicEncrypt(
            data: testData,
            publicKey: publicKey,
            encryptMode: .ECB,
            fillMode: .OAEP,
            hashAlgorithm: .SHA256,
            mgfHashAlgorithm: .SHA1
        )
        print("加密后数据: \(encryptedOAEP.prefix(40))...")
        
        let decryptedOAEP = try rsaPrivateDecrypt(
            data: encryptedOAEP,
            privateKey: privateKey,
            encryptMode: .ECB,
            fillMode: .OAEP,
            hashAlgorithm: .SHA256,
            mgfHashAlgorithm: .SHA1
        )
        print("解密后数据: \"\(decryptedOAEP)\"")
        print("解密是否成功: \(decryptedOAEP == testData ? "✅" : "❌")")
        
    } catch {
        print("❌ 加密解密测试失败: \(error)")
    }
}

func testLongTextEncryptionDecryption() {
    print("\n===== 测试长文本分块加密解密 =====")
    do {
        // 生成密钥对
        let keyPair = try generateRSAKeyPair(keyFormat: .PKCS1, keyLength: 2048)
        let publicKey = keyPair[0]
        let privateKey = keyPair[1]
        
        // 创建一个长文本
        let longText = String(repeating: "这是一个需要被分块加密和解密的长文本。包含中文、英文 RSA encryption test with block processing. ", count: 20)
        print("原始长文本长度: \(longText.count) 字符")
        
        // 使用PKCS1Padding模式加密长文本
        print("\n>> 使用PKCS1Padding模式加密长文本:")
        let encryptedLongText = try rsaPublicEncrypt(
            data: longText,
            publicKey: publicKey,
            fillMode: .PKCS1Padding
        )
        
        // 检查是否分块（通过查找分隔符'|'）
        let blockCount = encryptedLongText.components(separatedBy: "|").count
        print("分块数量: \(blockCount)")
        print("加密数据片段: \(encryptedLongText.prefix(40))...")
        
        // 解密长文本
        let decryptedLongText = try rsaPrivateDecrypt(
            data: encryptedLongText,
            privateKey: privateKey,
            fillMode: .PKCS1Padding
        )
        
        print("解密后的文本长度: \(decryptedLongText.count) 字符")
        print("解密是否成功: \(decryptedLongText == longText ? "✅" : "❌")")
        
        // 使用OAEP-SHA256模式加密长文本
        print("\n>> 使用OAEP-SHA256模式加密长文本:")
        let encryptedLongTextOAEP256 = try rsaPublicEncrypt(
            data: longText,
            publicKey: publicKey,
            fillMode: .OAEP,
            hashAlgorithm: .SHA256
        )
        
        // 检查是否分块
        let blockCountOAEP256 = encryptedLongTextOAEP256.components(separatedBy: "|").count
        print("SHA-256分块数量: \(blockCountOAEP256)")
        print("加密数据片段: \(encryptedLongTextOAEP256.prefix(40))...")
        
        // 解密长文本
        let decryptedLongTextOAEP256 = try rsaPrivateDecrypt(
            data: encryptedLongTextOAEP256,
            privateKey: privateKey,
            fillMode: .OAEP,
            hashAlgorithm: .SHA256
        )
        
        print("解密后的文本长度: \(decryptedLongTextOAEP256.count) 字符")
        print("解密是否成功: \(decryptedLongTextOAEP256 == longText ? "✅" : "❌")")
        
        // 使用OAEP-SHA1模式加密长文本
        print("\n>> 使用OAEP-SHA1模式加密长文本:")
        let encryptedLongTextOAEP1 = try rsaPublicEncrypt(
            data: longText,
            publicKey: publicKey,
            fillMode: .OAEP,
            hashAlgorithm: .SHA1
        )
        
        // 检查是否分块
        let blockCountOAEP1 = encryptedLongTextOAEP1.components(separatedBy: "|").count
        print("SHA-1分块数量: \(blockCountOAEP1)")
        print("加密数据片段: \(encryptedLongTextOAEP1.prefix(40))...")
        
        // 解密长文本
        let decryptedLongTextOAEP1 = try rsaPrivateDecrypt(
            data: encryptedLongTextOAEP1,
            privateKey: privateKey,
            fillMode: .OAEP,
            hashAlgorithm: .SHA1
        )
        
        print("解密后的文本长度: \(decryptedLongTextOAEP1.count) 字符")
        print("解密是否成功: \(decryptedLongTextOAEP1 == longText ? "✅" : "❌")")
        
        // 比较不同哈希算法下的分块数
        if blockCountOAEP256 != blockCountOAEP1 {
            print("\n不同哈希算法下分块数不同 - SHA-256: \(blockCountOAEP256), SHA-1: \(blockCountOAEP1)")
            print("验证了哈希算法影响OAEP填充大小和分块数量 ✅")
        }
        
    } catch {
        print("❌ 长文本加密解密测试失败: \(error)")
    }
}

func testErrorHandling() {
    print("\n===== 测试错误处理 =====")
    
    // 测试无效公钥
    print("\n>> 测试无效公钥:")
    let invalidKey = "这不是一个有效的密钥"
    do {
        let _ = try rsaPublicEncrypt(
            data: "测试数据",
            publicKey: invalidKey
        )
        print("❌ 应该抛出错误但没有")
    } catch {
        print("✅ 正确抛出错误: \(error)")
    }
    
    // 测试无效的OAEP配置
    print("\n>> 测试无效的OAEP配置:")
    do {
        let keyPair = try generateRSAKeyPair()
        let _ = try rsaPublicEncrypt(
            data: "测试数据",
            publicKey: keyPair[0],
            fillMode: .OAEP,
            hashAlgorithm: nil
        )
        print("❌ 应该抛出错误但没有")
    } catch {
        print("✅ 正确抛出错误: \(error)")
    }
}

// 2. 现在编写一个简单的测试函数来替代XCTest
func runTests() {
    print("开始RSA测试...")
    
    // 测试密钥生成
    testKeyGeneration()
    
    // 测试加密解密
    testEncryptionDecryption()
    
    // 测试长文本加密解密
    testLongTextEncryptionDecryption()
    
    // 测试错误处理
    testErrorHandling()
    
    print("测试完成!")
}

// 3. 运行测试
runTests()
