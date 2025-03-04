# DLCryptoUtil

基于`Kotlin Multiplatform`的加密工具库，目前支持`Android`、`JVM`、`JS`、`iOS`平台

[![Kotlin](https://img.shields.io/badge/Kotlin-Multiplatform-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white)](https://kotlinlang.org/docs/multiplatform.html)
[![Build Status](https://img.shields.io/github/workflow/status/D10NGYANG/DLCryptoUtil/Build/main?style=for-the-badge)](https://github.com/D10NGYANG/DLCryptoUtil)

![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)
![JVM](https://img.shields.io/badge/JVM-007396?style=for-the-badge&logo=java&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![iOS](https://img.shields.io/badge/iOS-000000?style=for-the-badge&logo=ios&logoColor=white)

[![Version](https://img.shields.io/badge/Version-0.2.1-blue?style=for-the-badge)](https://github.com/D10NGYANG/DLCryptoUtil/releases)

## 特性说明

 - 🔐 [RSA](#RSA)
 - 🔒 [AES](#AES)
 - 📝 [Base64](#Base64)
 - 🔑 [MD5](#MD5)


### RSA
1、支持生成`PKCS#1`、`PKCS#8`格式的公钥、私钥；

2、支持加密解密格式如下：
- `RSA/None/NoPadding`
- `RSA/None/PKCS1Padding`
- `RSA/ECB/NoPadding`
- `RSA/ECB/PKCS1Padding`
- `RSA/ECB/OAEPWithSHA-1AndMGF1Padding`
- `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`

> `iOS`端原生不支持`PKCS#8`格式的私钥，需要使用`PKCS#1`格式的私钥进行解密。

### AES
1、支持加密解密格式如下：
- `AES/CBC/PKCS7Padding`
- `AES/ECB/PKCS7Padding`

> `PKCS5Padding`在当前场景下和`PKCS7Padding`是等价的，不考虑支持。
> 
> `NoPadding`由于限制输入数据必须是`blockSize`的整数倍，使用起来比较麻烦，不考虑支持。

### Base64
1、支持`Base64`编码、解码；

### MD5
1、支持`MD5`加密；

## 安装与使用
> 参考`wiki`文档；

## 性能测试
选择`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`进行1000并发私钥解密测试，测试结果如下：
- `M1 Pro`: 0.25秒；
- `阿里云 ecs.c7.4xlarge`: 约6秒；