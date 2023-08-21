# DLCryptoUtil
基于`Kotlin Multiplatform`的加密工具库，目前支持`Android`、`JVM`、`JS`平台。

*当前最新版本`0.0.5`*

## 特性说明

 - [RSA](#RSA)
 - [AES](#AES)
 - [Base64](#Base64)


### RSA
1、支持生成`PKCS#1`、`PKCS#8`格式的公钥、私钥；

2、支持加密解密格式如下：
- `RSA/None/NoPadding`
- `RSA/None/PKCS1Padding`
- `RSA/ECB/NoPadding`
- `RSA/ECB/PKCS1Padding`
- `RSA/ECB/OAEPWithSHA-1AndMGF1Padding`
- `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`

### AES
1、支持加密解密格式如下：
- `AES/CBC/PKCS7Padding`
- `AES/ECB/PKCS7Padding`

> `PKCS5Padding`在当前场景下和`PKCS7Padding`是等价的，不考虑支持。
> 
> `NoPadding`由于限制输入数据必须是`blockSize`的整数倍，使用起来比较麻烦，不考虑支持。

### Base64
1、支持`Base64`编码、解码；

## 安装与使用
> 参考`wiki`文档；