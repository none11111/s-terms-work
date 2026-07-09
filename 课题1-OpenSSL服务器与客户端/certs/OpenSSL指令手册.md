# OpenSSL常用指令手册

## 一、概述

本文档整理了OpenSSL的常用命令，用于证书管理、加密解密、SSL测试等操作。

## 二、环境配置

### 2.1 检查OpenSSL版本

```bash
openssl version
```

### 2.2 设置环境变量

```bash
set OPENSSL_CONF=openssl.cnf
```

## 三、证书管理指令

### 3.1 生成RSA私钥

```bash
# 生成2048位私钥
openssl genrsa -out key.pem 2048

# 生成带密码保护的私钥
openssl genrsa -des3 -out key.pem 2048

# 生成4096位私钥（更高安全级别）
openssl genrsa -out key.pem 4096
```

### 3.2 生成证书请求(CSR)

```bash
# 生成证书请求
openssl req -new -key key.pem -out csr.pem

# 指定主题信息（免交互）
openssl req -new -key key.pem -out csr.pem -subj "/CN=example.com/O=MyOrg/C=CN"

# 生成CSR时包含SAN（Subject Alternative Name）
openssl req -new -key key.pem -out csr.pem -subj "/CN=example.com" -addext "subjectAltName = DNS:example.com, DNS:www.example.com"
```

### 3.3 签发证书

#### 3.3.1 自签名证书（用于CA根证书）

```bash
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=MyCA/O=Information Security/C=CN"
```

#### 3.3.2 CA签发服务器证书

```bash
# 使用CA根证书签发
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# 签发时添加扩展信息
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -extfile openssl.cnf -extensions v3_req
```

#### 3.3.3 签发客户端证书

```bash
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

### 3.4 查看证书信息

```bash
# 查看证书详细信息
openssl x509 -in cert.crt -text -noout

# 查看证书有效期
openssl x509 -in cert.crt -dates -noout

# 查看证书指纹
openssl x509 -in cert.crt -fingerprint -noout

# 查看证书主题和签发者
openssl x509 -in cert.crt -subject -issuer -noout
```

### 3.5 验证证书

```bash
# 验证证书是否由CA签发
openssl verify -CAfile ca.crt server.crt

# 验证证书链
openssl verify -CAfile ca.crt -untrusted intermediate.crt server.crt

# 详细验证
openssl verify -verbose -CAfile ca.crt server.crt
```

### 3.6 证书格式转换

```bash
# PEM转DER
openssl x509 -in cert.pem -outform der -out cert.der

# DER转PEM
openssl x509 -in cert.der -inform der -out cert.pem

# PEM转PKCS12（包含证书和私钥）
openssl pkcs12 -export -in cert.pem -inkey key.pem -out cert.p12

# PKCS12转PEM
openssl pkcs12 -in cert.p12 -out cert.pem -nodes
```

### 3.7 证书吊销列表(CRL)

```bash
# 生成CRL
openssl ca -gencrl -out crl.pem -crldays 30

# 查看CRL内容
openssl crl -in crl.pem -text -noout

# 吊销证书
openssl ca -revoke cert.pem -keyfile ca.key -cert ca.crt
```

### 3.8 私钥操作

```bash
# 查看私钥信息
openssl rsa -in key.pem -text -noout

# 检查私钥完整性
openssl rsa -in key.pem -check

# 移除私钥密码
openssl rsa -in key.pem -out key_nopass.pem

# 为私钥添加密码
openssl rsa -in key.pem -des3 -out key_encrypted.pem

# 提取公钥
openssl rsa -in key.pem -pubout -out pubkey.pem
```

## 四、加密解密指令

### 4.1 对称加密

```bash
# AES-256-CBC加密文件
openssl enc -aes-256-cbc -salt -in plain.txt -out cipher.txt

# AES-256-CBC解密文件
openssl enc -aes-256-cbc -d -in cipher.txt -out plain.txt

# 使用指定密钥和IV加密
openssl enc -aes-256-cbc -salt -in plain.txt -out cipher.txt -K <key> -iv <iv>

# AES-256-GCM加密（AEAD模式）
openssl enc -aes-256-gcm -salt -in plain.txt -out cipher.txt
```

### 4.2 非对称加密

```bash
# 使用公钥加密
openssl rsautl -encrypt -in plain.txt -out cipher.txt -inkey pubkey.pem -pubin

# 使用私钥解密
openssl rsautl -decrypt -in cipher.txt -out plain.txt -inkey key.pem

# 签名
openssl rsautl -sign -in data.txt -out signature.txt -inkey key.pem

# 验证签名
openssl rsautl -verify -in signature.txt -inkey pubkey.pem -pubin
```

### 4.3 哈希算法

```bash
# SHA256哈希
openssl dgst -sha256 file.txt

# SHA512哈希
openssl dgst -sha512 file.txt

# MD5哈希（不推荐用于安全场景）
openssl dgst -md5 file.txt

# 生成哈希文件
openssl dgst -sha256 file.txt > hash.txt

# 验证哈希
openssl dgst -sha256 -verify pubkey.pem -signature signature.bin data.txt
```

## 五、SSL测试指令

### 5.1 SSL客户端测试

```bash
# 连接SSL服务器
openssl s_client -connect example.com:443

# 使用CA证书验证
openssl s_client -connect example.com:443 -CAfile ca.crt

# 显示详细信息
openssl s_client -connect example.com:443 -debug

# 指定协议版本
openssl s_client -connect example.com:443 -tls1_2

# 查看服务器支持的加密套件
openssl s_client -connect example.com:443 -cipher 'ALL'

# 测试双向认证
openssl s_client -connect example.com:443 -cert client.crt -key client.key -CAfile ca.crt
```

### 5.2 SSL服务端测试

```bash
# 启动简单的SSL服务器
openssl s_server -cert cert.crt -key key.pem

# 指定端口
openssl s_server -cert cert.crt -key key.pem -accept 4433

# 要求客户端证书
openssl s_server -cert cert.crt -key key.pem -CAfile ca.crt -Verify 1
```

### 5.3 加密套件相关

```bash
# 列出所有支持的加密套件
openssl ciphers

# 列出特定协议的加密套件
openssl ciphers -tls1_2

# 查看套件详细信息
openssl ciphers -v

# 使用特定套件列表
openssl ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256'
```

## 六、证书生成完整流程

### 6.1 生成CA根证书

```bash
# 步骤1：生成CA私钥
openssl genrsa -out ca.key 2048

# 步骤2：生成CA根证书（自签名）
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=MyCA/O=Information Security/C=CN"
```

### 6.2 生成服务器证书

```bash
# 步骤1：生成服务器私钥
openssl genrsa -out server.key 2048

# 步骤2：生成服务器证书请求
openssl req -new -key server.key -out server.csr -subj "/CN=localhost/O=Server/C=CN"

# 步骤3：CA签发服务器证书
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
```

### 6.3 生成客户端证书

```bash
# 步骤1：生成客户端私钥
openssl genrsa -out client.key 2048

# 步骤2：生成客户端证书请求
openssl req -new -key client.key -out client.csr -subj "/CN=client/O=Client/C=CN"

# 步骤3：CA签发客户端证书
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

## 七、故障排查

### 7.1 常见错误及解决方案

| 错误信息 | 原因 | 解决方案 |
| :--- | :--- | :--- |
| `openssl: command not found` | 环境变量未配置 | 添加OpenSSL路径到PATH |
| `unable to load Private Key` | 私钥文件损坏或权限错误 | 检查文件完整性和权限 |
| `self signed certificate` | 使用自签名证书 | 正常现象，确保CA证书正确配置 |
| `certificate verify failed` | 证书链不完整 | 确保CA证书正确加载 |
| `protocol version mismatch` | 协议版本不兼容 | 使用兼容的协议版本 |
| `handshake failure` | 加密套件不匹配 | 检查加密套件配置 |
| `permission denied` | 文件权限不足 | 修改文件权限为600 |
| `common name mismatch` | 证书CN与域名不匹配 | 使用正确的域名生成证书 |
| `certificate has expired` | 证书已过期 | 重新签发证书 |

### 7.2 调试命令

```bash
# 详细调试SSL连接
openssl s_client -connect localhost:443 -CAfile ca.crt -debug

# 查看SSL连接信息
openssl s_client -connect localhost:443 -CAfile ca.crt -status

# 检查证书链
openssl verify -CAfile ca.crt -show_chain server.crt

# 查看OpenSSL配置
openssl version -a
```

## 八、安全最佳实践

### 8.1 密钥管理

1. 使用至少2048位的RSA密钥（推荐4096位）
2. 私钥文件权限设置为600（仅限所有者读写）
3. 定期轮换密钥（建议每90-180天）
4. 使用硬件安全模块(HSM)存储敏感私钥

### 8.2 证书管理

1. 设置合理的证书有效期（建议1年以内）
2. 使用SHA256或更高的哈希算法
3. 确保证书CN与服务器域名一致
4. 及时吊销过期或泄露的证书

### 8.3 加密套件选择

推荐使用的加密套件：
- ECDHE-RSA-AES256-GCM-SHA384
- ECDHE-RSA-AES128-GCM-SHA256
- ECDHE-ECDSA-AES256-GCM-SHA384
- ECDHE-ECDSA-AES128-GCM-SHA256

避免使用的加密套件：
- 包含MD5或SHA1的套件
- 使用RC4的套件
- 使用DES或3DES的套件

## 九、参考资料

- OpenSSL官方文档：https://www.openssl.org/docs/
- OpenSSL命令手册：https://www.openssl.org/docs/man1.1.1/man1/
- SSL/TLS最佳实践：https://cheatsheetseries.owasp.org/cheatsheets/TLS_Chestnut.html