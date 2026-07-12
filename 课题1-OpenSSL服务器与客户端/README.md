# OpenSSL服务器与客户端

信息系统安全课程设计 - 岗位1（环境搭建与证书管理）和岗位4（SSL双向认证与安全增强）

---

## 项目简介

本项目实现了基于OpenSSL的SSL/TLS服务器与客户端通信系统，包含以下功能（分片虚拟机，需合成，地址：通过网盘分享的文件：
链接: https://pan.baidu.com/s/1bOtbPdcaGJ2Ky26hNU6woQ?pwd=qzwy 提取码: qzwy 复制这段内容后打开百度网盘手机App，操作更方便哦）：

- **TCP基础通信**：纯TCP连接的客户端和服务器
- **单向SSL认证**：服务器端SSL认证，客户端验证服务器证书
- **双向SSL认证**：服务器和客户端相互认证，增强通信安全性
- **证书管理**：CA根证书、服务器证书、客户端证书的生成和管理
- **安全增强**：数据完整性校验、密码套件切换、连接过滤、审计日志

---

## 技术栈

| 技术 | 说明 |
| :--- | :--- |
| Python | 3.x |
| OpenSSL | 证书生成和SSL协议支持 |
| socket | 网络通信 |
| ssl | Python标准库SSL支持 |

---

## 目录结构

```
课题1-OpenSSL服务器与客户端/
├── certs/                    # 证书目录
│   ├── generate_certs.bat    # 证书生成脚本
│   ├── openssl.cnf           # OpenSSL配置文件
│   └── OpenSSL指令手册.md    # OpenSSL指令说明
├── src/                      # 源代码目录
│   ├── tcp_server.py         # TCP服务器（无SSL）
│   ├── tcp_client.py         # TCP客户端（无SSL）
│   ├── ssl_server_oneway.py  # SSL单向认证服务器
│   ├── ssl_client_oneway.py  # SSL单向认证客户端
│   ├── ssl_server_mutual.py  # SSL双向认证服务器
│   └── ssl_client_mutual.py  # SSL双向认证客户端
├── run_*.bat                 # 运行脚本
└── 实验报告.md               # 实验报告
```

---

## 快速开始

### 1. 环境准备

```bash
# 安装Python依赖
pip install pyopenssl
```

### 2. 生成证书

进入 `certs/` 目录，运行证书生成脚本：

```bash
cd certs
generate_certs.bat
```

生成的证书文件：

| 文件 | 说明 |
| :--- | :--- |
| `ca.crt` | CA根证书 |
| `ca.key` | CA私钥 |
| `server.crt` | 服务器证书 |
| `server.key` | 服务器私钥 |
| `client.crt` | 客户端证书 |
| `client.key` | 客户端私钥 |
| `crl.pem` | 证书吊销列表 |

### 3. 运行服务器

```bash
# TCP服务器
run_tcp_server.bat

# SSL单向认证服务器
run_ssl_oneway_server.bat

# SSL双向认证服务器
run_ssl_mutual_server.bat
```

### 4. 运行客户端

```bash
# TCP客户端
run_tcp_client.bat

# SSL单向认证客户端
run_ssl_oneway_client.bat

# SSL双向认证客户端
run_ssl_mutual_client.bat
```

---

## 功能特性

### TCP基础通信

- 纯TCP连接，无加密
- 客户端发送消息，服务器回显
- 支持多线程并发连接

### SSL单向认证

- 服务器启用SSL，客户端验证服务器证书
- 使用CA根证书验证服务器身份
- 通信数据加密传输

### SSL双向认证

- 服务器验证客户端证书
- 客户端验证服务器证书
- 支持密码套件协商
- 数据完整性校验（SHA256）
- 连接过滤（IP黑名单、证书黑名单）
- 审计日志记录

---

## 安全增强功能

| 功能 | 实现方式 |
| :--- | :--- |
| **数据完整性** | SHA256哈希校验 |
| **密码套件切换** | 支持多种密码套件协商 |
| **IP黑名单** | 阻止恶意IP连接 |
| **证书黑名单** | 阻止吊销证书连接 |
| **审计日志** | 记录所有连接和操作 |

---

## 配置说明

### OpenSSL配置文件 (`openssl.cnf`)

配置CA证书颁发机构参数，包括：
- 证书有效期
- 密钥长度
- 主题信息
- CRL配置

### 密码套件

服务器支持的密码套件：
- ECDHE-RSA-AES256-GCM-SHA384
- ECDHE-RSA-AES128-GCM-SHA256
- DHE-RSA-AES256-GCM-SHA384
- DHE-RSA-AES128-GCM-SHA256
- RSA-AES256-GCM-SHA384

### 日志配置

日志文件存储在 `logs/` 目录：
- `server.log`：服务器日志
- `client.log`：客户端日志

---

## 使用示例

### 双向认证流程

1. **启动服务器**：
   ```bash
   run_ssl_mutual_server.bat
   ```

2. **启动客户端**：
   ```bash
   run_ssl_mutual_client.bat
   ```

3. **发送消息**：
   ```
   输入消息: Hello, Secure SSL!
   ```

4. **服务器响应**：
   - 验证客户端证书
   - 计算消息完整性哈希
   - 返回响应消息和哈希值

---

## 实验报告

详细实验报告请参考：[实验报告.md](实验报告.md)

---

## 许可证

本项目仅供学习和研究使用。
