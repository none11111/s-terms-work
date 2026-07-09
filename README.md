# 小学期课程设计

两个课题：OpenSSL服务器与客户端、文件访问控制系统

---

## 项目概述

本课程设计包含两个安全系统项目：

| 课题 | 目录 | 岗位 | 技术栈 |
| :--- | :--- | :--- | :--- |
| **课题1：OpenSSL服务器与客户端** | `课题1-OpenSSL服务器与客户端/` | 岗位1（环境搭建与证书管理）、岗位4（SSL双向认证与安全增强） | Python、OpenSSL |
| **课题2：文件访问控制系统** | `课题2-文件访问控制系统/` | 安全认证与密钥管理模块 | C++、Windows CNG、SQLite |

---

## 课题1：OpenSSL服务器与客户端

### 功能简介

实现基于OpenSSL的SSL/TLS服务器与客户端通信系统，包含：

- **TCP基础通信**：纯TCP连接的客户端和服务器
- **单向SSL认证**：服务器端SSL认证，客户端验证服务器证书
- **双向SSL认证**：服务器和客户端相互认证，增强通信安全性
- **证书管理**：CA根证书、服务器证书、客户端证书的生成和管理
- **安全增强**：数据完整性校验、密码套件切换、连接过滤、审计日志

### 快速开始

```bash
# 1. 生成证书
cd 课题1-OpenSSL服务器与客户端/certs
generate_certs.bat

# 2. 启动双向认证服务器
cd ..
run_ssl_mutual_server.bat

# 3. 启动双向认证客户端（另一个终端）
run_ssl_mutual_client.bat
```

### 文档

- [课题1 README](课题1-OpenSSL服务器与客户端/README.md)
- [课题1 实验报告](课题1-OpenSSL服务器与客户端/实验报告.md)

---

## 课题2：文件访问控制系统

### 功能简介

实现基于角色的文件访问控制系统，提供完整的安全认证和密钥管理功能：

- **用户认证**：安全的用户注册、登录、登出和密码管理
- **密钥管理**：文件加密密钥的创建、存储、获取和轮换
- **文件安全**：文件级加密解密（AES算法）
- **访问控制**：基于角色的权限管理（RBAC）
- **审计日志**：完整的操作记录和查询
- **USB管控**：USB设备白名单管理和事件监控

### 项目版本

| 版本 | 目录 | 说明 |
| :--- | :--- | :--- |
| v1.0 | `SecureAuthKeyModule/` | 基础版本，核心认证和密钥管理 |
| v2.0 | `SecureAuthKeyModule2.0/` | 添加文件安全、访问控制、审计日志、USB管控 |
| v3.0 | `SecureAuthKeyModule3.0/` | 优化版本，推荐使用 |

### 快速开始

```bash
# 1. 打开项目（推荐v3.0）
# 打开: 课题2-文件访问控制系统/SecureAuthKeyModule3.0/SecureAuthKeyModule/SecureAuthKeyModule/SecureAuthKeyModule.sln

# 2. 编译项目（Visual Studio 2022）
# Ctrl+Shift+B 或 右键项目 → 生成

# 3. 运行测试程序
cd 课题2-文件访问控制系统/SecureAuthKeyModule3.0/SecureAuthKeyModule/SecureAuthKeyModule/x64/Debug
TestAuthKey.exe
```

### 文档

- [课题2 README](课题2-文件访问控制系统/README.md)
- [课题2 实验报告](课题2-文件访问控制系统/实验报告.md)
- [课题2 需求规格说明书](课题2-文件访问控制系统/需求规格说明书.md)
- [v3.0 设计文档](课题2-文件访问控制系统/SecureAuthKeyModule3.0/设计文档.md)

---

## 项目结构

```
新建文件夹 (3)/
├── README.md                              # 本文件
├── 课题1-OpenSSL服务器与客户端/           # OpenSSL服务器与客户端
│   ├── certs/                             # 证书目录
│   │   ├── generate_certs.bat            # 证书生成脚本
│   │   ├── openssl.cnf                   # OpenSSL配置文件
│   │   └── OpenSSL指令手册.md            # OpenSSL指令说明
│   ├── src/                              # 源代码
│   │   ├── tcp_server/client.py          # TCP通信
│   │   ├── ssl_server/client_oneway.py   # SSL单向认证
│   │   └── ssl_server/client_mutual.py   # SSL双向认证
│   ├── run_*.bat                         # 运行脚本
│   ├── README.md                         # 课题1 README
│   └── 实验报告.md                       # 课题1 实验报告
└── 课题2-文件访问控制系统/               # 文件访问控制系统
    ├── SecureAuthKeyModule3.0/           # v3.0版本（推荐）
    │   ├── SecureAuthKeyModule/
    │   │   └── SecureAuthKeyModule/
    │   │       ├── *.h/cpp               # 源代码文件
    │   │       ├── SecureAuthKeyModule.sln  # VS解决方案
    │   │       └── x64/Debug/            # 编译输出
    │   └── 设计文档.md                    # v3.0设计文档
    ├── SecureAuthKeyModule2.0/           # v2.0版本
    ├── SecureAuthKeyModule/              # v1.0版本
    ├── README.md                         # 课题2 README
    ├── 实验报告.md                       # 课题2 实验报告
    └── 需求规格说明书.md                 # 课题2 需求规格说明书
```

---

## 技术栈汇总

| 课题 | 语言 | 框架/库 | 平台 |
| :--- | :--- | :--- | :--- |
| 课题1 | Python 3.x | OpenSSL, socket, ssl | Windows/Linux |
| 课题2 | C++17 | Windows CNG (bcrypt.lib), SQLite | Windows |

---

## 安全特性对比

| 安全特性 | 课题1 | 课题2 |
| :--- | :--- | :--- |
| **身份认证** | SSL证书双向认证 | 用户名+密码认证 |
| **数据加密** | SSL/TLS传输加密 | AES文件加密 |
| **密钥管理** | 证书密钥管理 | 文件加密密钥(FEK)管理 |
| **访问控制** | IP/证书黑名单 | RBAC角色权限管理 |
| **审计日志** | 连接和操作日志 | 文件操作审计日志 |
| **完整性校验** | SHA256哈希校验 | 文件内容验证 |

---

## 运行环境要求

### 课题1

- Python 3.6+
- OpenSSL（Windows版需配置环境变量）

### 课题2

- Visual Studio 2022
- Windows 10/11（64位）
- Visual C++ Redistributable（vcruntime140.dll等）

---

## 使用建议

1. **先运行课题1**：理解SSL/TLS协议和证书管理
2. **再运行课题2**：理解文件安全和访问控制
3. **查看实验报告**：了解详细的实现原理和测试结果
4. **参考设计文档**：了解系统架构和模块设计

---

## 许可证

本项目仅供学习和研究使用。