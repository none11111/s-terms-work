# 文件访问控制系统

信息系统安全课程设计 - SecureAuthKeyModule安全认证与密钥管理模块

---

## 项目简介

本项目实现了一个基于角色的文件访问控制系统，提供完整的安全认证和密钥管理功能：

- **用户认证**：安全的用户注册、登录、登出和密码管理
- **密钥管理**：文件加密密钥的创建、存储、获取和轮换
- **文件安全**：文件级加密解密（AES算法）
- **访问控制**：基于角色的权限管理（RBAC）
- **审计日志**：完整的操作记录和查询
- **USB管控**：USB设备白名单管理和事件监控

---

## 技术栈

| 技术 | 说明 |
| :--- | :--- |
| C++ | 开发语言（C++17） |
| Visual Studio | 2022 |
| Windows CNG | 密码学API（bcrypt.lib） |
| SQLite | 嵌入式数据库 |

---

## 项目版本

| 版本 | 目录 | 说明 |
| :--- | :--- | :--- |
| v1.0 | `SecureAuthKeyModule/` | 基础版本，核心认证和密钥管理 |
| v2.0 | `SecureAuthKeyModule2.0/` | 添加文件安全、访问控制、审计日志、USB管控 |
| v3.0 | `SecureAuthKeyModule3.0/` | 优化版本，使用FileCrypto替代FileSecurity |

**推荐使用v3.0版本**。

---

## 目录结构

```
课题2-文件访问控制系统/
├── SecureAuthKeyModule3.0/           # v3.0版本（推荐）
│   ├── SecureAuthKeyModule/
│   │   └── SecureAuthKeyModule/
│   │       ├── AuthKeyManager.h/cpp     # 用户认证和密钥管理
│   │       ├── CryptoUtils.h/cpp        # 密码学工具
│   │       ├── DatabaseManager.h/cpp    # 数据库操作
│   │       ├── FileCrypto.h/cpp         # 文件加解密
│   │       ├── AccessControl.h/cpp      # 访问控制
│   │       ├── AuditLog.h/cpp           # 审计日志
│   │       ├── UsbManager.h/cpp         # USB管控
│   │       ├── sqlite3.c/sqlite3.h      # SQLite数据库
│   │       ├── main.cpp                 # 测试程序
│   │       ├── SecureAuthKeyModule.sln  # VS解决方案
│   │       └── x64/Debug/               # 编译输出
│   │           ├── TestAuthKey.exe      # 测试程序
│   │           └── SecureAuthKeyModule.dll  # DLL文件
│   └── 设计文档.md                      # 设计文档
├── SecureAuthKeyModule2.0/           # v2.0版本
├── SecureAuthKeyModule/              # v1.0版本
├── 实验报告.md                        # 实验报告
├── 需求规格说明书.md                  # 需求规格说明书
└── README.md                          # 本文件
```

---

## 快速开始

### 1. 编译项目

1. 打开 `SecureAuthKeyModule3.0/SecureAuthKeyModule/SecureAuthKeyModule/SecureAuthKeyModule.sln`
2. 选择 x64 平台和 Debug 配置
3. 右键点击项目 → **生成** 或按 `Ctrl+Shift+B`

### 2. 运行测试

编译成功后，运行测试程序：

```bash
cd SecureAuthKeyModule3.0/SecureAuthKeyModule/SecureAuthKeyModule/x64/Debug
TestAuthKey.exe
```

### 3. 测试内容

测试程序包含以下测试用例：

| 测试模块 | 测试内容 |
| :--- | :--- |
| 用户认证 | 注册、登录、错误密码、登出 |
| 密钥管理 | 创建、获取、删除文件密钥 |
| 文件加密 | 文件加密、解密、内容验证 |
| 访问控制 | 角色分配、权限检查（允许/拒绝） |
| 审计日志 | 日志记录、读取 |
| USB管控 | 白名单管理、设备授权验证 |
| 端到端 | 完整流程测试 |

---

## 核心模块

### AuthKeyManager

用户认证和密钥管理的统一接口：

- `RegisterUser()` - 用户注册
- `Login()` - 用户登录
- `Logout()` - 用户登出
- `CreateFileKey()` - 创建文件密钥
- `GetFileKey()` - 获取文件密钥
- `RotateAllKeys()` - 密钥轮换

### CryptoUtils

密码学工具函数：

- `HashPasswordWithSalt()` - SHA256加盐哈希
- `VerifyPassword()` - 密码验证
- `GenerateRandomBytes()` - 随机数生成
- `EncryptFEK()` / `DecryptFEK()` - AES-256-GCM加密解密

### FileCrypto

文件级加密解密：

- `EncryptFile()` - 加密文件
- `DecryptFile()` - 解密文件
- 使用AES-128算法

### AccessControl

基于角色的访问控制：

| 角色 | 权限 |
| :--- | :--- |
| ROLE_ADMIN | 全部权限（读/写/修改/下载） |
| ROLE_EDITOR | 读写修改，禁止下载 |
| ROLE_VIEWER | 仅读取 |
| ROLE_GUEST | 无权限 |

### AuditLog

操作审计日志：

- `WriteLog()` - 写入日志
- `ReadAllLog()` - 读取日志
- 日志格式：时间|用户名|操作类型|文件路径|允许/拒绝|备注

### UsbManager

USB设备管控：

- `AddToWhitelist()` - 添加白名单
- `IsDeviceAuthorized()` - 设备授权验证
- `StartUsbMonitoring()` - 启动监控
- 支持恶意设备检测（VID/PID为0xFFFF）

---

## 安全特性

| 安全措施 | 实现方式 |
| :--- | :--- |
| **密码安全** | SHA256加盐哈希存储 |
| **主密钥保护** | 仅在内存中临时存储，登出时安全清除 |
| **FEK加密** | AES-256-GCM加密存储 |
| **密钥轮换** | 修改密码时重新加密所有文件密钥 |
| **访问控制** | RBAC角色权限管理 |
| **审计日志** | 完整操作记录 |
| **USB管控** | 白名单机制 + 恶意设备检测 |

---

## 数据库设计

数据库包含以下表：

| 表名 | 说明 |
| :--- | :--- |
| `users` | 用户信息 |
| `file_keys` | 文件加密密钥 |
| `roles` | 角色定义 |
| `user_roles` | 用户角色关联 |
| `file_permissions` | 文件权限 |
| `file_owners` | 文件所有者 |
| `audit_logs` | 审计日志 |
| `usb_whitelist` | USB白名单 |
| `usb_logs` | USB事件日志 |

---

## 文档

| 文档 | 路径 |
| :--- | :--- |
| 实验报告 | [实验报告.md](实验报告.md) |
| 需求规格说明书 | [需求规格说明书.md](需求规格说明书.md) |
| v3.0设计文档 | [SecureAuthKeyModule3.0/设计文档.md](SecureAuthKeyModule3.0/设计文档.md) |

---

## 许可证

本项目仅供学习和研究使用。