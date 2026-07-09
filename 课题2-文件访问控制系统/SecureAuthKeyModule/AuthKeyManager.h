#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

// 前向声明
class DatabaseManager;

// ============================================================
// 认证与密钥管理核心类 - 岗位2对外统一接口
// ============================================================
class AuthKeyManager {
public:
    AuthKeyManager();
    ~AuthKeyManager();

    // -------- 初始化 --------
    // 指定数据库文件路径，初始化系统
    bool Initialize(const std::wstring& dbPath);

    // -------- 用户认证接口 --------
    // 用户注册
    bool RegisterUser(const std::wstring& username, const std::wstring& password);

    // 用户登录（成功返回 true，并缓存当前用户信息）
    bool Login(const std::wstring& username, const std::wstring& password);

    // 用户登出（清除缓存的用户信息，销毁内存中的密钥）
    void Logout();

    // 修改密码（成功后会触发密钥轮换）
    bool ChangePassword(const std::wstring& username,
        const std::wstring& oldPassword,
        const std::wstring& newPassword);

    // 获取当前登录用户
    std::wstring GetCurrentUsername() const;

    // -------- 密钥管理接口（给岗位3调用） --------
    // 为新文件生成 FEK（随机 AES-256 密钥），用当前用户主密钥加密后存储
    // 返回明文 FEK（用于实际加解密文件），同时自动存储 EFEK 到数据库
    bool CreateFileKey(const std::wstring& fileId, std::vector<BYTE>& outFEK);

    // 获取已有文件的 FEK（从数据库加载 EFEK 并解密）
    bool GetFileKey(const std::wstring& fileId, std::vector<BYTE>& outFEK);

    // 删除文件密钥（文件删除时调用）
    bool DeleteFileKey(const std::wstring& fileId);

    // 密钥轮换（内部使用，修改密码时自动调用）
    bool RotateAllKeys(const std::wstring& username, const std::wstring& newPassword);

    // -------- 安全工具 --------
    // 清除内存中的敏感数据（防止被 dump）
    static void SecureZeroMemory(BYTE* buffer, size_t size);

private:
    // 从密码生成主密钥（使用固定盐，仅用于演示）
    // 实际产品中盐应随机生成并存储
    std::vector<BYTE> DeriveMasterKeyFromPassword(const std::wstring& password);

    std::unique_ptr<DatabaseManager> m_db;
    std::wstring m_currentUser;
    std::vector<BYTE> m_masterKey;  // 当前用户主密钥（内存中，登出时清零）
    bool m_isLoggedIn;
};
