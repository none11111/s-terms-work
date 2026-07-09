#include "pch.h"
#include "AuthKeyManager.h"
#include "DatabaseManager.h"
#include "CryptoUtils.h"
#include <iostream>
#include <sstream>

// ============================================================
// 常量
// ============================================================
const size_t MASTER_KEY_SIZE = 32;  // 主密钥大小（AES-256）

// ============================================================
// 构造 / 析构
// ============================================================
AuthKeyManager::AuthKeyManager()
    : m_db(std::make_unique<DatabaseManager>())
    , m_isLoggedIn(false) {
}

AuthKeyManager::~AuthKeyManager() {
    Logout();
}

// ============================================================
// 初始化
// ============================================================
bool AuthKeyManager::Initialize(const std::wstring& dbPath) {
    return m_db->Initialize(dbPath);
}

// ============================================================
// 用户认证接口
// ============================================================
bool AuthKeyManager::RegisterUser(const std::wstring& username, const std::wstring& password) {
    if (username.empty() || password.empty()) {
        return false;
    }

    // 检查用户是否已存在
    std::string existingHash;
    if (m_db->FindUser(username, existingHash)) {
        return false;  // 用户已存在
    }

    // 对密码加盐哈希
    std::vector<BYTE> hashData = CryptoUtils::HashPasswordWithSalt(password);
    if (hashData.empty()) {
        return false;
    }

    // 将哈希数据转为十六进制字符串存库
    std::stringstream ss;
    for (BYTE b : hashData) {
        char hex[3] = { 0 };
        sprintf_s(hex, sizeof(hex), "%02x", b);
        ss << hex;
    }
    std::string hashHex = ss.str();

    // 转为宽字符存储
    int len = MultiByteToWideChar(CP_UTF8, 0, hashHex.c_str(), -1, nullptr, 0);
    if (len <= 0) return false;
    std::wstring hashWide(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, hashHex.c_str(), -1, &hashWide[0], len);
    hashWide.pop_back(); // 去掉结尾的 '\0'

    return m_db->CreateUser(username, hashWide);
}

bool AuthKeyManager::Login(const std::wstring& username, const std::wstring& password) {
    if (username.empty() || password.empty()) {
        return false;
    }

    // 如果已登录，先登出
    if (m_isLoggedIn) {
        Logout();
    }

    // 从数据库获取存储的哈希
    std::string storedHashHex;
    if (!m_db->FindUser(username, storedHashHex)) {
        return false;  // 用户不存在
    }

    // 将十六进制字符串转回二进制
    std::vector<BYTE> storedHashData;
    if (storedHashHex.length() % 2 != 0) return false;
    storedHashData.reserve(storedHashHex.length() / 2);
    for (size_t i = 0; i < storedHashHex.length(); i += 2) {
        std::string byteStr = storedHashHex.substr(i, 2);
        BYTE byte = static_cast<BYTE>(std::stoi(byteStr, nullptr, 16));
        storedHashData.push_back(byte);
    }

    // 验证密码
    if (!CryptoUtils::VerifyPassword(password, storedHashData)) {
        return false;
    }

    // ----- 登录成功 -----
    // 1. 生成主密钥（内存中）
    m_masterKey = DeriveMasterKeyFromPassword(password);
    if (m_masterKey.size() != MASTER_KEY_SIZE) {
        return false;
    }

    // 2. 缓存用户信息
    m_currentUser = username;
    m_isLoggedIn = true;

    return true;
}

void AuthKeyManager::Logout() {
    if (m_isLoggedIn) {
        // 清除内存中的主密钥
        if (!m_masterKey.empty()) {
            SecureZeroMemory(m_masterKey.data(), m_masterKey.size());
            m_masterKey.clear();
        }
        m_currentUser.clear();
        m_isLoggedIn = false;
    }
}

bool AuthKeyManager::ChangePassword(const std::wstring& username,
    const std::wstring& oldPassword,
    const std::wstring& newPassword) {
    if (username.empty() || oldPassword.empty() || newPassword.empty()) {
        return false;
    }

    // 先验证旧密码（使用现有登录逻辑）
    if (!Login(username, oldPassword)) {
        return false;
    }

    // 执行密钥轮换（用新密码重新加密所有文件密钥）
    if (!RotateAllKeys(username, newPassword)) {
        return false;
    }

    // 对新密码加盐哈希
    std::vector<BYTE> hashData = CryptoUtils::HashPasswordWithSalt(newPassword);
    if (hashData.empty()) return false;

    std::stringstream ss;
    for (BYTE b : hashData) {
        char hex[3] = { 0 };
        sprintf_s(hex, sizeof(hex), "%02x", b);
        ss << hex;
    }
    std::string hashHex = ss.str();

    int len = MultiByteToWideChar(CP_UTF8, 0, hashHex.c_str(), -1, nullptr, 0);
    if (len <= 0) return false;
    std::wstring hashWide(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, hashHex.c_str(), -1, &hashWide[0], len);
    hashWide.pop_back();

    // 更新数据库中的密码哈希
    if (!m_db->UpdatePassword(username, hashWide)) {
        return false;
    }

    // 更新当前用户主密钥
    m_masterKey = DeriveMasterKeyFromPassword(newPassword);

    return true;
}

std::wstring AuthKeyManager::GetCurrentUsername() const {
    return m_currentUser;
}

// ============================================================
// 密钥管理接口
// ============================================================
bool AuthKeyManager::CreateFileKey(const std::wstring& fileId, std::vector<BYTE>& outFEK) {
    if (!m_isLoggedIn) {
        return false;
    }
    if (fileId.empty()) {
        return false;
    }

    // 1. 生成随机的 FEK（AES-256 密钥，32字节）
    std::vector<BYTE> fek = CryptoUtils::GenerateRandomBytes(32);
    if (fek.size() != 32) {
        return false;
    }

    // 2. 用主密钥加密 FEK，得到 EFEK
    std::vector<BYTE> efek;
    if (!CryptoUtils::EncryptFEK(m_masterKey, fek, efek)) {
        return false;
    }

    // 3. 存储 EFEK 到数据库
    if (!m_db->SaveFileKey(m_currentUser, fileId, efek)) {
        return false;
    }

    // 4. 返回明文 FEK（给岗位3用于实际加解密）
    outFEK = fek;
    return true;
}

bool AuthKeyManager::GetFileKey(const std::wstring& fileId, std::vector<BYTE>& outFEK) {
    if (!m_isLoggedIn) {
        return false;
    }
    if (fileId.empty()) {
        return false;
    }

    // 1. 从数据库加载 EFEK
    std::vector<BYTE> efek;
    if (!m_db->LoadFileKey(m_currentUser, fileId, efek)) {
        return false;
    }

    // 2. 用主密钥解密 EFEK，得到 FEK
    std::vector<BYTE> fek;
    if (!CryptoUtils::DecryptFEK(m_masterKey, efek, fek)) {
        return false;
    }

    outFEK = fek;
    return true;
}

bool AuthKeyManager::DeleteFileKey(const std::wstring& fileId) {
    if (!m_isLoggedIn) {
        return false;
    }
    if (fileId.empty()) {
        return false;
    }

    return m_db->DeleteFileKey(m_currentUser, fileId);
}

bool AuthKeyManager::RotateAllKeys(const std::wstring& username, const std::wstring& newPassword) {
    if (username.empty() || newPassword.empty()) {
        return false;
    }

    // 1. 获取该用户所有文件密钥（EFEK列表）
    std::vector<std::pair<std::wstring, std::vector<BYTE>>> allKeys;
    if (!m_db->GetAllFileKeys(username, allKeys)) {
        return false;
    }

    // 2. 用旧主密钥解密所有 EFEK → 得到所有 FEK
    // 然后用新主密钥重新加密所有 FEK → 得到新的 EFEK
    // 再存回数据库

    std::vector<BYTE> oldMasterKey = m_masterKey;  // 当前主密钥（旧密码派生）

    // 用新密码派生新主密钥
    std::vector<BYTE> newMasterKey = DeriveMasterKeyFromPassword(newPassword);
    if (newMasterKey.size() != MASTER_KEY_SIZE) {
        return false;
    }

    // 遍历所有密钥
    for (auto& pair : allKeys) {
        const std::wstring& fileId = pair.first;
        std::vector<BYTE>& oldEFEK = pair.second;

        // 解密旧 EFEK → FEK
        std::vector<BYTE> fek;
        if (!CryptoUtils::DecryptFEK(oldMasterKey, oldEFEK, fek)) {
            continue;  // 跳过解密失败的（实际产品应记录日志）
        }

        // 用新主密钥重新加密 FEK → 新 EFEK
        std::vector<BYTE> newEFEK;
        if (!CryptoUtils::EncryptFEK(newMasterKey, fek, newEFEK)) {
            continue;
        }

        // 更新数据库
        m_db->UpdateFileKey(username, fileId, newEFEK);

        // 清除内存中的 FEK
        SecureZeroMemory(fek.data(), fek.size());
    }

    // 清除旧主密钥
    SecureZeroMemory(oldMasterKey.data(), oldMasterKey.size());

    return true;
}

// ============================================================
// 安全工具
// ============================================================
void AuthKeyManager::SecureZeroMemory(BYTE* buffer, size_t size) {
    if (buffer && size > 0) {
        // 使用 Windows API 安全清零（不会被编译器优化掉）
        SecureZeroMemory(buffer, size);
    }
}

// ============================================================
// 私有辅助函数
// ============================================================
std::vector<BYTE> AuthKeyManager::DeriveMasterKeyFromPassword(const std::wstring& password) {
    // 固定盐（演示用），实际产品应为每个用户生成随机盐并存储
    std::vector<BYTE> fixedSalt = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    // 使用 10000 次迭代派生主密钥
    return CryptoUtils::DeriveMasterKey(password, fixedSalt, 10000);
}