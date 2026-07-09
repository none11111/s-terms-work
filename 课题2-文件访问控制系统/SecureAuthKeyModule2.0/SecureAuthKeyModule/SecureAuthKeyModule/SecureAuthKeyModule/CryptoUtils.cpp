#include "pch.h"
#include <ntstatus.h>
#include "CryptoUtils.h"
#include <vector>
#include <string>
#include <bcrypt.h>
#include <random>
#include <chrono>

#pragma comment(lib, "bcrypt.lib")

// ============================================================
// 常量定义
// ============================================================
const size_t SALT_SIZE = 16;      // 盐长度（字节）
const size_t HASH_SIZE = 32;      // SHA-256 输出长度
const size_t FEK_SIZE = 32;       // AES-256 密钥长度
const size_t GCM_NONCE_SIZE = 12; // GCM 推荐 Nonce 长度
const size_t GCM_TAG_SIZE = 16;   // GCM 认证标签长度

// ============================================================
// 实现
// ============================================================

std::vector<BYTE> CryptoUtils::GenerateRandomBytes(size_t length) {
    std::vector<BYTE> buffer(length);

    // 使用 Windows CNG 生成随机数
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        // 降级：使用 C++ 标准随机数（仅作 fallback，生产环境应使用 CNG）
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<int> dis(0, 255);
        for (size_t i = 0; i < length; i++) {
            buffer[i] = static_cast<BYTE>(dis(gen));
        }
        return buffer;
    }

    BCryptGenRandom(hAlg, buffer.data(), (ULONG)buffer.size(), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return buffer;
}

std::vector<BYTE> CryptoUtils::HashPasswordWithSalt(const std::wstring& password) {
    // 1. 生成 16 字节随机盐
    std::vector<BYTE> salt = GenerateRandomBytes(SALT_SIZE);

    // 2. 将密码转为 UTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string passwordUtf8(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, &passwordUtf8[0], len, nullptr, nullptr);

    // 3. 拼接：盐 + 密码
    std::vector<BYTE> combined;
    combined.reserve(salt.size() + passwordUtf8.size());
    combined.insert(combined.end(), salt.begin(), salt.end());
    combined.insert(combined.end(), passwordUtf8.begin(), passwordUtf8.end());

    // 4. SHA-256 哈希
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        return {};
    }

    BYTE hash[HASH_SIZE] = { 0 };
    ULONG hashLen = 0;
    BCryptHashData(hAlg, combined.data(), (ULONG)combined.size(), 0);
    BCryptFinishHash(hAlg, hash, HASH_SIZE, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // 5. 返回 "盐 + 哈希"（共 48 字节）
    std::vector<BYTE> result;
    result.reserve(SALT_SIZE + HASH_SIZE);
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), hash, hash + HASH_SIZE);
    return result;
}

bool CryptoUtils::VerifyPassword(const std::wstring& password, const std::vector<BYTE>& storedHashData) {
    if (storedHashData.size() != SALT_SIZE + HASH_SIZE) {
        return false;
    }

    // 1. 提取盐（前16字节）
    std::vector<BYTE> salt(storedHashData.begin(), storedHashData.begin() + SALT_SIZE);

    // 2. 将密码转为 UTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    std::string passwordUtf8(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, &passwordUtf8[0], len, nullptr, nullptr);

    // 3. 拼接：盐 + 密码
    std::vector<BYTE> combined;
    combined.reserve(salt.size() + passwordUtf8.size());
    combined.insert(combined.end(), salt.begin(), salt.end());
    combined.insert(combined.end(), passwordUtf8.begin(), passwordUtf8.end());

    // 4. SHA-256 哈希
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        return false;
    }

    BYTE hash[HASH_SIZE] = { 0 };
    BCryptHashData(hAlg, combined.data(), (ULONG)combined.size(), 0);
    BCryptFinishHash(hAlg, hash, HASH_SIZE, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // 5. 比较哈希（后32字节）
    return memcmp(hash, storedHashData.data() + SALT_SIZE, HASH_SIZE) == 0;
}

std::vector<BYTE> CryptoUtils::DeriveMasterKey(const std::wstring& password, const std::vector<BYTE>& salt, int iterations) {
    // 使用 PBKDF2 从密码派生出 32 字节主密钥
    // Windows CNG 不直接提供 PBKDF2，此处使用简单方案：
    // 实际项目中应使用 BCryptKeyDerivation 或第三方库

    // 作为课程设计简化方案：使用 SHA-256 对 "密码 + 盐" 重复迭代
    // 注意：这只是简化版，正式产品应使用真正的 PBKDF2

    if (salt.size() < 16) return {};

    // 将密码转为 UTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string passwordUtf8(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, &passwordUtf8[0], len, nullptr, nullptr);

    std::vector<BYTE> current;
    current.reserve(passwordUtf8.size() + salt.size());
    current.insert(current.end(), passwordUtf8.begin(), passwordUtf8.end());
    current.insert(current.end(), salt.begin(), salt.end());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        return {};
    }

    BYTE hash[HASH_SIZE] = { 0 };
    for (int i = 0; i < iterations; i++) {
        BCryptHashData(hAlg, current.data(), (ULONG)current.size(), 0);
        BCryptFinishHash(hAlg, hash, HASH_SIZE, 0);
        // 将哈希结果作为下一次迭代的输入
        current.assign(hash, hash + HASH_SIZE);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // 返回 32 字节主密钥
    std::vector<BYTE> masterKey(hash, hash + HASH_SIZE);
    return masterKey;
}

bool CryptoUtils::EncryptFEK(const std::vector<BYTE>& masterKey,
    const std::vector<BYTE>& plaintextFEK,
    std::vector<BYTE>& outEFEK) {
    if (masterKey.size() != 32 || plaintextFEK.size() != 32) {
        return false;
    }

    // 生成 12 字节 Nonce
    std::vector<BYTE> nonce = GenerateRandomBytes(GCM_NONCE_SIZE);

    // 使用 Windows CNG AES-GCM 加密
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        return false;
    }

    // 设置 GCM 模式
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 创建密钥对象
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (BYTE*)masterKey.data(), (ULONG)masterKey.size(), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 准备认证信息
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (BYTE*)nonce.data();
    authInfo.cbNonce = (ULONG)nonce.size();

    // 准备输出缓冲区（密文 = 明文长度，相同）
    std::vector<BYTE> ciphertext(plaintextFEK.size());

    // 准备认证标签缓冲区
    BYTE tag[GCM_TAG_SIZE] = { 0 };
    authInfo.pbTag = tag;
    authInfo.cbTag = GCM_TAG_SIZE;

    ULONG cipherLen = 0;
    NTSTATUS status = BCryptEncrypt(hKey,
        (BYTE*)plaintextFEK.data(), (ULONG)plaintextFEK.size(),
        &authInfo, nullptr, 0,
        ciphertext.data(), (ULONG)ciphertext.size(),
        &cipherLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != STATUS_SUCCESS) {
        return false;
    }

    // 组装 EFEK = Nonce(12) + Tag(16) + Ciphertext(32)
    outEFEK.clear();
    outEFEK.reserve(GCM_NONCE_SIZE + GCM_TAG_SIZE + plaintextFEK.size());
    outEFEK.insert(outEFEK.end(), nonce.begin(), nonce.end());
    outEFEK.insert(outEFEK.end(), tag, tag + GCM_TAG_SIZE);
    outEFEK.insert(outEFEK.end(), ciphertext.begin(), ciphertext.end());

    return true;
}

bool CryptoUtils::DecryptFEK(const std::vector<BYTE>& masterKey,
    const std::vector<BYTE>& EFEK,
    std::vector<BYTE>& outFEK) {
    // 检查长度
    if (masterKey.size() != 32 || EFEK.size() < GCM_NONCE_SIZE + GCM_TAG_SIZE) {
        return false;
    }

    // 提取 Nonce、Tag、Ciphertext
    std::vector<BYTE> nonce(EFEK.begin(), EFEK.begin() + GCM_NONCE_SIZE);
    std::vector<BYTE> tag(EFEK.begin() + GCM_NONCE_SIZE,
        EFEK.begin() + GCM_NONCE_SIZE + GCM_TAG_SIZE);
    std::vector<BYTE> ciphertext(EFEK.begin() + GCM_NONCE_SIZE + GCM_TAG_SIZE, EFEK.end());

    // Windows CNG AES-GCM 解密
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        return false;
    }

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (BYTE*)masterKey.data(), (ULONG)masterKey.size(), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (BYTE*)nonce.data();
    authInfo.cbNonce = (ULONG)nonce.size();
    authInfo.pbTag = (BYTE*)tag.data();
    authInfo.cbTag = (ULONG)tag.size();

    std::vector<BYTE> plaintext(ciphertext.size());
    ULONG plainLen = 0;

    NTSTATUS status = BCryptDecrypt(hKey,
        (BYTE*)ciphertext.data(), (ULONG)ciphertext.size(),
        &authInfo, nullptr, 0,
        plaintext.data(), (ULONG)plaintext.size(),
        &plainLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != STATUS_SUCCESS) {
        return false;
    }

    outFEK = plaintext;
    return true;
}