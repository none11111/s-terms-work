#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// ============================================================
// 密码学工具类 - 基于 Windows CNG (bcrypt.h)
// ============================================================
class CryptoUtils {
public:
    // -------- 哈希（密码存储） --------
    // 对密码加盐后做 SHA-256 哈希，返回 "盐(16字节)+哈希(32字节)" 的二进制数据
    static std::vector<BYTE> HashPasswordWithSalt(const std::wstring& password);

    // 验证密码是否匹配给定的哈希数据
    static bool VerifyPassword(const std::wstring& password, const std::vector<BYTE>& storedHashData);

    // -------- 随机数 --------
    // 生成指定长度的随机字节（用于 FEK 和 Salt）
    static std::vector<BYTE> GenerateRandomBytes(size_t length);

    // -------- AES-256-GCM 加密/解密（用于 FEK 加密） --------
    // 用主密钥加密 FEK，输出 EFEK（包含 Nonce + Tag + CipherText）
    static bool EncryptFEK(const std::vector<BYTE>& masterKey,
        const std::vector<BYTE>& plaintextFEK,
        std::vector<BYTE>& outEFEK);

    // 用主密钥解密 EFEK，还原出 FEK
    static bool DecryptFEK(const std::vector<BYTE>& masterKey,
        const std::vector<BYTE>& EFEK,
        std::vector<BYTE>& outFEK);

    // -------- 密钥派生（从密码派生出主密钥） --------
    // 用 PBKDF2 从密码派生出 32 字节主密钥
    static std::vector<BYTE> DeriveMasterKey(const std::wstring& password, const std::vector<BYTE>& salt, int iterations = 100000);
};
