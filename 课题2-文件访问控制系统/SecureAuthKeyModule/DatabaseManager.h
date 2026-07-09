#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include "sqlite3.h"

// 数据库管理类 - 负责用户表和密钥表的创建与基础操作
class DatabaseManager {
public:
    DatabaseManager();
    ~DatabaseManager();

    // 初始化数据库（创建表结构）
    bool Initialize(const std::wstring& dbPath);

    // ===== 用户表操作 =====
    bool CreateUser(const std::wstring& username, const std::wstring& passwordHash);
    bool FindUser(const std::wstring& username, std::string& outPasswordHash);
    bool UpdatePassword(const std::wstring& username, const std::wstring& newPasswordHash);

    // ===== 密钥表操作 =====
    // 存储加密后的文件密钥 (EFEK)
    bool SaveFileKey(const std::wstring& username, const std::wstring& fileId, const std::vector<BYTE>& encryptedKey);
    // 读取加密后的文件密钥 (EFEK)
    bool LoadFileKey(const std::wstring& username, const std::wstring& fileId, std::vector<BYTE>& outEncryptedKey);
    // 删除文件密钥（文件删除时调用）
    bool DeleteFileKey(const std::wstring& username, const std::wstring& fileId);
    // 获取某个用户的所有文件密钥（用于密钥轮换）
    bool GetAllFileKeys(const std::wstring& username, std::vector<std::pair<std::wstring, std::vector<BYTE>>>& outKeys);
    // 更新某个文件密钥（密钥轮换时调用）
    bool UpdateFileKey(const std::wstring& username, const std::wstring& fileId, const std::vector<BYTE>& newEncryptedKey);

    // 关闭数据库
    void Close();

private:
    sqlite3* m_db;
    bool ExecuteSQL(const std::string& sql);
};
