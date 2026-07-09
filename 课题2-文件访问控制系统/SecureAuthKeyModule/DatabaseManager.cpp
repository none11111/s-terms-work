#include "pch.h"
#include "DatabaseManager.h"
#include <iostream>
#include <sstream>


DatabaseManager::DatabaseManager() : m_db(nullptr) {}

DatabaseManager::~DatabaseManager() {
    Close();
}

bool DatabaseManager::Initialize(const std::wstring& dbPath) {
    std::cout << "[调试] Initialize 函数被调用" << std::endl;
    // 将宽字符路径转换为UTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, dbPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    std::string utf8Path(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, dbPath.c_str(), -1, &utf8Path[0], len, nullptr, nullptr);

    // 打开数据库
    int rc = sqlite3_open(utf8Path.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        std::cout << "[错误] 打开数据库失败: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }

    // ---------- 创建用户表 ----------
    const char* createUserSQL =
        "CREATE TABLE IF NOT EXISTS users ("
        "    username TEXT PRIMARY KEY,"
        "    password_hash TEXT NOT NULL"
        ");";

    char* errMsg = nullptr;
    rc = sqlite3_exec(m_db, createUserSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[错误] 创建用户表失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }

    // ---------- 创建密钥表 ----------
    const char* createKeySQL =
        "CREATE TABLE IF NOT EXISTS file_keys ("
        "    username TEXT,"
        "    file_id TEXT,"
        "    encrypted_key BLOB NOT NULL,"
        "    PRIMARY KEY (username, file_id)"
        ");";

    rc = sqlite3_exec(m_db, createKeySQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[错误] 创建密钥表失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }

    std::cout << "[调试] 数据库表创建成功" << std::endl;
    return true;
}

bool DatabaseManager::ExecuteSQL(const std::string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        // 输出错误信息到控制台（调试用）
        if (errMsg) {
            std::cout << "[SQL错误] " << errMsg << std::endl;
            std::cout << "[SQL语句] " << sql << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }
    return true;
}

bool DatabaseManager::CreateUser(const std::wstring& username, const std::wstring& passwordHash) {
    // 转换宽字符为UTF-8
    int len1 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, passwordHash.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0) return false;

    std::string uname(len1, 0);
    std::string pwdHash(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, passwordHash.c_str(), -1, &pwdHash[0], len2, nullptr, nullptr);

    std::string sql = "INSERT INTO users (username, password_hash) VALUES ('" + uname + "', '" + pwdHash + "');";
    return ExecuteSQL(sql);
}

bool DatabaseManager::FindUser(const std::wstring& username, std::string& outPasswordHash) {
    int len = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    std::string uname(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len, nullptr, nullptr);

    std::string sql = "SELECT password_hash FROM users WHERE username = '" + uname + "';";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (hash) {
            outPasswordHash = hash;
            found = true;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

bool DatabaseManager::UpdatePassword(const std::wstring& username, const std::wstring& newPasswordHash) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, newPasswordHash.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0) return false;

    std::string uname(len1, 0);
    std::string pwdHash(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, newPasswordHash.c_str(), -1, &pwdHash[0], len2, nullptr, nullptr);

    std::string sql = "UPDATE users SET password_hash = '" + pwdHash + "' WHERE username = '" + uname + "';";
    return ExecuteSQL(sql);
}

bool DatabaseManager::SaveFileKey(const std::wstring& username, const std::wstring& fileId, const std::vector<BYTE>& encryptedKey) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0 || encryptedKey.empty()) return false;

    std::string uname(len1, 0);
    std::string fid(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, &fid[0], len2, nullptr, nullptr);

    // 使用参数化查询（防止SQL注入 + 正确处理二进制数据）
    std::string sql = "INSERT OR REPLACE INTO file_keys (username, file_id, encrypted_key) VALUES (?, ?, ?);";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, fid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, encryptedKey.data(), (int)encryptedKey.size(), SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool DatabaseManager::LoadFileKey(const std::wstring& username, const std::wstring& fileId, std::vector<BYTE>& outEncryptedKey) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0) return false;

    std::string uname(len1, 0);
    std::string fid(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, &fid[0], len2, nullptr, nullptr);

    std::string sql = "SELECT encrypted_key FROM file_keys WHERE username = ? AND file_id = ?;";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, fid.c_str(), -1, SQLITE_TRANSIENT);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(stmt, 0);
        int size = sqlite3_column_bytes(stmt, 0);
        if (blob && size > 0) {
            outEncryptedKey.resize(size);
            memcpy(outEncryptedKey.data(), blob, size);
            found = true;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

bool DatabaseManager::DeleteFileKey(const std::wstring& username, const std::wstring& fileId) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0) return false;

    std::string uname(len1, 0);
    std::string fid(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, &fid[0], len2, nullptr, nullptr);

    std::string sql = "DELETE FROM file_keys WHERE username = '" + uname + "' AND file_id = '" + fid + "';";
    return ExecuteSQL(sql);
}

bool DatabaseManager::GetAllFileKeys(const std::wstring& username, std::vector<std::pair<std::wstring, std::vector<BYTE>>>& outKeys) {
    int len = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    std::string uname(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len, nullptr, nullptr);

    std::string sql = "SELECT file_id, encrypted_key FROM file_keys WHERE username = '" + uname + "';";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    outKeys.clear();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* fileId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const void* blob = sqlite3_column_blob(stmt, 1);
        int size = sqlite3_column_bytes(stmt, 1);

        if (fileId && blob && size > 0) {
            // 将UTF-8 fileId转回宽字符
            int wlen = MultiByteToWideChar(CP_UTF8, 0, fileId, -1, nullptr, 0);
            if (wlen > 0) {
                std::wstring wfid(wlen, 0);
                MultiByteToWideChar(CP_UTF8, 0, fileId, -1, &wfid[0], wlen);
                wfid.pop_back(); // 去掉结尾的'\0'

                std::vector<BYTE> key(size);
                memcpy(key.data(), blob, size);
                outKeys.push_back({ wfid, key });
            }
        }
    }
    sqlite3_finalize(stmt);
    return true;
}

bool DatabaseManager::UpdateFileKey(const std::wstring& username, const std::wstring& fileId, const std::vector<BYTE>& newEncryptedKey) {
    // 直接用 SaveFileKey 覆盖
    return SaveFileKey(username, fileId, newEncryptedKey);
}

void DatabaseManager::Close() {
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}