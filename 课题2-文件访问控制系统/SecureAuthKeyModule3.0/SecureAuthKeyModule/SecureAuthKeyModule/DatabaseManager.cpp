#include "pch.h"
#include "DatabaseManager.h"
#include <iostream>
#include <sstream>


DatabaseManager::DatabaseManager() : m_db(nullptr) {}

DatabaseManager::~DatabaseManager() {
    Close();
}

bool DatabaseManager::Initialize(const std::wstring& dbPath) {
    std::cout << "[����] Initialize ����������" << std::endl;
    // �����ַ�·��ת��ΪUTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, dbPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    std::string utf8Path(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, dbPath.c_str(), -1, &utf8Path[0], len, nullptr, nullptr);

    // �����ݿ�
    int rc = sqlite3_open(utf8Path.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        std::cout << "[����] �����ݿ�ʧ��: " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }

    // ---------- �����û��� ----------
    const char* createUserSQL =
        "CREATE TABLE IF NOT EXISTS users ("
        "    username TEXT PRIMARY KEY,"
        "    password_hash TEXT NOT NULL"
        ");";

    char* errMsg = nullptr;
    rc = sqlite3_exec(m_db, createUserSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[����] �����û���ʧ��: " << errMsg << std::endl;
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

    // ---------- 创建角色表 ----------
    const char* createRoleSQL =
        "CREATE TABLE IF NOT EXISTS roles ("
        "    role_name TEXT PRIMARY KEY,"
        "    description TEXT"
        ");";

    rc = sqlite3_exec(m_db, createRoleSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[错误] 创建角色表失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }

    // ---------- 创建用户角色关联表 ----------
    const char* createUserRoleSQL =
        "CREATE TABLE IF NOT EXISTS user_roles ("
        "    username TEXT,"
        "    role_name TEXT,"
        "    PRIMARY KEY (username, role_name)"
        ");";

    rc = sqlite3_exec(m_db, createUserRoleSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[错误] 创建用户角色表失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }

    // ---------- 创建文件权限表 ----------
    const char* createPermissionSQL =
        "CREATE TABLE IF NOT EXISTS file_permissions ("
        "    username TEXT,"
        "    file_id TEXT,"
        "    permission_flags INTEGER NOT NULL DEFAULT 0,"
        "    PRIMARY KEY (username, file_id)"
        ");";

    rc = sqlite3_exec(m_db, createPermissionSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[错误] 创建权限表失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }

    // ---------- 创建文件所有者表 ----------
    const char* createOwnerSQL =
        "CREATE TABLE IF NOT EXISTS file_owners ("
        "    file_id TEXT PRIMARY KEY,"
        "    username TEXT NOT NULL"
        ");";

    rc = sqlite3_exec(m_db, createOwnerSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[错误] 创建文件所有者表失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }

    // ---------- 创建审计日志表 ----------
    const char* createAuditSQL =
        "CREATE TABLE IF NOT EXISTS audit_logs ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    username TEXT NOT NULL,"
        "    action TEXT NOT NULL,"
        "    file_id TEXT,"
        "    file_path TEXT,"
        "    success INTEGER NOT NULL,"
        "    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";

    rc = sqlite3_exec(m_db, createAuditSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[错误] 创建审计日志表失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }

    // ---------- 创建USB白名单表 ----------
    const char* createUsbWhitelistSQL =
        "CREATE TABLE IF NOT EXISTS usb_whitelist ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    vid TEXT NOT NULL,"
        "    pid TEXT NOT NULL,"
        "    serial_number TEXT NOT NULL,"
        "    device_name TEXT,"
        "    authorized INTEGER DEFAULT 1,"
        "    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "    UNIQUE(vid, pid, serial_number)"
        ");";

    rc = sqlite3_exec(m_db, createUsbWhitelistSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[错误] 创建USB白名单表失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }

    // ---------- 创建USB日志表 ----------
    const char* createUsbLogsSQL =
        "CREATE TABLE IF NOT EXISTS usb_logs ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    vid TEXT NOT NULL,"
        "    pid TEXT NOT NULL,"
        "    serial_number TEXT,"
        "    device_name TEXT,"
        "    action TEXT NOT NULL,"
        "    username TEXT,"
        "    success INTEGER NOT NULL,"
        "    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";

    rc = sqlite3_exec(m_db, createUsbLogsSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        if (errMsg) {
            std::cout << "[错误] 创建USB日志表失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }

    std::cout << "[信息] 数据库初始化成功" << std::endl;
    return true;
}

bool DatabaseManager::ExecuteSQL(const std::string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        // ���������Ϣ������̨�������ã�
        if (errMsg) {
            std::cout << "[SQL����] " << errMsg << std::endl;
            std::cout << "[SQL���] " << sql << std::endl;
            sqlite3_free(errMsg);
        }
        return false;
    }
    return true;
}

bool DatabaseManager::CreateUser(const std::wstring& username, const std::wstring& passwordHash) {
    // ת�����ַ�ΪUTF-8
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

    // ʹ�ò�������ѯ����ֹSQLע�� + ��ȷ�������������ݣ�
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
            // ��UTF-8 fileIdת�ؿ��ַ�
            int wlen = MultiByteToWideChar(CP_UTF8, 0, fileId, -1, nullptr, 0);
            if (wlen > 0) {
                std::wstring wfid(wlen, 0);
                MultiByteToWideChar(CP_UTF8, 0, fileId, -1, &wfid[0], wlen);
                wfid.pop_back(); // ȥ����β��'\0'

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
    return SaveFileKey(username, fileId, newEncryptedKey);
}

bool DatabaseManager::CreateRole(const std::wstring& roleName, const std::wstring& description) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, roleName.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, description.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0) return false;

    std::string rname(len1, 0);
    WideCharToMultiByte(CP_UTF8, 0, roleName.c_str(), -1, &rname[0], len1, nullptr, nullptr);

    std::string desc = "";
    if (len2 > 0) {
        desc.resize(len2);
        WideCharToMultiByte(CP_UTF8, 0, description.c_str(), -1, &desc[0], len2, nullptr, nullptr);
    }

    std::string sql = "INSERT OR IGNORE INTO roles (role_name, description) VALUES ('" + rname + "', '" + desc + "');";
    return ExecuteSQL(sql);
}

bool DatabaseManager::AssignRole(const std::wstring& username, const std::wstring& roleName) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, roleName.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0) return false;

    std::string uname(len1, 0);
    std::string rname(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, roleName.c_str(), -1, &rname[0], len2, nullptr, nullptr);

    std::string sql = "INSERT OR IGNORE INTO user_roles (username, role_name) VALUES ('" + uname + "', '" + rname + "');";
    return ExecuteSQL(sql);
}

bool DatabaseManager::GetUserRoles(const std::wstring& username, std::vector<std::wstring>& outRoles) {
    int len = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    std::string uname(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len, nullptr, nullptr);

    std::string sql = "SELECT role_name FROM user_roles WHERE username = '" + uname + "';";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    outRoles.clear();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (role) {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, role, -1, nullptr, 0);
            if (wlen > 0) {
                std::wstring wrole(wlen, 0);
                MultiByteToWideChar(CP_UTF8, 0, role, -1, &wrole[0], wlen);
                wrole.pop_back();
                outRoles.push_back(wrole);
            }
        }
    }
    sqlite3_finalize(stmt);
    return true;
}

bool DatabaseManager::SetFilePermission(const std::wstring& username, const std::wstring& fileId, int permissionFlags) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0) return false;

    std::string uname(len1, 0);
    std::string fid(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, &fid[0], len2, nullptr, nullptr);

    std::string sql = "INSERT OR REPLACE INTO file_permissions (username, file_id, permission_flags) VALUES ('" + uname + "', '" + fid + "', " + std::to_string(permissionFlags) + ");";
    return ExecuteSQL(sql);
}

bool DatabaseManager::GetFilePermission(const std::wstring& username, const std::wstring& fileId, int& outPermissionFlags) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0) return false;

    std::string uname(len1, 0);
    std::string fid(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, &fid[0], len2, nullptr, nullptr);

    std::string sql = "SELECT permission_flags FROM file_permissions WHERE username = ? AND file_id = ?;";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, fid.c_str(), -1, SQLITE_TRANSIENT);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        outPermissionFlags = sqlite3_column_int(stmt, 0);
        found = true;
    }
    sqlite3_finalize(stmt);
    return found;
}

bool DatabaseManager::LogAudit(const std::wstring& username, const std::wstring& action,
    const std::wstring& fileId, const std::wstring& filePath, bool success) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, action.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0) return false;

    std::string uname(len1, 0);
    std::string act(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, action.c_str(), -1, &act[0], len2, nullptr, nullptr);

    std::string fid = "";
    if (!fileId.empty()) {
        int len3 = WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len3 > 0) {
            fid.resize(len3);
            WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, &fid[0], len3, nullptr, nullptr);
        }
    }

    std::string fpath = "";
    if (!filePath.empty()) {
        int len4 = WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len4 > 0) {
            fpath.resize(len4);
            WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, &fpath[0], len4, nullptr, nullptr);
        }
    }

    std::string sql = "INSERT INTO audit_logs (username, action, file_id, file_path, success) VALUES ('" + uname + "', '" + act + "', '" + fid + "', '" + fpath + "', " + (success ? "1" : "0") + ");";
    return ExecuteSQL(sql);
}

bool DatabaseManager::GetAuditLogs(const std::wstring& username, const std::wstring& action,
    std::vector<std::pair<std::wstring, std::wstring>>& outLogs) {
    int len = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    std::string uname(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len, nullptr, nullptr);

    std::string sql = "SELECT timestamp, action, file_path, success FROM audit_logs WHERE username = '" + uname + "'";
    if (!action.empty()) {
        int alen = WideCharToMultiByte(CP_UTF8, 0, action.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (alen > 0) {
            std::string act(alen, 0);
            WideCharToMultiByte(CP_UTF8, 0, action.c_str(), -1, &act[0], alen, nullptr, nullptr);
            sql += " AND action = '" + act + "'";
        }
    }
    sql += " ORDER BY timestamp DESC;";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    outLogs.clear();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* ts = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* act = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* fp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        int success = sqlite3_column_int(stmt, 3);

        if (ts && act) {
            std::wstringstream wss;
            wss << ts << " - " << act;
            if (fp) wss << " - " << fp;
            wss << " (" << (success ? "成功" : "失败") << ")";
            
            int wlen = MultiByteToWideChar(CP_UTF8, 0, wss.str().c_str(), -1, nullptr, 0);
            if (wlen > 0) {
                std::wstring entry(wlen, 0);
                MultiByteToWideChar(CP_UTF8, 0, wss.str().c_str(), -1, &entry[0], wlen);
                entry.pop_back();
                outLogs.push_back({ uname, entry });
            }
        }
    }
    sqlite3_finalize(stmt);
    return true;
}

bool DatabaseManager::SetFileOwner(const std::wstring& fileId, const std::wstring& username) {
    int len1 = WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, nullptr, 0, nullptr, nullptr);
    int len2 = WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len1 <= 0 || len2 <= 0) return false;

    std::string fid(len1, 0);
    std::string uname(len2, 0);
    WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, &fid[0], len1, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, username.c_str(), -1, &uname[0], len2, nullptr, nullptr);

    std::string sql = "INSERT OR REPLACE INTO file_owners (file_id, username) VALUES ('" + fid + "', '" + uname + "');";
    return ExecuteSQL(sql);
}

bool DatabaseManager::GetFileOwner(const std::wstring& fileId, std::wstring& outUsername) {
    int len = WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    std::string fid(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, fileId.c_str(), -1, &fid[0], len, nullptr, nullptr);

    std::string sql = "SELECT username FROM file_owners WHERE file_id = '" + fid + "';";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (username) {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, username, -1, nullptr, 0);
            if (wlen > 0) {
                outUsername.resize(wlen);
                MultiByteToWideChar(CP_UTF8, 0, username, -1, &outUsername[0], wlen);
                outUsername.pop_back();
                found = true;
            }
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

void DatabaseManager::Close() {
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}