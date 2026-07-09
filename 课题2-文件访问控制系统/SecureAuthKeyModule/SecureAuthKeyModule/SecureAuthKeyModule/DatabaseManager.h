#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include "sqlite3.h"

class DatabaseManager {
public:
    DatabaseManager();
    ~DatabaseManager();

    bool Initialize(const std::wstring& dbPath);

    bool CreateUser(const std::wstring& username, const std::wstring& passwordHash);
    bool FindUser(const std::wstring& username, std::string& outPasswordHash);
    bool UpdatePassword(const std::wstring& username, const std::wstring& newPasswordHash);

    bool SaveFileKey(const std::wstring& username, const std::wstring& fileId, const std::vector<BYTE>& encryptedKey);
    bool LoadFileKey(const std::wstring& username, const std::wstring& fileId, std::vector<BYTE>& outEncryptedKey);
    bool DeleteFileKey(const std::wstring& username, const std::wstring& fileId);
    bool GetAllFileKeys(const std::wstring& username, std::vector<std::pair<std::wstring, std::vector<BYTE>>>& outKeys);
    bool UpdateFileKey(const std::wstring& username, const std::wstring& fileId, const std::vector<BYTE>& newEncryptedKey);

    bool CreateRole(const std::wstring& roleName, const std::wstring& description);
    bool AssignRole(const std::wstring& username, const std::wstring& roleName);
    bool GetUserRoles(const std::wstring& username, std::vector<std::wstring>& outRoles);
    bool SetFilePermission(const std::wstring& username, const std::wstring& fileId, int permissionFlags);
    bool GetFilePermission(const std::wstring& username, const std::wstring& fileId, int& outPermissionFlags);

    bool LogAudit(const std::wstring& username, const std::wstring& action,
                  const std::wstring& fileId, const std::wstring& filePath, bool success);
    bool GetAuditLogs(const std::wstring& username, const std::wstring& action,
                      std::vector<std::pair<std::wstring, std::wstring>>& outLogs);

    bool SetFileOwner(const std::wstring& fileId, const std::wstring& username);
    bool GetFileOwner(const std::wstring& fileId, std::wstring& outUsername);

    void Close();

    sqlite3* GetDBHandle() { return m_db; }

private:
    sqlite3* m_db;
    bool ExecuteSQL(const std::string& sql);
};