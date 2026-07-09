#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

class DatabaseManager;

enum class FileAction {
    READ,
    WRITE,
    MODIFY,
    DELETE,
    DOWNLOAD,
    ENCRYPT,
    DECRYPT,
    PERMISSION_CHANGE,
    LOGIN,
    LOGOUT
};

class AuditLogger {
public:
    AuditLogger();
    ~AuditLogger();

    bool Initialize(DatabaseManager* dbManager);

    bool LogAction(const std::wstring& username, FileAction action,
                   const std::wstring& fileId, const std::wstring& filePath, bool success);

    bool GetLogsByUser(const std::wstring& username,
                       std::vector<std::pair<std::wstring, std::wstring>>& outLogs);

    bool GetLogsByAction(const std::wstring& username, FileAction action,
                         std::vector<std::pair<std::wstring, std::wstring>>& outLogs);

    bool GetRecentLogs(int count, std::vector<std::pair<std::wstring, std::wstring>>& outLogs);

private:
    DatabaseManager* m_dbManager;

    std::wstring ActionToString(FileAction action);
    FileAction StringToAction(const std::wstring& actionStr);
};