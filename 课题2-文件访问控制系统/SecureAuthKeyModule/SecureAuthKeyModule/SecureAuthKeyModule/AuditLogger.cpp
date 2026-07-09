#include "pch.h"
#include "AuditLogger.h"
#include "DatabaseManager.h"

AuditLogger::AuditLogger() : m_dbManager(nullptr) {}

AuditLogger::~AuditLogger() {}

bool AuditLogger::Initialize(DatabaseManager* dbManager) {
    if (!dbManager) {
        return false;
    }
    m_dbManager = dbManager;
    return true;
}

std::wstring AuditLogger::ActionToString(FileAction action) {
    switch (action) {
    case FileAction::READ: return L"READ";
    case FileAction::WRITE: return L"WRITE";
    case FileAction::MODIFY: return L"MODIFY";
    case FileAction::DELETE: return L"DELETE";
    case FileAction::DOWNLOAD: return L"DOWNLOAD";
    case FileAction::ENCRYPT: return L"ENCRYPT";
    case FileAction::DECRYPT: return L"DECRYPT";
    case FileAction::PERMISSION_CHANGE: return L"PERMISSION_CHANGE";
    case FileAction::LOGIN: return L"LOGIN";
    case FileAction::LOGOUT: return L"LOGOUT";
    default: return L"UNKNOWN";
    }
}

FileAction AuditLogger::StringToAction(const std::wstring& actionStr) {
    if (actionStr == L"READ") return FileAction::READ;
    if (actionStr == L"WRITE") return FileAction::WRITE;
    if (actionStr == L"MODIFY") return FileAction::MODIFY;
    if (actionStr == L"DELETE") return FileAction::DELETE;
    if (actionStr == L"DOWNLOAD") return FileAction::DOWNLOAD;
    if (actionStr == L"ENCRYPT") return FileAction::ENCRYPT;
    if (actionStr == L"DECRYPT") return FileAction::DECRYPT;
    if (actionStr == L"PERMISSION_CHANGE") return FileAction::PERMISSION_CHANGE;
    if (actionStr == L"LOGIN") return FileAction::LOGIN;
    if (actionStr == L"LOGOUT") return FileAction::LOGOUT;
    return FileAction::READ;
}

bool AuditLogger::LogAction(const std::wstring& username, FileAction action,
                           const std::wstring& fileId, const std::wstring& filePath, bool success) {
    if (!m_dbManager || username.empty()) {
        return false;
    }

    std::wstring actionStr = ActionToString(action);
    return m_dbManager->LogAudit(username, actionStr, fileId, filePath, success);
}

bool AuditLogger::GetLogsByUser(const std::wstring& username,
                                std::vector<std::pair<std::wstring, std::wstring>>& outLogs) {
    if (!m_dbManager || username.empty()) {
        return false;
    }

    return m_dbManager->GetAuditLogs(username, L"", outLogs);
}

bool AuditLogger::GetLogsByAction(const std::wstring& username, FileAction action,
                                  std::vector<std::pair<std::wstring, std::wstring>>& outLogs) {
    if (!m_dbManager || username.empty()) {
        return false;
    }

    std::wstring actionStr = ActionToString(action);
    return m_dbManager->GetAuditLogs(username, actionStr, outLogs);
}

bool AuditLogger::GetRecentLogs(int count, std::vector<std::pair<std::wstring, std::wstring>>& outLogs) {
    if (!m_dbManager || count <= 0) {
        return false;
    }

    outLogs.clear();

    std::string sql = "SELECT username, timestamp, action, file_path, success FROM audit_logs ORDER BY timestamp DESC LIMIT " + std::to_string(count) + ";";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_dbManager->GetDBHandle(), sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* uname = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* ts = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* act = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const char* fp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        int success = sqlite3_column_int(stmt, 4);

        if (uname && ts && act) {
            std::wstringstream wss;
            wss << ts << " - " << act;
            if (fp) wss << " - " << fp;
            wss << " (" << (success ? L"成功" : L"失败") << ")";

            int wlen = MultiByteToWideChar(CP_UTF8, 0, wss.str().c_str(), -1, nullptr, 0);
            if (wlen > 0) {
                std::wstring entry(wlen, 0);
                MultiByteToWideChar(CP_UTF8, 0, wss.str().c_str(), -1, &entry[0], wlen);
                entry.pop_back();

                int uwlen = MultiByteToWideChar(CP_UTF8, 0, uname, -1, nullptr, 0);
                std::wstring wuname(uwlen, 0);
                MultiByteToWideChar(CP_UTF8, 0, uname, -1, &wuname[0], uwlen);
                wuname.pop_back();

                outLogs.push_back({ wuname, entry });
            }
        }
    }
    sqlite3_finalize(stmt);
    return true;
}