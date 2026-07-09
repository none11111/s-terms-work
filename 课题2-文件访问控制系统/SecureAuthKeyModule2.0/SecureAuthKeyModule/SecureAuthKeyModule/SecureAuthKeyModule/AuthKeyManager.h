#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

class DatabaseManager;

class AuthKeyManager {
public:
    AuthKeyManager();
    ~AuthKeyManager();

    bool Initialize(const std::wstring& dbPath);

    bool RegisterUser(const std::wstring& username, const std::wstring& password);
    bool Login(const std::wstring& username, const std::wstring& password);
    void Logout();
    bool ChangePassword(const std::wstring& username,
        const std::wstring& oldPassword,
        const std::wstring& newPassword);
    std::wstring GetCurrentUsername() const;

    bool CreateFileKey(const std::wstring& fileId, std::vector<BYTE>& outFEK);
    bool GetFileKey(const std::wstring& fileId, std::vector<BYTE>& outFEK);
    bool DeleteFileKey(const std::wstring& fileId);
    bool RotateAllKeys(const std::wstring& username, const std::wstring& newPassword);

    static void SecureZeroMemory(BYTE* buffer, size_t size);
    DatabaseManager* GetDBManager() { return m_db.get(); }

private:
    std::vector<BYTE> DeriveMasterKeyFromPassword(const std::wstring& password);

    std::unique_ptr<DatabaseManager> m_db;
    std::wstring m_currentUser;
    std::vector<BYTE> m_masterKey;
    bool m_isLoggedIn;
};