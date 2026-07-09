#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

class DatabaseManager;

enum class Permission {
    NONE = 0,
    READ = 1,
    WRITE = 2,
    MODIFY = 4,
    DELETE = 8,
    DOWNLOAD = 16,
    ALL = 31
};

enum class Role {
    ADMIN,
    USER,
    READER,
    GUEST
};

class AccessControl {
public:
    AccessControl();
    ~AccessControl();

    bool Initialize(DatabaseManager* dbManager);

    bool CreateRole(const std::wstring& roleName, const std::wstring& description);
    bool AssignRole(const std::wstring& username, const std::wstring& roleName);
    bool GetUserRoles(const std::wstring& username, std::vector<std::wstring>& outRoles);

    bool GrantPermission(const std::wstring& username, const std::wstring& fileId, Permission permission);
    bool RevokePermission(const std::wstring& username, const std::wstring& fileId, Permission permission);
    bool CheckPermission(const std::wstring& username, const std::wstring& fileId, Permission permission);

    bool SetFileOwner(const std::wstring& username, const std::wstring& fileId);
    bool GetFileOwner(const std::wstring& fileId, std::wstring& outOwner);

private:
    DatabaseManager* m_dbManager;

    int GetRoleDefaultPermissions(const std::wstring& roleName);
    int GetPermissionFlag(Permission permission);
};