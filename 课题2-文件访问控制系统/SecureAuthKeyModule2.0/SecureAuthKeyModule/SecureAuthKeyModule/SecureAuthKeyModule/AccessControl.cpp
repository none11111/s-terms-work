#include "pch.h"
#include "AccessControl.h"
#include "DatabaseManager.h"

AccessControl::AccessControl() : m_dbManager(nullptr) {}

AccessControl::~AccessControl() {}

bool AccessControl::Initialize(DatabaseManager* dbManager) {
    if (!dbManager) {
        return false;
    }
    m_dbManager = dbManager;

    m_dbManager->CreateRole(L"ADMIN", L"管理员，拥有所有权限");
    m_dbManager->CreateRole(L"USER", L"普通用户，拥有读写权限");
    m_dbManager->CreateRole(L"READER", L"只读用户，仅拥有读取权限");
    m_dbManager->CreateRole(L"GUEST", L"访客，权限受限");

    return true;
}

int AccessControl::GetPermissionFlag(Permission permission) {
    return static_cast<int>(permission);
}

int AccessControl::GetRoleDefaultPermissions(const std::wstring& roleName) {
    if (roleName == L"ADMIN") {
        return static_cast<int>(Permission::ALL);
    }
    else if (roleName == L"USER") {
        return static_cast<int>(Permission::READ) |
               static_cast<int>(Permission::WRITE) |
               static_cast<int>(Permission::MODIFY) |
               static_cast<int>(Permission::DOWNLOAD);
    }
    else if (roleName == L"READER") {
        return static_cast<int>(Permission::READ);
    }
    else if (roleName == L"GUEST") {
        return static_cast<int>(Permission::READ);
    }
    return static_cast<int>(Permission::NONE);
}

bool AccessControl::CreateRole(const std::wstring& roleName, const std::wstring& description) {
    if (!m_dbManager || roleName.empty()) {
        return false;
    }
    return m_dbManager->CreateRole(roleName, description);
}

bool AccessControl::AssignRole(const std::wstring& username, const std::wstring& roleName) {
    if (!m_dbManager || username.empty() || roleName.empty()) {
        return false;
    }
    return m_dbManager->AssignRole(username, roleName);
}

bool AccessControl::GetUserRoles(const std::wstring& username, std::vector<std::wstring>& outRoles) {
    if (!m_dbManager || username.empty()) {
        return false;
    }
    return m_dbManager->GetUserRoles(username, outRoles);
}

bool AccessControl::GrantPermission(const std::wstring& username, const std::wstring& fileId, Permission permission) {
    if (!m_dbManager || username.empty() || fileId.empty()) {
        return false;
    }

    int currentFlags = 0;
    m_dbManager->GetFilePermission(username, fileId, currentFlags);

    int newFlags = currentFlags | GetPermissionFlag(permission);
    return m_dbManager->SetFilePermission(username, fileId, newFlags);
}

bool AccessControl::RevokePermission(const std::wstring& username, const std::wstring& fileId, Permission permission) {
    if (!m_dbManager || username.empty() || fileId.empty()) {
        return false;
    }

    int currentFlags = 0;
    m_dbManager->GetFilePermission(username, fileId, currentFlags);

    int newFlags = currentFlags & ~GetPermissionFlag(permission);
    return m_dbManager->SetFilePermission(username, fileId, newFlags);
}

bool AccessControl::CheckPermission(const std::wstring& username, const std::wstring& fileId, Permission permission) {
    if (!m_dbManager || username.empty() || fileId.empty()) {
        return false;
    }

    std::wstring owner;
    if (m_dbManager->GetFileOwner(fileId, owner)) {
        if (username == owner) {
            return true;
        }
    }

    int permissionFlags = 0;
    bool hasDirectPermission = m_dbManager->GetFilePermission(username, fileId, permissionFlags);

    if (hasDirectPermission && (permissionFlags & GetPermissionFlag(permission)) != 0) {
        return true;
    }

    std::vector<std::wstring> roles;
    if (!m_dbManager->GetUserRoles(username, roles)) {
        return false;
    }

    for (const std::wstring& role : roles) {
        int rolePermissions = GetRoleDefaultPermissions(role);
        if ((rolePermissions & GetPermissionFlag(permission)) != 0) {
            return true;
        }
    }

    return false;
}

bool AccessControl::SetFileOwner(const std::wstring& username, const std::wstring& fileId) {
    if (!m_dbManager || username.empty() || fileId.empty()) {
        return false;
    }

    if (!m_dbManager->SetFileOwner(fileId, username)) {
        return false;
    }

    return GrantPermission(username, fileId, Permission::ALL);
}

bool AccessControl::GetFileOwner(const std::wstring& fileId, std::wstring& outOwner) {
    if (!m_dbManager || fileId.empty()) {
        return false;
    }

    return m_dbManager->GetFileOwner(fileId, outOwner);
}