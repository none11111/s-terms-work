#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

// 补齐所有缺失头文件
#include <string>
#include <map>
#include <vector>

// 【关键】枚举放到类外面，全局可用，AuditLog/main才能识别
// 文件操作类型
enum FileOpType
{
    OP_READ,
    OP_WRITE,
    OP_MODIFY,
    OP_DOWNLOAD
};

// RBAC角色定义
enum RoleType
{
    ROLE_ADMIN,    // 管理员：全部权限
    ROLE_EDITOR,   // 编辑：读写，禁止导出下载
    ROLE_VIEWER,   // 访客：仅读取
    ROLE_GUEST     // 游客：无权限
};

// 访问控制类：判定用户对文件的操作权限
class AccessControl
{
public:
    // 加载权限配置（本地文件持久化角色权限）
    bool LoadRoleConfig(const std::string& cfgPath);
    // 保存权限配置
    bool SaveRoleConfig(const std::string& cfgPath);

    // 给用户分配角色
    void AssignUserRole(const std::string& userName, RoleType r);
    // 校验：用户是否允许对目标文件执行操作
    bool CheckPermission(const std::string& userName, FileOpType op);

    // 获取角色名称，用于日志打印
    std::string GetRoleName(RoleType r);

    // 移到public，main可调用
    void InitDefaultPerm();

private:
    // 用户-角色映射
    std::map<std::string, RoleType> m_userRoleMap;
    // 角色-允许操作集合
    std::map<RoleType, std::vector<FileOpType>> m_rolePerm;
};

#endif