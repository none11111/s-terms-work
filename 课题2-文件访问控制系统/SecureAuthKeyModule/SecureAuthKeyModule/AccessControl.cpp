#include "AccessControl.h"
#include <fstream>
#include <sstream>

void AccessControl::InitDefaultPerm()
{
    // 管理员全部权限
    m_rolePerm[ROLE_ADMIN] = {OP_READ, OP_WRITE, OP_MODIFY, OP_DOWNLOAD};
    // 编辑仅读写修改
    m_rolePerm[ROLE_EDITOR] = {OP_READ, OP_WRITE, OP_MODIFY};
    // 访客只读
    m_rolePerm[ROLE_VIEWER] = {OP_READ};
    // 游客无权限
    m_rolePerm[ROLE_GUEST] = {};
}

bool AccessControl::LoadRoleConfig(const std::string& cfgPath)
{
    InitDefaultPerm();
    std::ifstream fin(cfgPath);
    if(!fin.is_open()) return false;
    std::string line;
    while(std::getline(fin, line))
    {
        std::istringstream iss(line);
        std::string user; int rid;
        iss >> user >> rid;
        m_userRoleMap[user] = (RoleType)rid;
    }
    fin.close();
    return true;
}

bool AccessControl::SaveRoleConfig(const std::string& cfgPath)
{
    std::ofstream fout(cfgPath);
    if(!fout.is_open()) return false;
    for(auto& pair : m_userRoleMap)
    {
        fout << pair.first << " " << (int)pair.second << std::endl;
    }
    fout.close();
    return true;
}

void AccessControl::AssignUserRole(const std::string& userName, RoleType r)
{
    m_userRoleMap[userName] = r;
}

bool AccessControl::CheckPermission(const std::string& userName, FileOpType op)
{
    if(m_userRoleMap.find(userName) == m_userRoleMap.end())
        return false;
    RoleType r = m_userRoleMap[userName];
    auto& ops = m_rolePerm[r];
    for(auto o : ops)
    {
        if(o == op) return true;
    }
    return false;
}

std::string AccessControl::GetRoleName(RoleType r)
{
    switch(r)
    {
        case ROLE_ADMIN: return "管理员";
        case ROLE_EDITOR: return "编辑员";
        case ROLE_VIEWER: return "浏览者";
        case ROLE_GUEST: return "访客";
        default: return "未知角色";
    }
}