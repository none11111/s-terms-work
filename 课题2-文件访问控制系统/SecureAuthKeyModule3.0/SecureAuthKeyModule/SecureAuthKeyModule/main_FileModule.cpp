#include <iostream>
#include <vector>
#include <cstdint>
// 顺序：先AccessControl，再AuditLog，避免类型未定义
#include "AccessControl.h"
#include "FileCrypto.h"
#include "AuditLog.h"

// 生成测试密钥
std::vector<uint8_t> GenTestKey()
{
    std::vector<uint8_t> key = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
    };
    return key;
}

int main()
{
    // 1. 初始化文件加密模块
    FileCrypto crypto;
    crypto.SetKey(GenTestKey());

    // 2. 初始化访问控制 & 用户角色
    AccessControl ac;
    ac.InitDefaultPerm();
    ac.AssignUserRole("admin01", ROLE_ADMIN);
    ac.AssignUserRole("editor01", ROLE_EDITOR);
    ac.AssignUserRole("viewer01", ROLE_VIEWER);
    ac.AssignUserRole("guest01", ROLE_GUEST);

    // 3. 初始化审计日志
    AuditLog log;
    log.SetLogPath("file_audit.log");

    std::string testFile = "secret.txt";
    std::string encFile = "secret.enc";
    std::string decFile = "secret_dec.txt";

    // 场景1：管理员加密文件
    std::cout << "=====管理员加密文件=====\n";
    bool encOk = crypto.EncryptFile(testFile, encFile);
    std::cout << (encOk ? "加密成功" : "加密失败") << std::endl;

    // 场景2：校验访客下载权限（应拒绝）
    AuditRecord rec;
    rec.userName = "viewer01";
    rec.filePath = encFile;
    rec.opType = OP_DOWNLOAD;
    rec.opTime = log.GetCurrentTime();
    rec.isPermit = ac.CheckPermission(rec.userName, rec.opType);
    rec.desc = "访客尝试导出保密文件";
    log.WriteLog(rec);
    std::cout << "访客下载权限：" << (rec.isPermit ? "允许" : "拒绝") << std::endl;

    // 场景3：管理员解密文件
    std::cout << "\n=====管理员解密文件=====\n";
    bool decOk = crypto.DecryptFile(encFile, decFile);
    std::cout << (decOk ? "解密成功" : "解密失败") << std::endl;

    // 场景4：管理员读取日志
    auto allLog = log.ReadAllLog();
    std::cout << "\n=====审计日志列表=====\n";
    for(auto& r : allLog)
    {
        std::cout << r.desc << std::endl;
    }

    system("pause");
    return 0;
}