#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <string>
#include <vector>
#include <ctime>
// 引入AccessControl，拿到FileOpType枚举
#include "AccessControl.h"

// 审计日志单条记录结构体
struct AuditRecord
{
    std::string userName;       // 操作用户
    std::string filePath;       // 操作文件路径
    FileOpType opType;          // 操作类型
    std::string opTime;         // 操作时间
    bool isPermit;              // 是否允许访问
    std::string desc;           // 备注信息
};

// 文件操作审计日志模块
class AuditLog
{
public:
    // 设置日志保存路径
    void SetLogPath(const std::string& path);
    // 写入一条审计日志
    void WriteLog(const AuditRecord& record);
    // 读取全部日志（用于后台查看）
    std::vector<AuditRecord> ReadAllLog();

    // 对外获取当前时间
    std::string GetCurrentTime();

private:
    std::string m_logFile;
    // 获取当前时间字符串
    std::string GetNowTime();
    // 操作类型转文字
    std::string OpToString(FileOpType op);
};

#endif