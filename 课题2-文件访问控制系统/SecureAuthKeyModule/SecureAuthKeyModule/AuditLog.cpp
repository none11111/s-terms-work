#include "AuditLog.h"
#include <fstream>
#include <vector>
#include <sstream>

void AuditLog::SetLogPath(const std::string& path)
{
    m_logFile = path;
}

std::string AuditLog::GetNowTime()
{
    time_t now = time(NULL);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return std::string(buf);
}

std::string AuditLog::OpToString(FileOpType op)
{
    switch(op)
    {
        case OP_READ: return "读取文件";
        case OP_WRITE: return "写入文件";
        case OP_MODIFY: return "修改文件";
        case OP_DOWNLOAD: return "导出/下载文件";
        default: return "未知操作";
    }
}

void AuditLog::WriteLog(const AuditRecord& record)
{
    std::ofstream fout(m_logFile, std::ios::app);
    if(!fout.is_open()) return;
    fout << record.opTime << "|"
         << record.userName << "|"
         << OpToString(record.opType) << "|"
         << record.filePath << "|"
         << (record.isPermit ? "允许" : "拒绝") << "|"
         << record.desc << std::endl;
    fout.close();
}

std::vector<AuditRecord> AuditLog::ReadAllLog()
{
    std::vector<AuditRecord> res;
    std::ifstream fin(m_logFile);
    if(!fin.is_open()) return res;
    std::string line;
    while(std::getline(fin, line))
    {
        // 课程设计简化，不做完整解析，仅演示存储
        AuditRecord r;
        r.desc = line;
        res.push_back(r);
    }
    fin.close();
    return res;
}

// 新增对外接口
std::string AuditLog::GetCurrentTime()
{
    return GetNowTime();
}