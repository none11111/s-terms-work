#include "pch.h"
#include "AuthKeyManager.h"
#include "FileCrypto.h"
#include "AccessControl.h"
#include "AuditLog.h"
#include "UsbManager.h"
#include "DatabaseManager.h"
#include <iostream>
#include <fstream>

#define TEST_DB_PATH L".\\test_auth.db"
#define TEST_FILE_PATH L".\\test_file.txt"
#define TEST_ENCRYPTED_PATH L".\\test_file.enc"
#define TEST_DECRYPTED_PATH L".\\test_file_dec.txt"

void TestAuthKeyManager(AuthKeyManager& authManager) {
    std::wcout << L"\n=== [测试1] 用户认证模块 ===" << std::endl;

    bool result = authManager.RegisterUser(L"admin", L"admin123");
    std::wcout << L"1.1 用户注册: " << (result ? L"成功" : L"失败") << std::endl;

    result = authManager.RegisterUser(L"user1", L"password1");
    std::wcout << L"1.2 用户注册: " << (result ? L"成功" : L"失败") << std::endl;

    result = authManager.Login(L"admin", L"admin123");
    std::wcout << L"1.3 管理员登录: " << (result ? L"成功" : L"失败") << std::endl;

    std::wstring currentUser = authManager.GetCurrentUsername();
    std::wcout << L"1.4 当前用户: " << currentUser << std::endl;

    result = authManager.Login(L"user1", L"wrong_password");
    std::wcout << L"1.5 错误密码登录: " << (result ? L"成功" : L"失败(预期)") << std::endl;

    authManager.Logout();
    std::wcout << L"1.6 用户登出: 完成" << std::endl;
}

void TestKeyManagement(AuthKeyManager& authManager) {
    std::wcout << L"\n=== [测试2] 密钥管理模块 ===" << std::endl;

    authManager.Login(L"admin", L"admin123");

    std::vector<BYTE> fek;
    bool result = authManager.CreateFileKey(L"file_test_001", fek);
    std::wcout << L"2.1 创建文件密钥: " << (result ? L"成功" : L"失败") << std::endl;

    std::vector<BYTE> fek2;
    result = authManager.GetFileKey(L"file_test_001", fek2);
    std::wcout << L"2.2 获取文件密钥: " << (result ? L"成功" : L"失败") << std::endl;

    result = authManager.DeleteFileKey(L"file_test_001");
    std::wcout << L"2.3 删除文件密钥: " << (result ? L"成功" : L"失败") << std::endl;

    authManager.Logout();
}

void TestFileCrypto(FileCrypto& fileCrypto) {
    std::wcout << L"\n=== [测试3] 文件加解密模块 ===" << std::endl;

    std::ofstream outFile("test_file.txt");
    outFile << "Hello, SecureAuthKeyModule! This is a test file for encryption." << std::endl;
    outFile << "This file contains sensitive data that needs protection." << std::endl;
    outFile.close();
    std::wcout << L"3.1 创建测试文件: 完成" << std::endl;

    std::vector<uint8_t> key(16);
    for (int i = 0; i < 16; i++) {
        key[i] = (uint8_t)(i + 1);
    }
    fileCrypto.SetKey(key);

    bool result = fileCrypto.EncryptFile("test_file.txt", "test_file.enc");
    std::wcout << L"3.2 文件加密: " << (result ? L"成功" : L"失败") << std::endl;

    result = fileCrypto.DecryptFile("test_file.enc", "test_file_dec.txt");
    std::wcout << L"3.3 文件解密: " << (result ? L"成功" : L"失败") << std::endl;

    std::ifstream decFile("test_file_dec.txt");
    std::string content((std::istreambuf_iterator<char>(decFile)), std::istreambuf_iterator<char>());
    decFile.close();
    std::wcout << L"3.4 解密内容验证: " << (content.find("Hello") != std::string::npos ? L"成功" : L"失败") << std::endl;

    DeleteFile(L"test_file.txt");
    DeleteFile(L"test_file.enc");
    DeleteFile(L"test_file_dec.txt");
    std::wcout << L"3.5 清理测试文件: 完成" << std::endl;
}

void TestAccessControl(AccessControl& accessControl) {
    std::wcout << L"\n=== [测试4] 访问控制模块 ===" << std::endl;

    accessControl.InitDefaultPerm();

    accessControl.AssignUserRole("admin", ROLE_ADMIN);
    std::wcout << L"4.1 分配管理员角色: 完成" << std::endl;

    accessControl.AssignUserRole("editor01", ROLE_EDITOR);
    std::wcout << L"4.2 分配编辑员角色: 完成" << std::endl;

    accessControl.AssignUserRole("viewer01", ROLE_VIEWER);
    std::wcout << L"4.3 分配浏览者角色: 完成" << std::endl;

    accessControl.AssignUserRole("guest01", ROLE_GUEST);
    std::wcout << L"4.4 分配访客角色: 完成" << std::endl;

    bool result = accessControl.CheckPermission("admin", OP_READ);
    std::wcout << L"4.5 管理员读取权限: " << (result ? L"允许" : L"拒绝") << std::endl;

    result = accessControl.CheckPermission("admin", OP_WRITE);
    std::wcout << L"4.6 管理员写入权限: " << (result ? L"允许" : L"拒绝") << std::endl;

    result = accessControl.CheckPermission("admin", OP_DOWNLOAD);
    std::wcout << L"4.7 管理员下载权限: " << (result ? L"允许" : L"拒绝") << std::endl;

    result = accessControl.CheckPermission("editor01", OP_DOWNLOAD);
    std::wcout << L"4.8 编辑员下载权限: " << (result ? L"允许" : L"拒绝(预期)") << std::endl;

    result = accessControl.CheckPermission("viewer01", OP_READ);
    std::wcout << L"4.9 浏览者读取权限: " << (result ? L"允许" : L"拒绝") << std::endl;

    result = accessControl.CheckPermission("viewer01", OP_WRITE);
    std::wcout << L"4.10 浏览者写入权限: " << (result ? L"允许" : L"拒绝(预期)") << std::endl;

    result = accessControl.CheckPermission("guest01", OP_READ);
    std::wcout << L"4.11 访客读取权限: " << (result ? L"允许" : L"拒绝(预期)") << std::endl;
}

void TestAuditLog(AuditLog& auditLog) {
    std::wcout << L"\n=== [测试5] 审计日志模块 ===" << std::endl;

    auditLog.SetLogPath("file_audit.log");

    AuditRecord rec1;
    rec1.userName = "admin";
    rec1.filePath = "secret.txt";
    rec1.opType = OP_READ;
    rec1.opTime = auditLog.GetCurrentTime();
    rec1.isPermit = true;
    rec1.desc = "管理员读取保密文件";
    auditLog.WriteLog(rec1);
    std::wcout << L"5.1 记录读取日志: 完成" << std::endl;

    AuditRecord rec2;
    rec2.userName = "guest01";
    rec2.filePath = "secret.txt";
    rec2.opType = OP_DOWNLOAD;
    rec2.opTime = auditLog.GetCurrentTime();
    rec2.isPermit = false;
    rec2.desc = "访客尝试下载保密文件，权限不足";
    auditLog.WriteLog(rec2);
    std::wcout << L"5.2 记录下载拒绝日志: 完成" << std::endl;

    AuditRecord rec3;
    rec3.userName = "admin";
    rec3.filePath = "secret.enc";
    rec3.opType = OP_WRITE;
    rec3.opTime = auditLog.GetCurrentTime();
    rec3.isPermit = true;
    rec3.desc = "管理员加密文件";
    auditLog.WriteLog(rec3);
    std::wcout << L"5.3 记录加密日志: 完成" << std::endl;

    auto logs = auditLog.ReadAllLog();
    std::wcout << L"5.4 读取全部日志: " << logs.size() << L"条" << std::endl;
}

void TestUsbManager(UsbManager& usbManager, SimulateUsbDetector& detector) {
    std::wcout << L"\n=== [测试6] USB端口管控模块 ===" << std::endl;

    UsbDeviceInfo device1;
    device1.vid = L"0x0781";
    device1.pid = L"0x5581";
    device1.serialNumber = L"SN000001";
    device1.deviceName = L"SanDisk Ultra USB 3.0";
    device1.isStorage = true;

    UsbDeviceInfo device2;
    device2.vid = L"0x05AC";
    device2.pid = L"0x12A8";
    device2.serialNumber = L"SN000002";
    device2.deviceName = L"Apple USB Flash Drive";
    device2.isStorage = true;

    UsbDeviceInfo device3;
    device3.vid = L"0x0930";
    device3.pid = L"0x6545";
    device3.serialNumber = L"SN000003";
    device3.deviceName = L"Generic USB Drive";
    device3.isStorage = true;

    bool result = usbManager.AddToWhitelist(device1);
    std::wcout << L"6.1 添加授权U盘到白名单: " << (result ? L"成功" : L"失败") << std::endl;

    result = usbManager.AddToWhitelist(device2);
    std::wcout << L"6.2 添加授权U盘到白名单: " << (result ? L"成功" : L"失败") << std::endl;

    std::vector<UsbDeviceInfo> whitelist;
    result = usbManager.GetWhitelist(whitelist);
    std::wcout << L"6.3 查询白名单: " << (result ? L"成功(" + std::to_wstring(whitelist.size()) + L"个设备)" : L"失败") << std::endl;

    result = usbManager.IsDeviceAuthorized(device1);
    std::wcout << L"6.4 验证授权设备: " << (result ? L"已授权" : L"未授权") << std::endl;

    result = usbManager.IsDeviceAuthorized(device3);
    std::wcout << L"6.5 验证未授权设备: " << (result ? L"已授权" : L"未授权(预期)") << std::endl;

    std::wcout << L"6.6 启动USB监控..." << std::endl;
    result = usbManager.StartUsbMonitoring();
    std::wcout << L"    USB监控状态: " << (result ? L"已启动" : L"启动失败") << std::endl;

    std::wcout << L"6.7 模拟授权U盘接入..." << std::endl;
    detector.SimulateInsert(device1);
    Sleep(200);

    std::wcout << L"6.8 模拟未授权U盘接入..." << std::endl;
    detector.SimulateInsert(device3);
    Sleep(200);

    std::wcout << L"6.9 模拟恶意设备接入..." << std::endl;
    detector.SimulateMaliciousDevice();
    Sleep(200);

    std::wcout << L"6.10 停止USB监控..." << std::endl;
    result = usbManager.StopUsbMonitoring();
    std::wcout << L"    USB监控状态: " << (result ? L"已停止" : L"停止失败") << std::endl;
}

void TestEndToEnd(AuthKeyManager& authManager, FileCrypto& fileCrypto,
                  AccessControl& accessControl, AuditLog& auditLog,
                  UsbManager& usbManager, SimulateUsbDetector& detector) {
    std::wcout << L"\n=== [测试7] 端到端完整流程 ===" << std::endl;

    std::ofstream outFile("secret.txt");
    outFile << "END-TO-END TEST DATA - CONFIDENTIAL INFORMATION" << std::endl;
    outFile.close();

    std::wcout << L"7.1 用户注册 & 登录..." << std::endl;
    authManager.RegisterUser(L"testuser", L"testpass123");
    authManager.Login(L"testuser", L"testpass123");

    std::wcout << L"7.2 创建文件密钥..." << std::endl;
    std::vector<BYTE> fek;
    authManager.CreateFileKey(L"e2e_file_001", fek);

    std::wcout << L"7.3 初始化访问控制..." << std::endl;
    accessControl.InitDefaultPerm();
    accessControl.AssignUserRole("testuser", ROLE_ADMIN);

    std::wcout << L"7.4 初始化审计日志..." << std::endl;
    auditLog.SetLogPath("file_audit.log");

    std::wcout << L"7.5 文件加密..." << std::endl;
    std::vector<uint8_t> key(16);
    for (int i = 0; i < 16; i++) {
        key[i] = (uint8_t)(i + 1);
    }
    fileCrypto.SetKey(key);
    fileCrypto.EncryptFile("secret.txt", "secret.enc");

    AuditRecord encRec;
    encRec.userName = "testuser";
    encRec.filePath = "secret.txt";
    encRec.opType = OP_WRITE;
    encRec.opTime = auditLog.GetCurrentTime();
    encRec.isPermit = true;
    encRec.desc = "端到端测试：用户加密文件";
    auditLog.WriteLog(encRec);

    std::wcout << L"7.6 文件解密..." << std::endl;
    fileCrypto.DecryptFile("secret.enc", "secret_dec.txt");

    AuditRecord decRec;
    decRec.userName = "testuser";
    decRec.filePath = "secret_dec.txt";
    decRec.opType = OP_READ;
    decRec.opTime = auditLog.GetCurrentTime();
    decRec.isPermit = true;
    decRec.desc = "端到端测试：用户解密文件";
    auditLog.WriteLog(decRec);

    std::wcout << L"7.7 验证解密结果..." << std::endl;
    std::ifstream decFile("secret_dec.txt");
    std::string content((std::istreambuf_iterator<char>(decFile)), std::istreambuf_iterator<char>());
    bool verified = (content.find("END-TO-END") != std::string::npos);
    std::wcout << L"    结果验证: " << (verified ? L"成功" : L"失败") << std::endl;

    std::wcout << L"7.8 USB设备管控..." << std::endl;
    UsbDeviceInfo testUsbDevice;
    testUsbDevice.vid = L"0x0781";
    testUsbDevice.pid = L"0x5581";
    testUsbDevice.serialNumber = L"SN_E2E_TEST";
    testUsbDevice.deviceName = L"Test USB Drive";
    testUsbDevice.isStorage = true;

    usbManager.AddToWhitelist(testUsbDevice);
    usbManager.StartUsbMonitoring();
    detector.SimulateInsert(testUsbDevice);
    Sleep(200);
    usbManager.StopUsbMonitoring();
    std::wcout << L"    USB设备授权测试完成" << std::endl;

    authManager.Logout();

    DeleteFile(L"secret.txt");
    DeleteFile(L"secret.enc");
    DeleteFile(L"secret_dec.txt");

    std::wcout << L"7.9 端到端测试完成!" << std::endl;
}

int wmain() {
    std::wcout << L"==============================================" << std::endl;
    std::wcout << L"    SecureAuthKeyModule3.0 完整联调测试" << std::endl;
    std::wcout << L"==============================================" << std::endl;

    DeleteFile(TEST_DB_PATH);

    AuthKeyManager authManager;
    FileCrypto fileCrypto;
    AccessControl accessControl;
    AuditLog auditLog;
    UsbManager usbManager;
    SimulateUsbDetector detector;

    std::wcout << L"\n[初始化] 配置数据库..." << std::endl;
    bool initResult = authManager.Initialize(TEST_DB_PATH);
    if (!initResult) {
        std::wcout << L"数据库初始化失败!" << std::endl;
        return -1;
    }

    std::wcout << L"[初始化] 初始化模块..." << std::endl;
    usbManager.Initialize(authManager.GetDBManager(), nullptr);
    usbManager.SetDetector(std::make_unique<SimulateUsbDetector>(detector));

    TestAuthKeyManager(authManager);
    TestKeyManagement(authManager);
    TestFileCrypto(fileCrypto);
    TestAccessControl(accessControl);
    TestAuditLog(auditLog);
    TestUsbManager(usbManager, detector);
    TestEndToEnd(authManager, fileCrypto, accessControl, auditLog, usbManager, detector);

    std::wcout << L"\n==============================================" << std::endl;
    std::wcout << L"    所有测试完成!" << std::endl;
    std::wcout << L"==============================================" << std::endl;

    DeleteFile(TEST_DB_PATH);

    std::wcout << L"\n按任意键退出..." << std::endl;
    std::wcin.get();

    return 0;
}