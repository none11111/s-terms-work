#include "pch.h"
#include "AuthKeyManager.h"
#include "FileSecurity.h"
#include "AccessControl.h"
#include "AuditLogger.h"
#include "UsbManager.h"
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

void TestFileSecurity(AuthKeyManager& authManager, FileSecurity& fileSecurity) {
    std::wcout << L"\n=== [测试3] 文件加解密模块 ===" << std::endl;

    std::ofstream outFile(TEST_FILE_PATH);
    outFile << "Hello, SecureAuthKeyModule! This is a test file for encryption." << std::endl;
    outFile << "This file contains sensitive data that needs protection." << std::endl;
    outFile.close();
    std::wcout << L"3.1 创建测试文件: 完成" << std::endl;

    authManager.Login(L"admin", L"admin123");

    bool result = fileSecurity.EncryptFile(TEST_FILE_PATH, TEST_ENCRYPTED_PATH, L"file_encrypt_001");
    std::wcout << L"3.2 文件加密: " << (result ? L"成功" : L"失败") << std::endl;

    result = fileSecurity.DecryptFile(TEST_ENCRYPTED_PATH, TEST_DECRYPTED_PATH, L"file_encrypt_001");
    std::wcout << L"3.3 文件解密: " << (result ? L"成功" : L"失败") << std::endl;

    std::ifstream decFile(TEST_DECRYPTED_PATH);
    std::string content((std::istreambuf_iterator<char>(decFile)), std::istreambuf_iterator<char>());
    decFile.close();
    std::wcout << L"3.4 解密内容验证: " << (content.find("Hello") != std::string::npos ? L"成功" : L"失败") << std::endl;

    authManager.Logout();

    DeleteFile(TEST_FILE_PATH);
    DeleteFile(TEST_ENCRYPTED_PATH);
    DeleteFile(TEST_DECRYPTED_PATH);
    std::wcout << L"3.5 清理测试文件: 完成" << std::endl;
}

void TestAccessControl(AuthKeyManager& authManager, AccessControl& accessControl) {
    std::wcout << L"\n=== [测试4] 访问控制模块 ===" << std::endl;

    bool result = accessControl.AssignRole(L"admin", L"ADMIN");
    std::wcout << L"4.1 分配管理员角色: " << (result ? L"成功" : L"失败") << std::endl;

    result = accessControl.AssignRole(L"user1", L"USER");
    std::wcout << L"4.2 分配用户角色: " << (result ? L"成功" : L"失败") << std::endl;

    result = accessControl.SetFileOwner(L"admin", L"file_acl_test_001");
    std::wcout << L"4.3 设置文件所有者: " << (result ? L"成功" : L"失败") << std::endl;

    result = accessControl.CheckPermission(L"admin", L"file_acl_test_001", Permission::READ);
    std::wcout << L"4.4 管理员读取权限: " << (result ? L"允许" : L"拒绝") << std::endl;

    result = accessControl.CheckPermission(L"admin", L"file_acl_test_001", Permission::WRITE);
    std::wcout << L"4.5 管理员写入权限: " << (result ? L"允许" : L"拒绝") << std::endl;

    result = accessControl.GrantPermission(L"user1", L"file_acl_test_001", Permission::READ);
    std::wcout << L"4.6 授予用户读取权限: " << (result ? L"成功" : L"失败") << std::endl;

    result = accessControl.CheckPermission(L"user1", L"file_acl_test_001", Permission::READ);
    std::wcout << L"4.7 用户读取权限: " << (result ? L"允许" : L"拒绝") << std::endl;

    result = accessControl.CheckPermission(L"user1", L"file_acl_test_001", Permission::WRITE);
    std::wcout << L"4.8 用户写入权限: " << (result ? L"允许" : L"拒绝(预期)") << std::endl;

    result = accessControl.RevokePermission(L"user1", L"file_acl_test_001", Permission::READ);
    std::wcout << L"4.9 撤销用户读取权限: " << (result ? L"成功" : L"失败") << std::endl;

    result = accessControl.CheckPermission(L"user1", L"file_acl_test_001", Permission::READ);
    std::wcout << L"4.10 用户读取权限(撤销后): " << (result ? L"允许" : L"拒绝(预期)") << std::endl;
}

void TestAuditLogger(AuthKeyManager& authManager, AuditLogger& auditLogger) {
    std::wcout << L"\n=== [测试5] 审计日志模块 ===" << std::endl;

    authManager.Login(L"admin", L"admin123");

    bool result = auditLogger.LogAction(L"admin", FileAction::LOGIN, L"", L"", true);
    std::wcout << L"5.1 记录登录日志: " << (result ? L"成功" : L"失败") << std::endl;

    result = auditLogger.LogAction(L"admin", FileAction::ENCRYPT, L"file_audit_001", L"\\test\\secret.txt", true);
    std::wcout << L"5.2 记录加密操作日志: " << (result ? L"成功" : L"失败") << std::endl;

    result = auditLogger.LogAction(L"admin", FileAction::READ, L"file_audit_001", L"\\test\\secret.txt", true);
    std::wcout << L"5.3 记录读取操作日志: " << (result ? L"成功" : L"失败") << std::endl;

    result = auditLogger.LogAction(L"user1", FileAction::WRITE, L"file_audit_001", L"\\test\\secret.txt", false);
    std::wcout << L"5.4 记录失败操作日志: " << (result ? L"成功" : L"失败") << std::endl;

    std::vector<std::pair<std::wstring, std::wstring>> logs;
    result = auditLogger.GetLogsByUser(L"admin", logs);
    std::wcout << L"5.5 查询管理员日志: " << (result ? L"成功(" + std::to_wstring(logs.size()) + L"条)" : L"失败") << std::endl;

    if (result && !logs.empty()) {
        std::wcout << L"    最新日志: " << logs[0].second << std::endl;
    }

    logs.clear();
    result = auditLogger.GetLogsByAction(L"admin", FileAction::ENCRYPT, logs);
    std::wcout << L"5.6 查询加密操作日志: " << (result ? L"成功(" + std::to_wstring(logs.size()) + L"条)" : L"失败") << std::endl;

    authManager.Logout();

    result = auditLogger.LogAction(L"admin", FileAction::LOGOUT, L"", L"", true);
    std::wcout << L"5.7 记录登出日志: " << (result ? L"成功" : L"失败") << std::endl;
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

void TestEndToEnd(AuthKeyManager& authManager, FileSecurity& fileSecurity, 
                  AccessControl& accessControl, AuditLogger& auditLogger,
                  UsbManager& usbManager, SimulateUsbDetector& detector) {
    std::wcout << L"\n=== [测试7] 端到端完整流程 ===" << std::endl;

    std::ofstream outFile(TEST_FILE_PATH);
    outFile << "END-TO-END TEST DATA - CONFIDENTIAL INFORMATION" << std::endl;
    outFile.close();

    std::wcout << L"7.1 用户注册 & 登录..." << std::endl;
    authManager.RegisterUser(L"testuser", L"testpass123");
    authManager.Login(L"testuser", L"testpass123");
    accessControl.AssignRole(L"testuser", L"USER");

    std::wcout << L"7.2 创建文件密钥..." << std::endl;
    std::vector<BYTE> fek;
    authManager.CreateFileKey(L"e2e_file_001", fek);

    std::wcout << L"7.3 设置文件所有者..." << std::endl;
    accessControl.SetFileOwner(L"testuser", L"e2e_file_001");

    std::wcout << L"7.4 检查权限..." << std::endl;
    bool hasRead = accessControl.CheckPermission(L"testuser", L"e2e_file_001", Permission::READ);
    bool hasWrite = accessControl.CheckPermission(L"testuser", L"e2e_file_001", Permission::WRITE);

    if (hasRead && hasWrite) {
        std::wcout << L"7.5 文件加密..." << std::endl;
        fileSecurity.EncryptFile(TEST_FILE_PATH, TEST_ENCRYPTED_PATH, L"e2e_file_001");
        auditLogger.LogAction(L"testuser", FileAction::ENCRYPT, L"e2e_file_001", TEST_FILE_PATH, true);

        std::wcout << L"7.6 文件解密..." << std::endl;
        fileSecurity.DecryptFile(TEST_ENCRYPTED_PATH, TEST_DECRYPTED_PATH, L"e2e_file_001");
        auditLogger.LogAction(L"testuser", FileAction::DECRYPT, L"e2e_file_001", TEST_DECRYPTED_PATH, true);

        std::wcout << L"7.7 验证解密结果..." << std::endl;
        std::ifstream decFile(TEST_DECRYPTED_PATH);
        std::string content((std::istreambuf_iterator<char>(decFile)), std::istreambuf_iterator<char>());
        bool verified = (content.find("END-TO-END") != std::string::npos);
        std::wcout << L"    结果验证: " << (verified ? L"成功" : L"失败") << std::endl;
    }

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
    auditLogger.LogAction(L"testuser", FileAction::LOGOUT, L"", L"", true);

    DeleteFile(TEST_FILE_PATH);
    DeleteFile(TEST_ENCRYPTED_PATH);
    DeleteFile(TEST_DECRYPTED_PATH);

    std::wcout << L"7.9 端到端测试完成!" << std::endl;
}

int wmain() {
    std::wcout << L"==============================================" << std::endl;
    std::wcout << L"    SecureAuthKeyModule 完整联调测试" << std::endl;
    std::wcout << L"==============================================" << std::endl;

    DeleteFile(TEST_DB_PATH);

    AuthKeyManager authManager;
    FileSecurity fileSecurity;
    AccessControl accessControl;
    AuditLogger auditLogger;
    UsbManager usbManager;
    SimulateUsbDetector detector;

    std::wcout << L"\n[初始化] 配置数据库..." << std::endl;
    bool initResult = authManager.Initialize(TEST_DB_PATH);
    if (!initResult) {
        std::wcout << L"数据库初始化失败!" << std::endl;
        return -1;
    }

    std::wcout << L"[初始化] 初始化模块..." << std::endl;
    fileSecurity.Initialize(&authManager);
    accessControl.Initialize(authManager.GetDBManager());
    auditLogger.Initialize(authManager.GetDBManager());
    usbManager.Initialize(authManager.GetDBManager(), &auditLogger);
    usbManager.SetDetector(std::make_unique<SimulateUsbDetector>(detector));

    TestAuthKeyManager(authManager);
    TestKeyManagement(authManager);
    TestFileSecurity(authManager, fileSecurity);
    TestAccessControl(authManager, accessControl);
    TestAuditLogger(authManager, auditLogger);
    TestUsbManager(usbManager, detector);
    TestEndToEnd(authManager, fileSecurity, accessControl, auditLogger, usbManager, detector);

    std::wcout << L"\n==============================================" << std::endl;
    std::wcout << L"    所有测试完成!" << std::endl;
    std::wcout << L"==============================================" << std::endl;

    DeleteFile(TEST_DB_PATH);

    return 0;
}
