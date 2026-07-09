#include "pch.h"
#include "UsbManager.h"
#include "DatabaseManager.h"
#include "AuditLogger.h"

UsbManager* UsbManager::s_instance = nullptr;

SimulateUsbDetector::SimulateUsbDetector() : m_callback(nullptr), m_isMonitoring(false) {
    InitSimulatedDevices();
}

SimulateUsbDetector::~SimulateUsbDetector() {
    StopMonitoring();
}

void SimulateUsbDetector::InitSimulatedDevices() {
    m_simulatedDevices.clear();

    UsbDeviceInfo device1;
    device1.vid = L"0x0781";
    device1.pid = L"0x5581";
    device1.serialNumber = L"SN000001";
    device1.deviceName = L"SanDisk Ultra USB 3.0";
    device1.driveLetter = L"D:";
    device1.pnpDeviceId = L"USB\\VID_0781&PID_5581\\SN000001";
    device1.isStorage = true;
    device1.isAuthorized = true;
    m_simulatedDevices.push_back(device1);

    UsbDeviceInfo device2;
    device2.vid = L"0x05AC";
    device2.pid = L"0x12A8";
    device2.serialNumber = L"SN000002";
    device2.deviceName = L"Apple USB Flash Drive";
    device2.driveLetter = L"E:";
    device2.pnpDeviceId = L"USB\\VID_05AC&PID_12A8\\SN000002";
    device2.isStorage = true;
    device2.isAuthorized = true;
    m_simulatedDevices.push_back(device2);

    UsbDeviceInfo device3;
    device3.vid = L"0x0930";
    device3.pid = L"0x6545";
    device3.serialNumber = L"SN000003";
    device3.deviceName = L"Generic USB Drive";
    device3.driveLetter = L"F:";
    device3.pnpDeviceId = L"USB\\VID_0930&PID_6545\\SN000003";
    device3.isStorage = true;
    device3.isAuthorized = false;
    m_simulatedDevices.push_back(device3);

    UsbDeviceInfo device4;
    device4.vid = L"0xFFFF";
    device4.pid = L"0xFFFF";
    device4.serialNumber = L"MALICIOUS_USB_001";
    device4.deviceName = L"Unknown Device";
    device4.driveLetter = L"G:";
    device4.pnpDeviceId = L"USB\\VID_FFFF&PID_FFFF\\MALICIOUS_USB_001";
    device4.isStorage = true;
    device4.isAuthorized = false;
    m_simulatedDevices.push_back(device4);
}

bool SimulateUsbDetector::Initialize() {
    return true;
}

bool SimulateUsbDetector::GetConnectedDevices(std::vector<UsbDeviceInfo>& devices) {
    devices = m_simulatedDevices;
    return true;
}

bool SimulateUsbDetector::StartMonitoring(void(*callback)(UsbDeviceInfo, UsbAction)) {
    m_callback = callback;
    m_isMonitoring = true;
    return true;
}

bool SimulateUsbDetector::StopMonitoring() {
    m_callback = nullptr;
    m_isMonitoring = false;
    return true;
}

void SimulateUsbDetector::SimulateInsert(const UsbDeviceInfo& device) {
    if (m_callback && m_isMonitoring) {
        m_callback(device, UsbAction::INSERT);
    }
}

void SimulateUsbDetector::SimulateRemove(const UsbDeviceInfo& device) {
    if (m_callback && m_isMonitoring) {
        m_callback(device, UsbAction::REMOVE);
    }
}

void SimulateUsbDetector::SimulateMaliciousDevice() {
    UsbDeviceInfo maliciousDevice;
    maliciousDevice.vid = L"0xFFFF";
    maliciousDevice.pid = L"0xFFFF";
    maliciousDevice.serialNumber = L"MALICIOUS_USB_" + std::to_wstring(rand() % 1000);
    maliciousDevice.deviceName = L"Malicious USB Device";
    maliciousDevice.driveLetter = L"Z:";
    maliciousDevice.pnpDeviceId = L"USB\\VID_FFFF&PID_FFFF\\" + maliciousDevice.serialNumber;
    maliciousDevice.isStorage = true;
    maliciousDevice.isAuthorized = false;

    if (m_callback && m_isMonitoring) {
        m_callback(maliciousDevice, UsbAction::INSERT);
    }
}

UsbManager::UsbManager() : m_dbManager(nullptr), m_auditLogger(nullptr), s_instance(this) {}

UsbManager::~UsbManager() {
    StopUsbMonitoring();
}

bool UsbManager::Initialize(DatabaseManager* dbManager, AuditLogger* auditLogger) {
    if (!dbManager || !auditLogger) {
        return false;
    }
    m_dbManager = dbManager;
    m_auditLogger = auditLogger;
    return true;
}

bool UsbManager::SetDetector(std::unique_ptr<IUsbDetector> detector) {
    if (!detector || !detector->Initialize()) {
        return false;
    }
    m_detector = std::move(detector);
    return true;
}

bool UsbManager::AddToWhitelist(const UsbDeviceInfo& device) {
    if (!m_dbManager) {
        return false;
    }

    std::string vid = "";
    std::string pid = "";
    std::string serial = "";
    std::string name = "";

    int len = WideCharToMultiByte(CP_UTF8, 0, device.vid.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { vid.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.vid.c_str(), -1, &vid[0], len, nullptr, nullptr); }

    len = WideCharToMultiByte(CP_UTF8, 0, device.pid.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { pid.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.pid.c_str(), -1, &pid[0], len, nullptr, nullptr); }

    len = WideCharToMultiByte(CP_UTF8, 0, device.serialNumber.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { serial.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.serialNumber.c_str(), -1, &serial[0], len, nullptr, nullptr); }

    len = WideCharToMultiByte(CP_UTF8, 0, device.deviceName.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { name.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.deviceName.c_str(), -1, &name[0], len, nullptr, nullptr); }

    std::string sql = "INSERT OR REPLACE INTO usb_whitelist (vid, pid, serial_number, device_name, authorized) VALUES ('" + 
                      vid + "', '" + pid + "', '" + serial + "', '" + name + "', 1);";
    return m_dbManager->ExecuteSQL(sql);
}

bool UsbManager::RemoveFromWhitelist(const std::wstring& serialNumber) {
    if (!m_dbManager || serialNumber.empty()) {
        return false;
    }

    int len = WideCharToMultiByte(CP_UTF8, 0, serialNumber.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    std::string serial(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, serialNumber.c_str(), -1, &serial[0], len, nullptr, nullptr);

    std::string sql = "DELETE FROM usb_whitelist WHERE serial_number = '" + serial + "';";
    return m_dbManager->ExecuteSQL(sql);
}

bool UsbManager::IsDeviceAuthorized(const UsbDeviceInfo& device) {
    if (!m_dbManager) {
        return false;
    }

    if (device.vid == L"0xFFFF" && device.pid == L"0xFFFF") {
        return false;
    }

    std::string sql = "SELECT authorized FROM usb_whitelist WHERE vid = ? AND pid = ? AND serial_number = ?;";
    
    sqlite3_stmt* stmt;
    std::string vid, pid, serial;
    
    int len = WideCharToMultiByte(CP_UTF8, 0, device.vid.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { vid.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.vid.c_str(), -1, &vid[0], len, nullptr, nullptr); }
    
    len = WideCharToMultiByte(CP_UTF8, 0, device.pid.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { pid.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.pid.c_str(), -1, &pid[0], len, nullptr, nullptr); }
    
    len = WideCharToMultiByte(CP_UTF8, 0, device.serialNumber.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { serial.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.serialNumber.c_str(), -1, &serial[0], len, nullptr, nullptr); }

    int rc = sqlite3_prepare_v2(m_dbManager->GetDBHandle(), sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, vid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, serial.c_str(), -1, SQLITE_TRANSIENT);

    bool isAuthorized = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        isAuthorized = sqlite3_column_int(stmt, 0) == 1;
    }

    sqlite3_finalize(stmt);
    return isAuthorized;
}

bool UsbManager::GetWhitelist(std::vector<UsbDeviceInfo>& devices) {
    if (!m_dbManager) {
        return false;
    }

    devices.clear();
    std::string sql = "SELECT vid, pid, serial_number, device_name FROM usb_whitelist WHERE authorized = 1;";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(m_dbManager->GetDBHandle(), sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* vid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* pid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* serial = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));

        if (vid && pid && serial) {
            UsbDeviceInfo device;
            
            int wlen = MultiByteToWideChar(CP_UTF8, 0, vid, -1, nullptr, 0);
            device.vid.resize(wlen > 0 ? wlen : 0);
            if (wlen > 0) MultiByteToWideChar(CP_UTF8, 0, vid, -1, &device.vid[0], wlen);
            if (!device.vid.empty()) device.vid.pop_back();

            wlen = MultiByteToWideChar(CP_UTF8, 0, pid, -1, nullptr, 0);
            device.pid.resize(wlen > 0 ? wlen : 0);
            if (wlen > 0) MultiByteToWideChar(CP_UTF8, 0, pid, -1, &device.pid[0], wlen);
            if (!device.pid.empty()) device.pid.pop_back();

            wlen = MultiByteToWideChar(CP_UTF8, 0, serial, -1, nullptr, 0);
            device.serialNumber.resize(wlen > 0 ? wlen : 0);
            if (wlen > 0) MultiByteToWideChar(CP_UTF8, 0, serial, -1, &device.serialNumber[0], wlen);
            if (!device.serialNumber.empty()) device.serialNumber.pop_back();

            if (name) {
                wlen = MultiByteToWideChar(CP_UTF8, 0, name, -1, nullptr, 0);
                device.deviceName.resize(wlen > 0 ? wlen : 0);
                if (wlen > 0) MultiByteToWideChar(CP_UTF8, 0, name, -1, &device.deviceName[0], wlen);
                if (!device.deviceName.empty()) device.deviceName.pop_back();
            }

            device.isStorage = true;
            device.isAuthorized = true;
            devices.push_back(device);
        }
    }

    sqlite3_finalize(stmt);
    return true;
}

bool UsbManager::BlockDevice(const UsbDeviceInfo& device) {
    if (!m_dbManager) {
        return false;
    }

    std::string vid, pid, serial, name;
    
    int len = WideCharToMultiByte(CP_UTF8, 0, device.vid.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { vid.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.vid.c_str(), -1, &vid[0], len, nullptr, nullptr); }
    
    len = WideCharToMultiByte(CP_UTF8, 0, device.pid.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { pid.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.pid.c_str(), -1, &pid[0], len, nullptr, nullptr); }
    
    len = WideCharToMultiByte(CP_UTF8, 0, device.serialNumber.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { serial.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.serialNumber.c_str(), -1, &serial[0], len, nullptr, nullptr); }
    
    len = WideCharToMultiByte(CP_UTF8, 0, device.deviceName.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { name.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.deviceName.c_str(), -1, &name[0], len, nullptr, nullptr); }

    std::string sql = "INSERT INTO usb_logs (vid, pid, serial_number, device_name, action, success) VALUES ('" +
                      vid + "', '" + pid + "', '" + serial + "', '" + name + "', 'BLOCKED', 1);";
    return m_dbManager->ExecuteSQL(sql);
}

bool UsbManager::AllowDevice(const UsbDeviceInfo& device) {
    if (!m_dbManager) {
        return false;
    }

    std::string vid, pid, serial, name;
    
    int len = WideCharToMultiByte(CP_UTF8, 0, device.vid.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { vid.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.vid.c_str(), -1, &vid[0], len, nullptr, nullptr); }
    
    len = WideCharToMultiByte(CP_UTF8, 0, device.pid.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { pid.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.pid.c_str(), -1, &pid[0], len, nullptr, nullptr); }
    
    len = WideCharToMultiByte(CP_UTF8, 0, device.serialNumber.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { serial.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.serialNumber.c_str(), -1, &serial[0], len, nullptr, nullptr); }
    
    len = WideCharToMultiByte(CP_UTF8, 0, device.deviceName.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) { name.resize(len); WideCharToMultiByte(CP_UTF8, 0, device.deviceName.c_str(), -1, &name[0], len, nullptr, nullptr); }

    std::string sql = "INSERT INTO usb_logs (vid, pid, serial_number, device_name, action, success) VALUES ('" +
                      vid + "', '" + pid + "', '" + serial + "', '" + name + "', 'ALLOW', 1);";
    return m_dbManager->ExecuteSQL(sql);
}

bool UsbManager::StartUsbMonitoring() {
    if (!m_detector) {
        return false;
    }
    return m_detector->StartMonitoring(OnUsbEvent);
}

bool UsbManager::StopUsbMonitoring() {
    if (!m_detector) {
        return false;
    }
    return m_detector->StopMonitoring();
}

std::wstring UsbManager::UsbActionToString(UsbAction action) {
    switch (action) {
    case UsbAction::INSERT: return L"INSERT";
    case UsbAction::REMOVE: return L"REMOVE";
    case UsbAction::ALLOW: return L"ALLOW";
    case UsbAction::DENY: return L"DENY";
    case UsbAction::BLOCKED: return L"BLOCKED";
    default: return L"UNKNOWN";
    }
}

UsbAction UsbManager::StringToUsbAction(const std::wstring& actionStr) {
    if (actionStr == L"INSERT") return UsbAction::INSERT;
    if (actionStr == L"REMOVE") return UsbAction::REMOVE;
    if (actionStr == L"ALLOW") return UsbAction::ALLOW;
    if (actionStr == L"DENY") return UsbAction::DENY;
    if (actionStr == L"BLOCKED") return UsbAction::BLOCKED;
    return UsbAction::INSERT;
}

void UsbManager::OnUsbEvent(UsbDeviceInfo device, UsbAction action) {
    if (s_instance) {
        s_instance->HandleUsbEvent(device, action);
    }
}

void UsbManager::HandleUsbEvent(const UsbDeviceInfo& device, UsbAction action) {
    if (action == UsbAction::INSERT) {
        bool isAuthorized = IsDeviceAuthorized(device);
        
        if (isAuthorized) {
            AllowDevice(device);
        } else {
            BlockDevice(device);
        }
    }
}
