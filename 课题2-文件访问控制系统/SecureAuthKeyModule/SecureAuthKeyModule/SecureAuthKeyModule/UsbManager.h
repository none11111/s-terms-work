#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

class DatabaseManager;
class AuditLogger;

struct UsbDeviceInfo {
    std::wstring vid;
    std::wstring pid;
    std::wstring serialNumber;
    std::wstring deviceName;
    std::wstring driveLetter;
    std::wstring pnpDeviceId;
    bool isStorage;
    bool isAuthorized;
};

enum class UsbAction {
    INSERT,
    REMOVE,
    ALLOW,
    DENY,
    BLOCKED
};

class IUsbDetector {
public:
    virtual ~IUsbDetector() = default;
    virtual bool Initialize() = 0;
    virtual bool GetConnectedDevices(std::vector<UsbDeviceInfo>& devices) = 0;
    virtual bool StartMonitoring(void(*callback)(UsbDeviceInfo, UsbAction)) = 0;
    virtual bool StopMonitoring() = 0;
};

class SimulateUsbDetector : public IUsbDetector {
public:
    SimulateUsbDetector();
    ~SimulateUsbDetector() override;

    bool Initialize() override;
    bool GetConnectedDevices(std::vector<UsbDeviceInfo>& devices) override;
    bool StartMonitoring(void(*callback)(UsbDeviceInfo, UsbAction)) override;
    bool StopMonitoring() override;

    void SimulateInsert(const UsbDeviceInfo& device);
    void SimulateRemove(const UsbDeviceInfo& device);
    void SimulateMaliciousDevice();

private:
    void (*m_callback)(UsbDeviceInfo, UsbAction);
    std::vector<UsbDeviceInfo> m_simulatedDevices;
    bool m_isMonitoring;

    void InitSimulatedDevices();
};

class UsbManager {
public:
    UsbManager();
    ~UsbManager();

    bool Initialize(DatabaseManager* dbManager, AuditLogger* auditLogger);
    bool SetDetector(std::unique_ptr<IUsbDetector> detector);
    
    bool AddToWhitelist(const UsbDeviceInfo& device);
    bool RemoveFromWhitelist(const std::wstring& serialNumber);
    bool IsDeviceAuthorized(const UsbDeviceInfo& device);
    bool GetWhitelist(std::vector<UsbDeviceInfo>& devices);
    
    bool BlockDevice(const UsbDeviceInfo& device);
    bool AllowDevice(const UsbDeviceInfo& device);
    
    bool StartUsbMonitoring();
    bool StopUsbMonitoring();

    static std::wstring UsbActionToString(UsbAction action);
    static UsbAction StringToUsbAction(const std::wstring& actionStr);

private:
    DatabaseManager* m_dbManager;
    AuditLogger* m_auditLogger;
    std::unique_ptr<IUsbDetector> m_detector;

    static void OnUsbEvent(UsbDeviceInfo device, UsbAction action);
    
    static UsbManager* s_instance;
    void HandleUsbEvent(const UsbDeviceInfo& device, UsbAction action);
};
