#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

class AuthKeyManager;

class FileSecurity {
public:
    FileSecurity();
    ~FileSecurity();

    bool Initialize(AuthKeyManager* authManager);

    bool EncryptFile(const std::wstring& inputPath, const std::wstring& outputPath, const std::wstring& fileId);
    bool DecryptFile(const std::wstring& inputPath, const std::wstring& outputPath, const std::wstring& fileId);

    bool EncryptBuffer(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& fek, std::vector<BYTE>& outCiphertext);
    bool DecryptBuffer(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& fek, std::vector<BYTE>& outPlaintext);

    std::wstring GenerateFileId(const std::wstring& filePath);

private:
    struct FileHeader {
        char magic[8];
        uint32_t version;
        uint64_t fileSize;
        uint8_t nonce[12];
        uint8_t tag[16];
    };

    AuthKeyManager* m_authManager;

    bool ReadFileHeader(FILE* file, FileHeader& header);
    bool WriteFileHeader(FILE* file, const FileHeader& header);
};