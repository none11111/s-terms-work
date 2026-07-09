#include "pch.h"
#include "FileSecurity.h"
#include "AuthKeyManager.h"
#include "CryptoUtils.h"
#include <bcrypt.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

const char FILE_MAGIC[8] = { 'E', 'C', 'R', 'Y', 'P', 'T', 'F', 'S' };
const uint32_t FILE_VERSION = 1;

FileSecurity::FileSecurity() : m_authManager(nullptr) {}

FileSecurity::~FileSecurity() {}

bool FileSecurity::Initialize(AuthKeyManager* authManager) {
    if (!authManager) {
        return false;
    }
    m_authManager = authManager;
    return true;
}

std::wstring FileSecurity::GenerateFileId(const std::wstring& filePath) {
    std::vector<BYTE> hashInput;
    int len = WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) {
        hashInput.resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), -1, (char*)hashInput.data(), len, nullptr, nullptr);
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        return L"";
    }

    BYTE hash[32] = { 0 };
    BCryptHashData(hAlg, hashInput.data(), (ULONG)hashInput.size(), 0);
    BCryptFinishHash(hAlg, hash, 32, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::wstringstream wss;
    for (int i = 0; i < 16; i++) {
        wss << std::hex << std::setw(2) << std::setfill(L'0') << (int)hash[i];
    }
    return wss.str();
}

bool FileSecurity::ReadFileHeader(FILE* file, FileHeader& header) {
    if (!file) return false;
    
    size_t bytesRead = fread(&header, sizeof(FileHeader), 1, file);
    if (bytesRead != 1) {
        return false;
    }

    if (memcmp(header.magic, FILE_MAGIC, 8) != 0) {
        return false;
    }

    if (header.version != FILE_VERSION) {
        return false;
    }

    return true;
}

bool FileSecurity::WriteFileHeader(FILE* file, const FileHeader& header) {
    if (!file) return false;
    
    size_t bytesWritten = fwrite(&header, sizeof(FileHeader), 1, file);
    return bytesWritten == 1;
}

bool FileSecurity::EncryptBuffer(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& fek, std::vector<BYTE>& outCiphertext) {
    if (fek.size() != 32 || plaintext.empty()) {
        return false;
    }

    std::vector<BYTE> nonce = CryptoUtils::GenerateRandomBytes(12);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        return false;
    }

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (BYTE*)fek.data(), (ULONG)fek.size(), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = (ULONG)nonce.size();

    std::vector<BYTE> ciphertext(plaintext.size());
    BYTE tag[16] = { 0 };
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    ULONG cipherLen = 0;
    NTSTATUS status = BCryptEncrypt(hKey,
        (BYTE*)plaintext.data(), (ULONG)plaintext.size(),
        &authInfo, nullptr, 0,
        ciphertext.data(), (ULONG)ciphertext.size(),
        &cipherLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != STATUS_SUCCESS) {
        return false;
    }

    outCiphertext.clear();
    outCiphertext.reserve(12 + 16 + ciphertext.size());
    outCiphertext.insert(outCiphertext.end(), nonce.begin(), nonce.end());
    outCiphertext.insert(outCiphertext.end(), tag, tag + 16);
    outCiphertext.insert(outCiphertext.end(), ciphertext.begin(), ciphertext.end());

    return true;
}

bool FileSecurity::DecryptBuffer(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& fek, std::vector<BYTE>& outPlaintext) {
    if (fek.size() != 32 || ciphertext.size() < 28) {
        return false;
    }

    std::vector<BYTE> nonce(ciphertext.begin(), ciphertext.begin() + 12);
    std::vector<BYTE> tag(ciphertext.begin() + 12, ciphertext.begin() + 28);
    std::vector<BYTE> encryptedData(ciphertext.begin() + 28, ciphertext.end());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        return false;
    }

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (BYTE*)fek.data(), (ULONG)fek.size(), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = (ULONG)nonce.size();
    authInfo.pbTag = tag.data();
    authInfo.cbTag = (ULONG)tag.size();

    std::vector<BYTE> plaintext(encryptedData.size());
    ULONG plainLen = 0;

    NTSTATUS status = BCryptDecrypt(hKey,
        (BYTE*)encryptedData.data(), (ULONG)encryptedData.size(),
        &authInfo, nullptr, 0,
        plaintext.data(), (ULONG)plaintext.size(),
        &plainLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != STATUS_SUCCESS) {
        return false;
    }

    outPlaintext = plaintext;
    return true;
}

bool FileSecurity::EncryptFile(const std::wstring& inputPath, const std::wstring& outputPath, const std::wstring& fileId) {
    if (!m_authManager || inputPath.empty() || outputPath.empty()) {
        return false;
    }

    std::wstring effectiveFileId = fileId;
    if (effectiveFileId.empty()) {
        effectiveFileId = GenerateFileId(inputPath);
    }

    std::vector<BYTE> fek;
    if (!m_authManager->CreateFileKey(effectiveFileId, fek)) {
        return false;
    }

    FILE* inFile = nullptr;
    FILE* outFile = nullptr;

    errno_t err = _wfopen_s(&inFile, inputPath.c_str(), L"rb");
    if (err != 0 || !inFile) {
        return false;
    }

    err = _wfopen_s(&outFile, outputPath.c_str(), L"wb");
    if (err != 0 || !outFile) {
        fclose(inFile);
        return false;
    }

    fseek(inFile, 0, SEEK_END);
    uint64_t fileSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    std::vector<BYTE> plaintext(fileSize);
    size_t bytesRead = fread(plaintext.data(), 1, fileSize, inFile);
    if (bytesRead != fileSize) {
        fclose(inFile);
        fclose(outFile);
        return false;
    }
    fclose(inFile);

    std::vector<BYTE> nonce = CryptoUtils::GenerateRandomBytes(12);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        fclose(outFile);
        return false;
    }

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        fclose(outFile);
        return false;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (BYTE*)fek.data(), (ULONG)fek.size(), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        fclose(outFile);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = (ULONG)nonce.size();

    std::vector<BYTE> ciphertext(fileSize);
    BYTE tag[16] = { 0 };
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    ULONG cipherLen = 0;
    NTSTATUS status = BCryptEncrypt(hKey,
        (BYTE*)plaintext.data(), (ULONG)plaintext.size(),
        &authInfo, nullptr, 0,
        ciphertext.data(), (ULONG)ciphertext.size(),
        &cipherLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != STATUS_SUCCESS) {
        fclose(outFile);
        return false;
    }

    FileHeader header;
    memcpy(header.magic, FILE_MAGIC, 8);
    header.version = FILE_VERSION;
    header.fileSize = fileSize;
    memcpy(header.nonce, nonce.data(), 12);
    memcpy(header.tag, tag, 16);

    WriteFileHeader(outFile, header);
    fwrite(ciphertext.data(), 1, ciphertext.size(), outFile);

    fclose(outFile);
    AuthKeyManager::SecureZeroMemory(fek.data(), fek.size());

    return true;
}

bool FileSecurity::DecryptFile(const std::wstring& inputPath, const std::wstring& outputPath, const std::wstring& fileId) {
    if (!m_authManager || inputPath.empty() || outputPath.empty()) {
        return false;
    }

    std::wstring effectiveFileId = fileId;
    if (effectiveFileId.empty()) {
        effectiveFileId = GenerateFileId(inputPath);
    }

    std::vector<BYTE> fek;
    if (!m_authManager->GetFileKey(effectiveFileId, fek)) {
        return false;
    }

    FILE* inFile = nullptr;
    FILE* outFile = nullptr;

    errno_t err = _wfopen_s(&inFile, inputPath.c_str(), L"rb");
    if (err != 0 || !inFile) {
        return false;
    }

    err = _wfopen_s(&outFile, outputPath.c_str(), L"wb");
    if (err != 0 || !outFile) {
        fclose(inFile);
        return false;
    }

    FileHeader header;
    if (!ReadFileHeader(inFile, header)) {
        fclose(inFile);
        fclose(outFile);
        return false;
    }

    fseek(inFile, sizeof(FileHeader), SEEK_END);
    size_t cipherSize = ftell(inFile) - sizeof(FileHeader);
    fseek(inFile, sizeof(FileHeader), SEEK_SET);

    std::vector<BYTE> ciphertext(cipherSize);
    size_t bytesRead = fread(ciphertext.data(), 1, cipherSize, inFile);
    if (bytesRead != cipherSize) {
        fclose(inFile);
        fclose(outFile);
        return false;
    }
    fclose(inFile);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS) {
        fclose(outFile);
        return false;
    }

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        fclose(outFile);
        return false;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (BYTE*)fek.data(), (ULONG)fek.size(), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        fclose(outFile);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = header.nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = header.tag;
    authInfo.cbTag = 16;

    std::vector<BYTE> plaintext(header.fileSize);
    ULONG plainLen = 0;

    NTSTATUS status = BCryptDecrypt(hKey,
        (BYTE*)ciphertext.data(), (ULONG)ciphertext.size(),
        &authInfo, nullptr, 0,
        plaintext.data(), (ULONG)plaintext.size(),
        &plainLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != STATUS_SUCCESS) {
        fclose(outFile);
        return false;
    }

    fwrite(plaintext.data(), 1, plaintext.size(), outFile);
    fclose(outFile);
    AuthKeyManager::SecureZeroMemory(fek.data(), fek.size());

    return true;
}