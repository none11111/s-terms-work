#ifndef FILE_CRYPTO_H
#define FILE_CRYPTO_H

#include <string>
#include <vector>
#include <cstdint>   // 必须存在

#define AES_KEY_LEN 16
#define AES_BLOCK_LEN 16

class FileCrypto
{
public:
    void SetKey(const std::vector<uint8_t>& key);
    bool EncryptFile(const std::string& srcPath, const std::string& dstEncPath);
    bool DecryptFile(const std::string& encPath, const std::string& dstPlainPath);

    std::vector<uint8_t> AesEncrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> AesDecrypt(const std::vector<uint8_t>& cipher);

private:
    std::vector<uint8_t> m_key;
    std::vector<uint8_t> m_iv;
    void XorBlock(uint8_t* buf, const uint8_t* iv);
    void PadData(std::vector<uint8_t>& data);
    void UnPadData(std::vector<uint8_t>& data);
};

#endif