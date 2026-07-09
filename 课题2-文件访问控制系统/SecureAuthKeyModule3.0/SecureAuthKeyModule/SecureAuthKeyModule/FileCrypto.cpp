#include "FileCrypto.h"
#include <fstream>
#include <iostream>
#include <cstdint>

void FileCrypto::SetKey(const std::vector<uint8_t>& key)
{
    if (key.size() == AES_KEY_LEN)
        m_key = key;
    // 固定IV，实际项目由密钥模块动态生成
    m_iv = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
            0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
}

void FileCrypto::XorBlock(uint8_t* buf, const uint8_t* iv)
{
    for(int i=0; i<AES_BLOCK_LEN; i++)
        buf[i] ^= iv[i];
}

void FileCrypto::PadData(std::vector<uint8_t>& data)
{
    uint8_t pad = AES_BLOCK_LEN - (data.size() % AES_BLOCK_LEN);
    for(int i=0; i<pad; i++) data.push_back(pad);
}

void FileCrypto::UnPadData(std::vector<uint8_t>& data)
{
    uint8_t pad = data.back();
    data.resize(data.size() - pad);
}

// 简化AES加密（课程演示，商用需专业密码库）
std::vector<uint8_t> FileCrypto::AesEncrypt(const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> in = data;
    PadData(in);
    std::vector<uint8_t> out;
    uint8_t curIv[AES_BLOCK_LEN];
    memcpy(curIv, m_iv.data(), AES_BLOCK_LEN);

    for(size_t i=0; i<in.size(); i+=AES_BLOCK_LEN)
    {
        uint8_t block[AES_BLOCK_LEN];
        memcpy(block, in.data()+i, AES_BLOCK_LEN);
        XorBlock(block, curIv);
        // 此处省略完整AES轮函数，课程设计简化模拟加密
        for(int j=0; j<AES_BLOCK_LEN; j++) block[j] ^= m_key[j];
        memcpy(curIv, block, AES_BLOCK_LEN);
        out.insert(out.end(), block, block+AES_BLOCK_LEN);
    }
    return out;
}

std::vector<uint8_t> FileCrypto::AesDecrypt(const std::vector<uint8_t>& cipher)
{
    std::vector<uint8_t> out;
    uint8_t curIv[AES_BLOCK_LEN];
    memcpy(curIv, m_iv.data(), AES_BLOCK_LEN);

    for(size_t i=0; i<cipher.size(); i+=AES_BLOCK_LEN)
    {
        uint8_t block[AES_BLOCK_LEN];
        memcpy(block, cipher.data()+i, AES_BLOCK_LEN);
        uint8_t preIv[AES_BLOCK_LEN];
        memcpy(preIv, curIv, AES_BLOCK_LEN);

        // 解密反向异或
        for(int j=0; j<AES_BLOCK_LEN; j++) block[j] ^= m_key[j];
        XorBlock(block, preIv);
        memcpy(curIv, cipher.data()+i, AES_BLOCK_LEN);
        out.insert(out.end(), block, block+AES_BLOCK_LEN);
    }
    UnPadData(out);
    return out;
}

bool FileCrypto::EncryptFile(const std::string& srcPath, const std::string& dstEncPath)
{
    std::ifstream fin(srcPath, std::ios::binary);
    if(!fin.is_open()) return false;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    std::vector<uint8_t> cipher = AesEncrypt(data);
    std::ofstream fout(dstEncPath, std::ios::binary);
    fout.write((char*)cipher.data(), cipher.size());
    fout.close();
    return true;
}

bool FileCrypto::DecryptFile(const std::string& encPath, const std::string& dstPlainPath)
{
    std::ifstream fin(encPath, std::ios::binary);
    if(!fin.is_open()) return false;
    std::vector<uint8_t> cipher((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
    fin.close();

    std::vector<uint8_t> plain = AesDecrypt(cipher);
    std::ofstream fout(dstPlainPath, std::ios::binary);
    fout.write((char*)plain.data(), plain.size());
    fout.close();
    return true;
}