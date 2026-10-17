#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <print>
#include <stdexcept>

TEST(CryptoGuardCtxEncrypt, EmptyStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{}, outStr{};
    ASSERT_NO_THROW(ctx.EncryptFile(inStr, outStr, ""));
}

TEST(CryptoGuardCtxEncrypt, FailedStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{}, outStr{};
    inStr.setstate(std::ios::badbit);
    outStr.setstate(std::ios::badbit);
    ASSERT_THROW(ctx.EncryptFile(inStr, outStr, ""), std::runtime_error);
}

TEST(CryptoGuardCtxEncrypt, Success) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{"Sensitive data"}, outStr{};
    ASSERT_NO_THROW(ctx.EncryptFile(inStr, outStr, "12345"));
    ASSERT_FALSE(outStr.str().empty());
}

TEST(CryptoGuardCtxEncrypt, IsStable) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{"data"}, 
        outStr1{},outStr2{},outStr3{},outStr4{};
        
    std::string password = "12345";

    ASSERT_NO_THROW(ctx.EncryptFile(inStr, outStr1, password));
    inStr.clear();          
    inStr.seekg(0, std::ios::beg); 
    ASSERT_NO_THROW(ctx.EncryptFile(inStr, outStr2, password));
    inStr.clear();          
    inStr.seekg(0, std::ios::beg); 
    ASSERT_NO_THROW(ctx.EncryptFile(inStr, outStr3, password));
    inStr.clear();          
    inStr.seekg(0, std::ios::beg); 
    ASSERT_NO_THROW(ctx.EncryptFile(inStr, outStr4, password));

    ASSERT_EQ(outStr1.str(), outStr2.str());
    ASSERT_EQ(outStr2.str(), outStr3.str());
    ASSERT_EQ(outStr3.str(), outStr4.str());
}

TEST(CryptoGuardCtx, DecryptEncrypted) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream dataStr{"Sensitive data"}, cryptedStr{}, decryptenData{};
    std::string password = "12345";
    ASSERT_NO_THROW(ctx.EncryptFile(dataStr, cryptedStr, password));
    ASSERT_NO_THROW(ctx.DecryptFile(cryptedStr, decryptenData, password));
    ASSERT_EQ(dataStr.str(), dataStr.str());
}

TEST(CryptoGuardCtxDecrypt, NotRightPassword) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{}, outStr{};
    ASSERT_ANY_THROW(ctx.DecryptFile(inStr, outStr, ""));
}

TEST(CryptoGuardCtxDecrypt, FailedStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{}, outStr{};
    inStr.setstate(std::ios::badbit);
    outStr.setstate(std::ios::badbit);
    ASSERT_THROW(ctx.DecryptFile(inStr, outStr, ""), std::runtime_error);
}

TEST(CryptoGuardCtxDecrypt, IsStable) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream raw{"data"}, encryptedStr{}, 
        outStr1{},outStr2{},outStr3{},outStr4{};
        
    std::string password = "12345";

    ASSERT_NO_THROW(ctx.EncryptFile(raw, encryptedStr, password));

    ASSERT_NO_THROW(ctx.DecryptFile(encryptedStr, outStr1, password));
    encryptedStr.clear();          
    encryptedStr.seekg(0, std::ios::beg); 
    ASSERT_NO_THROW(ctx.DecryptFile(encryptedStr, outStr2, password));
    encryptedStr.clear();          
    encryptedStr.seekg(0, std::ios::beg); 
    ASSERT_NO_THROW(ctx.DecryptFile(encryptedStr, outStr3, password));
    encryptedStr.clear();          
    encryptedStr.seekg(0, std::ios::beg); 
    ASSERT_NO_THROW(ctx.DecryptFile(encryptedStr, outStr4, password));

    ASSERT_EQ(outStr1.str(), outStr2.str());
    ASSERT_EQ(outStr2.str(), outStr3.str());
    ASSERT_EQ(outStr3.str(), outStr4.str());
}

TEST(CryptoGuardCtxCalculateChecksum, Check1) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{"Hello, World!"};
    std::string out;
    ASSERT_NO_THROW(out = ctx.CalculateChecksum(inStr));
    ASSERT_EQ(out, "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
}

TEST(CryptoGuardCtxCalculateChecksum, Check2) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{""};
    std::string out;
    ASSERT_NO_THROW(out = ctx.CalculateChecksum(inStr));
    ASSERT_EQ(out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(CryptoGuardCtxCalculateChecksum, FailedStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{""};
    inStr.setstate(std::ios::badbit);
    ASSERT_ANY_THROW(ctx.CalculateChecksum(inStr));
}