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

TEST(CryptoGuardCtx, DecryptEncrypted) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream dataStr{"Sensitive data"}, cryptedStr{}, decryptenData{};
    std::string password = "12345";
    ASSERT_NO_THROW(ctx.EncryptFile(dataStr, cryptedStr, password));
    ASSERT_NO_THROW(ctx.DecryptFile(cryptedStr, decryptenData, password));
    ASSERT_EQ(dataStr.str(), dataStr.str());
}

TEST(CryptoGuardCtxDecrypt, EmptyStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{}, outStr{};
    ASSERT_NO_THROW(ctx.DecryptFile(inStr, outStr, ""));
}

TEST(CryptoGuardCtxDecrypt, FailedStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{}, outStr{};
    inStr.setstate(std::ios::badbit);
    outStr.setstate(std::ios::badbit);
    ASSERT_THROW(ctx.DecryptFile(inStr, outStr, ""), std::runtime_error);
}

TEST(CryptoGuardCtxDecrypt, Success) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStr{"Sensitive data"}, outStr{};
    ASSERT_NO_THROW(ctx.DecryptFile(inStr, outStr, "12345"));
    ASSERT_FALSE(outStr.str().empty());
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