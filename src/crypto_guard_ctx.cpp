#include "crypto_guard_ctx.h"

#include <array>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>

namespace CryptoGuard {

struct CryptoGuardCtx::Impl {

    struct AesCipherParams {
        static constexpr size_t KEY_SIZE = 32;         // AES-256 key size
        static constexpr size_t IV_SIZE = 16;          // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    [[nodiscard]] AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        if (!EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                            reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                            params.key.data(), params.iv.data())) {
            throw std::runtime_error{"Failed to create a key from password. " + getOpenSslError()};
        }

        return params;
    }
    
    void DoCrypt(std::istream &inStream, std::ostream &outStream, std::string_view password, bool isEncrypt) {

        constexpr std::size_t BUF_SIZE = 16;
            
        if (!inStream) {
            throw std::runtime_error("inStream not good");
        }
        if (!outStream) {
            throw std::runtime_error("outStream not good");
        }
        
        auto ctxDeleter = [](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); };
        std::unique_ptr<EVP_CIPHER_CTX, decltype(ctxDeleter)> ctx{EVP_CIPHER_CTX_new()};

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = isEncrypt;

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error("EVP_CipherInit_ex return error. " + getOpenSslError());
        }

        std::array<unsigned char, BUF_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf{};
        std::array<unsigned char, BUF_SIZE> inBuf{};
        int outLen, inLen;

        while (!inStream.eof()) {

            if (!inStream) {
                throw std::runtime_error("inStream not good");
            }

            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            inLen = inStream.gcount();
            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(inLen))) {
                throw std::runtime_error("EVP_CipherUpdate return error. " + getOpenSslError());
            }
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);

            if (!outStream) {
                throw std::runtime_error("outStream not good");
            }
        }
        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error("EVP_CipherFinal_ex return error. " + getOpenSslError());
        }
        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
    }

    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        DoCrypt(inStream, outStream, password, true);
    }
    void DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        DoCrypt(inStream, outStream, password, false);
    }
    [[nodiscard]] std::string CalculateChecksum(std::istream &inStream) {
        
        constexpr std::size_t BUF_SIZE = 16;

        if (!inStream) {
            throw std::runtime_error("inStream not good");
        }
            
        const auto md = EVP_sha256();
        if (md == NULL) {
            throw std::runtime_error("Unsupported digest algorithm. " + getOpenSslError());
        }
        
        auto ctxDeleter = [](EVP_MD_CTX *ptr) { EVP_MD_CTX_free(ptr); };
        std::unique_ptr<EVP_MD_CTX, decltype(ctxDeleter)> ctx{EVP_MD_CTX_new()};
        if (!EVP_DigestInit_ex2(ctx.get(), md, NULL)) {
            throw std::runtime_error("Message digest initialization failed.. " + getOpenSslError());
        }

        std::array<unsigned char, BUF_SIZE> inBuf{};

        int inLen;
        while (!inStream.eof()) {
            if (!inStream) {
                throw std::runtime_error("inStream not good");
            }
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            inLen = inStream.gcount();
            if (!EVP_DigestUpdate(ctx.get(), inBuf.data(), static_cast<int>(inLen))) {
                throw std::runtime_error("EVP_DigestUpdate return error. " + getOpenSslError());
            }
        }
        unsigned int md_len;
        std::array<unsigned char, EVP_MAX_MD_SIZE> md_value{};

        if (!EVP_DigestFinal_ex(ctx.get(), md_value.data(), &md_len)) {
            throw std::runtime_error("EVP_CipherFinal_ex return error. " + getOpenSslError());
        }
        std::stringstream out{};
        out << std::hex << std::setfill('0');
        for (auto i = 0; md_len > i; i++) {
            out << std::setw(2) << std::hex << static_cast<int>(md_value[i]);
        }
        return out.str();
    }

    std::string getOpenSslError() {
        if (auto error = ERR_get_error(); !error) {
            std::array<char, 256> buffer{};
            ERR_error_string_n(error, buffer.data(), buffer.size());
            return std::to_string(error) + " " + std::string(buffer.data());
        }
        return "Unknown OpenSSL error";
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<CryptoGuardCtx::Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
