#ifndef __CRYPTO_H__
#define __CRYPTO_H__
#include <string>
#include <vector>
#include "status.h"

namespace ette {
enum class CryptoAlgorithm { kDefaultNone, kAES256CBC };

struct CryptoState {
    std::string raw_key;
    std::string hashed_key;
    std::string plaintext;
    std::string ciphertext;
    std::vector<unsigned char> iv;
    unsigned long ciphertext_size;
    uint64_t plaintext_size;
    CryptoAlgorithm algorithm;
    ette::Status<void> status;
};

CryptoState Encrypt(const std::string& plaintext, const std::string& key,
                    const std::vector<unsigned char>& iv,
                    CryptoAlgorithm algorithm);

CryptoState Decrypt(std::string ciphertext, std::string raw_key,
                    CryptoAlgorithm algorithm);

std::vector<unsigned char> GenerateRandomAsciiByteVector();

bool IsKeyCorrect(const std::string& key, const std::string& path,
                  CryptoAlgorithm algorithm);
}  // namespace ette

#endif  // __CRYPTO_H__