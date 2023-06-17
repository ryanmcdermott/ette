#include "crypto.h"
#include "constants.h"
#include "third_party/picosha2/picosha2.h"
#include "third_party/plusaes/plusaes.h"

#include <stdlib.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <string>
#include <vector>

using ::ette::CryptoAlgorithm;
using ::ette::CryptoState;
using ::ette::Status;
using ::ette::StatusCode;

namespace ette {
inline bool IsSystemLittleEndian() {
    const int value{0x01};
    const void* address = static_cast<const void*>(&value);
    const unsigned char* least_significant_address =
        static_cast<const unsigned char*>(address);
    return (*least_significant_address == 0x01);
}

uint64_t GetPlaintextSizeFromCiphertext(const std::string& ciphertext) {
    // Check if the ciphertext is at least 8 bytes
    if (ciphertext.size() < 8) {
        // Handle the error appropriately
        return 0;
    }

    // Get first 8 bytes of ciphertext
    unsigned char cstr[8] = {static_cast<unsigned char>(ciphertext[0]),
                             static_cast<unsigned char>(ciphertext[1]),
                             static_cast<unsigned char>(ciphertext[2]),
                             static_cast<unsigned char>(ciphertext[3]),
                             static_cast<unsigned char>(ciphertext[4]),
                             static_cast<unsigned char>(ciphertext[5]),
                             static_cast<unsigned char>(ciphertext[6]),
                             static_cast<unsigned char>(ciphertext[7])};

    if (IsSystemLittleEndian()) {
        // Little-endian system
        return static_cast<uint64_t>(cstr[0]) << 56 |
               static_cast<uint64_t>(cstr[1]) << 48 |
               static_cast<uint64_t>(cstr[2]) << 40 |
               static_cast<uint64_t>(cstr[3]) << 32 |
               static_cast<uint64_t>(cstr[4]) << 24 |
               static_cast<uint64_t>(cstr[5]) << 16 |
               static_cast<uint64_t>(cstr[6]) << 8 |
               static_cast<uint64_t>(cstr[7]);
    } else {
        // Big-endian system
        return static_cast<uint64_t>(cstr[7]) << 56 |
               static_cast<uint64_t>(cstr[6]) << 48 |
               static_cast<uint64_t>(cstr[5]) << 40 |
               static_cast<uint64_t>(cstr[4]) << 32 |
               static_cast<uint64_t>(cstr[3]) << 24 |
               static_cast<uint64_t>(cstr[2]) << 16 |
               static_cast<uint64_t>(cstr[1]) << 8 |
               static_cast<uint64_t>(cstr[0]);
    }
}

CryptoState CreateEmptyCryptoState() {
    CryptoState crypto_state;
    crypto_state.raw_key = "";
    crypto_state.hashed_key = "";
    crypto_state.plaintext = "";
    crypto_state.ciphertext = "";
    crypto_state.iv = {};
    crypto_state.ciphertext_size = 0;
    crypto_state.plaintext_size = 0;
    crypto_state.algorithm = CryptoAlgorithm::kDefaultNone;
    crypto_state.status = Status<void>(StatusCode::kOk, "");
    return crypto_state;
}

CryptoState CreateCryptoStateWithStatus(const StatusCode status_code,
                                        const std::string& message) {
    CryptoState crypto_state = CreateEmptyCryptoState();
    crypto_state.status = Status<void>(status_code, message);
    return crypto_state;
}

std::string HashRawKey(std::string raw_key) {
    const std::string hashed_key = picosha2::hash256_hex_string(raw_key);
    // Return only 128 bits of the Sha256 hash
    return hashed_key.substr(0, 32);
}

std::string ConstructPlaintextSizeHeaderForCiphertext(
    const uint64_t plaintext_size) {
    std::string header;

    if (IsSystemLittleEndian()) {
        // Little-endian system
        header += (plaintext_size >> 56) & 0xFF;
        header += (plaintext_size >> 48) & 0xFF;
        header += (plaintext_size >> 40) & 0xFF;
        header += (plaintext_size >> 32) & 0xFF;
        header += (plaintext_size >> 24) & 0xFF;
        header += (plaintext_size >> 16) & 0xFF;
        header += (plaintext_size >> 8) & 0xFF;
        header += plaintext_size & 0xFF;
    } else {
        // Big-endian system
        header += plaintext_size & 0xFF;
        header += (plaintext_size >> 8) & 0xFF;
        header += (plaintext_size >> 16) & 0xFF;
        header += (plaintext_size >> 24) & 0xFF;
        header += (plaintext_size >> 32) & 0xFF;
        header += (plaintext_size >> 40) & 0xFF;
        header += (plaintext_size >> 48) & 0xFF;
        header += (plaintext_size >> 56) & 0xFF;
    }
    return header;
}

CryptoState SetupCryptoStateFromCiphertextAES256CBC(std::string ciphertext,
                                                    std::string raw_key,
                                                    CryptoAlgorithm algorithm) {
    if (ciphertext.size() < kHeaderSize) {
        return CreateCryptoStateWithStatus(
            StatusCode::kInvalidDataSize,
            "Ciphertext is too small to contain header");
    }

    if (raw_key.empty()) {
        return CreateCryptoStateWithStatus(StatusCode::kInvalidKeySize,
                                           "Key is empty");
    }

    ciphertext.erase(0, sizeof(kHeaderMagicNumber) +
                            kHeaderCryptoAlgorithmSize + kHeaderVersionSize);

    // Get plaintext size from first 8 bytes of ciphertext and erase first 8 bytes
    uint64_t plaintext_size = GetPlaintextSizeFromCiphertext(ciphertext);
    ciphertext.erase(0, kHeaderPlaintextSize);

    // Remove first 16 bytes from ciphertext and store as IV
    std::vector<unsigned char> iv;
    for (uint32_t i = 0; i < kHeaderIvSize; i++) {
        iv.push_back(ciphertext[i]);
    }
    ciphertext.erase(0, kHeaderIvSize);

    CryptoState state;
    state.ciphertext = ciphertext;
    state.raw_key = raw_key;
    state.hashed_key = HashRawKey(raw_key);
    state.iv = iv;
    state.plaintext_size = plaintext_size;
    state.ciphertext_size = ciphertext.size();
    state.algorithm = algorithm;
    state.status = Status<void>(StatusCode::kOk, "");
    return state;
}

CryptoState SetupCryptoStateFromCiphertext(std::string ciphertext,
                                           std::string raw_key,
                                           CryptoAlgorithm algorithm) {
    switch (algorithm) {
        case CryptoAlgorithm::kAES256CBC:
            return SetupCryptoStateFromCiphertextAES256CBC(ciphertext, raw_key,
                                                           algorithm);
        default:
            return CryptoState();
    }
}

std::vector<unsigned char> GenerateRandomAsciiByteVector() {
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<unsigned char> dist(0, 255);

    std::vector<unsigned char> random_ascii;
    for (uint32_t i = 0; i < kHeaderIvSize; i++) {
        random_ascii.push_back(dist(gen));
    }
    return random_ascii;
}

CryptoState EncryptAES256CBC(const std::string& plaintext,
                             const std::string& raw_key,
                             const std::vector<unsigned char>& raw_iv) {
    if (raw_key.empty()) {
        return CreateCryptoStateWithStatus(StatusCode::kInvalidKeySize,
                                           "Key is empty");
    }

    const uint64_t plaintext_size = plaintext.size();

    const std::string key = HashRawKey(raw_key);

    // Construct a null terminated IV unsigned char array.
    unsigned char iv[kHeaderIvSize];
    memcpy(iv, raw_iv.data(), sizeof(iv));
    iv[kHeaderIvSize - 1] = '\0';

    char key_char[33];
    memcpy(key_char, key.c_str(), sizeof(key_char));
    const std::vector<unsigned char> key_vector =
        plusaes::key_from_string(&key_char);

    const unsigned long ciphertext_size =
        plusaes::get_padded_encrypted_size(plaintext_size);
    std::vector<unsigned char> ciphertext(ciphertext_size);

    plusaes::Error status = plusaes::encrypt_cbc(
        (unsigned char*)plaintext.data(), plaintext_size, &key_vector[0],
        key_vector.size(), &iv, &ciphertext[0], ciphertext_size, true);

    if (status != plusaes::Error::kErrorOk) {
        switch (status) {
            case plusaes::Error::kErrorInvalidKey:
                return CreateCryptoStateWithStatus(StatusCode::kInvalidKey,
                                                   "Key is incorrect");
            case plusaes::Error::kErrorInvalidKeySize:
                return CreateCryptoStateWithStatus(StatusCode::kInvalidKeySize,
                                                   "Key is not 256 bits");
            case plusaes::Error::kErrorInvalidIvSize:
                return CreateCryptoStateWithStatus(StatusCode::kInvalidIvSize,
                                                   "IV is not 128 bits");
            default:
                return CreateCryptoStateWithStatus(StatusCode::kUnknownError,
                                                   "Unknown error");
        }
    }

    // Add header indicating how many bytes of plaintext were encrypted.
    std::string ciphertext_str;

    ciphertext_str += std::string(kHeaderMagicNumber);
    ciphertext_str += std::string("1");
    ciphertext_str += std::to_string(kVersionMajor);
    ciphertext_str += std::to_string(kVersionMinor);
    ciphertext_str += std::to_string(kVersionPatch);

    ciphertext_str += ConstructPlaintextSizeHeaderForCiphertext(plaintext_size);

    // Add IV to ciphertext
    for (uint32_t i = 0; i < kHeaderIvSize; i++) {
        ciphertext_str += iv[i];
    }

    // Add encrypted data to ciphertext
    for (uint32_t i = 0; i < ciphertext_size; i++) {
        ciphertext_str += ciphertext[i];
    }
    CryptoState state;
    state.raw_key = raw_key;
    state.hashed_key = key;
    state.plaintext = plaintext;
    state.ciphertext = ciphertext_str;
    state.iv = raw_iv;
    state.ciphertext_size = ciphertext_size;
    state.plaintext_size = plaintext_size;
    state.algorithm = CryptoAlgorithm::kAES256CBC;
    state.status = Status<void>(StatusCode::kOk, "");
    return state;
}

CryptoState Encrypt(const std::string& plaintext, const std::string& key,
                    const std::vector<unsigned char>& iv,
                    CryptoAlgorithm algorithm) {
    switch (algorithm) {
        case CryptoAlgorithm::kAES256CBC:
            return EncryptAES256CBC(plaintext, key, iv);
        default:
            return CryptoState();
    }
}

CryptoState DecryptAES256CBC(std::string ciphertext, std::string raw_key,
                             CryptoAlgorithm algorithm) {
    const CryptoState state =
        SetupCryptoStateFromCiphertextAES256CBC(ciphertext, raw_key, algorithm);

    if (!state.status.ok() &&
        (state.status.error().code() == StatusCode::kInvalidDataSize ||
         state.status.error().code() == StatusCode::kInvalidKeySize)) {
        return state;
    }

    unsigned char iv[kHeaderIvSize];
    memcpy(iv, state.iv.data(), sizeof(iv));
    iv[kHeaderIvSize - 1] = '\0';

    unsigned long padded_size = 0;
    const uint64_t plaintext_size = state.plaintext_size;
    if (plaintext_size == 0) {
        CryptoState crypto_state;
        crypto_state.raw_key = state.raw_key;
        crypto_state.hashed_key = state.hashed_key;
        crypto_state.plaintext = std::string("");
        crypto_state.ciphertext = state.ciphertext;
        crypto_state.iv = state.iv;
        crypto_state.ciphertext_size = state.ciphertext_size;
        crypto_state.plaintext_size = plaintext_size;
        crypto_state.algorithm = CryptoAlgorithm::kAES256CBC;
        crypto_state.status = Status<void>(StatusCode::kOk, "");
        return crypto_state;
    }

    std::vector<unsigned char> decrypted(plaintext_size);
    plusaes::Error status = plusaes::decrypt_cbc(
        reinterpret_cast<const unsigned char*>(state.ciphertext.data()),
        state.ciphertext_size,
        reinterpret_cast<const unsigned char*>(state.hashed_key.data()),
        state.hashed_key.size(), &iv, &decrypted[0], plaintext_size,
        &padded_size);

    if (status != plusaes::Error::kErrorOk) {
        switch (status) {
            case plusaes::Error::kErrorInvalidKey:
                return CreateCryptoStateWithStatus(StatusCode::kInvalidKey,
                                                   "Key is incorrect");

            case plusaes::Error::kErrorInvalidKeySize:
                return CreateCryptoStateWithStatus(StatusCode::kInvalidKeySize,
                                                   "Key is not 256 bits");

            case plusaes::Error::kErrorInvalidIvSize:
                return CreateCryptoStateWithStatus(StatusCode::kInvalidIvSize,
                                                   "IV is not 128 bits");

            default:
                return CreateCryptoStateWithStatus(StatusCode::kUnknownError,
                                                   "Unknown error");
        }
    }

    const std::string plaintext(decrypted.begin(), decrypted.end());

    CryptoState crypto_state;
    crypto_state.raw_key = state.raw_key;
    crypto_state.hashed_key = state.hashed_key;
    crypto_state.plaintext = plaintext;
    crypto_state.ciphertext = state.ciphertext;
    crypto_state.iv = state.iv;
    crypto_state.ciphertext_size = state.ciphertext_size;
    crypto_state.plaintext_size = plaintext_size;
    crypto_state.algorithm = CryptoAlgorithm::kAES256CBC;
    crypto_state.status = Status<void>(StatusCode::kOk, "");
    return crypto_state;
}

CryptoState Decrypt(std::string ciphertext, std::string raw_key,
                    CryptoAlgorithm algorithm) {
    switch (algorithm) {
        case CryptoAlgorithm::kAES256CBC:
            return DecryptAES256CBC(ciphertext, raw_key, algorithm);
        default:
            return CryptoState();
    }
}

std::optional<std::string> ReadFileToString(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    const std::string content((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
    return content;
}

bool IsKeyCorrect(const std::string& key, const std::string& path,
                  CryptoAlgorithm algorithm) {
    const auto result = ReadFileToString(path);
    if (!result.has_value()) {
        return false;
    }

    const std::string ciphertext = result.value();

    const CryptoState state = Decrypt(ciphertext, key, algorithm);
    return state.status.ok();
}
}  // namespace ette