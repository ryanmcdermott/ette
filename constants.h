#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#include <cstdint>

namespace ette {

static constexpr uint8_t kVersionMajor = 0;
static constexpr uint8_t kVersionMinor = 0;
static constexpr uint8_t kVersionPatch = 1;
static constexpr char kVersionStr[] = "0.0.1";

/**
 * Header structure:
 * 4 bytes:  magic number
 * 1 byte:   crypto algorithm
 * 3 bytes:  encoded version
 * 8 bytes:  plaintext size
 * 16 bytes: iv
*/
static constexpr char kHeaderMagicNumber[] = {0x45, 0x54, 0x54, 0x45};  // ETTE
static constexpr uint64_t kHeaderCryptoAlgorithmSize = 1;
static constexpr uint64_t kHeaderPlaintextSize = 8;
static constexpr uint64_t kHeaderIvSize = 16;
static constexpr uint64_t kHeaderVersionSize =
    sizeof(kVersionMajor) + sizeof(kVersionMinor) + sizeof(kVersionPatch);
// Total header size: 32 bytes
static constexpr uint64_t kHeaderSize =
    sizeof(kHeaderMagicNumber) + kHeaderCryptoAlgorithmSize +
    kHeaderVersionSize + +kHeaderPlaintextSize + kHeaderIvSize;

}  // namespace ette
#endif  // __CONSTANTS_H__