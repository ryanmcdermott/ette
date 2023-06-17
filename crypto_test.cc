#include <fstream>

#include "crypto.h"
#include "third_party/picosha2/picosha2.h"

#include "gtest/gtest.h"

using ::ette::CryptoAlgorithm;
using ::ette::CryptoState;
using ::ette::Decrypt;
using ::ette::Encrypt;
using ::ette::GenerateRandomAsciiByteVector;
using ::ette::IsKeyCorrect;

TEST(Crypto, AES256CBC_Encrypt_Decrypt) {
    const std::string key = "somewhatlongkey";
    const std::string expected_plaintext =
        "The quick brown fox jumps over the lazy dog";

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);
    const CryptoState decrypted_state =
        Decrypt(encrypted_state.ciphertext, key, CryptoAlgorithm::kAES256CBC);

    EXPECT_EQ(decrypted_state.plaintext, expected_plaintext);
}

TEST(Crypto, AES256CBC_Encrypt_FixedOutput) {
    const std::string key = "somewhatlongkey";
    const std::string expected_plaintext =
        "The quick brown fox jumps over the lazy dog";

    const std::vector<unsigned char> iv = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, iv, CryptoAlgorithm::kAES256CBC);
    const std::string hashed_ciphertext =
        picosha2::hash256_hex_string(encrypted_state.ciphertext);

    EXPECT_EQ(
        hashed_ciphertext,
        "c590210e14959c813cd948f0f1462518ed14217b17090db985fd9c0a5d77024f");
}

TEST(Crypto, AES256CBC_Encrypt_Decrypt_Unicode) {
    const std::string key = "somewhatlongkey";
    const std::string expected_plaintext = "こんにちは元気ですか😀 🤣";

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);
    const CryptoState decrypted_state =
        Decrypt(encrypted_state.ciphertext, key, CryptoAlgorithm::kAES256CBC);

    EXPECT_EQ(decrypted_state.plaintext, expected_plaintext);
}

TEST(Crypto, AES256CBC_Encrypt_Decrypt_SingleCharacterPlaintext) {
    const std::string key = "somewhatlongkey";
    const std::string expected_plaintext = "a";

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);
    const CryptoState decrypted_state =
        Decrypt(encrypted_state.ciphertext, key, CryptoAlgorithm::kAES256CBC);

    EXPECT_EQ(decrypted_state.plaintext, expected_plaintext);
}

TEST(Crypto, AES256CBC_Encrypt_Decrypt_EmptyPlaintext) {
    const std::string key = "somewhatlongkey";
    const std::string expected_plaintext = "";

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);
    const CryptoState decrypted_state =
        Decrypt(encrypted_state.ciphertext, key, CryptoAlgorithm::kAES256CBC);

    EXPECT_EQ(decrypted_state.plaintext, expected_plaintext);
}

TEST(Crypto, AES256CBC_Encrypt_Decrypt_MultilinePlaintext) {
    const std::string key = "somewhatlongkey";
    const std::string expected_plaintext =
        R"(
            To be, or not to be, that is the question:
            Whether 'tis nobler in the mind to suffer
            The slings and arrows of outrageous fortune,
            Or to take arms against a sea of troubles
            And by opposing end them. To die—to sleep,
            No more; and by a sleep to say we end
            The heart-ache and the thousand natural shocks
            That flesh is heir to: 'tis a consummation
            Devoutly to be wish'd. To die, to sleep;
            To sleep, perchance to dream—ay, there's the rub:
            For in that sleep of death what dreams may come,
            When we have shuffled off this mortal coil,
            Must give us pause—there's the respect
            That makes calamity of so long life.
            For who would bear the whips and scorns of time,
            Th'oppressor's wrong, the proud man's contumely,
            The pangs of dispriz'd love, the law's delay,
            The insolence of office, and the spurns
            That patient merit of th'unworthy takes,
            When he himself might his quietus make
            With a bare bodkin? Who would fardels bear,
            To grunt and sweat under a weary life,
            But that the dread of something after death,
            The undiscovere'd country, from whose bourn
            No traveller returns, puzzles the will,
            And makes us rather bear those ills we have
            Than fly to others that we know not of?
            Thus conscience doth make cowards of us all,
            And thus the native hue of resolution
            Is sicklied o'er with the pale cast of thought,
            And enterprises of great pith and moment
            With this regard their currents turn awry
            And lose the name of action.
        )";

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);
    const CryptoState decrypted_state =
        Decrypt(encrypted_state.ciphertext, key, CryptoAlgorithm::kAES256CBC);

    EXPECT_EQ(decrypted_state.plaintext, expected_plaintext);
}

TEST(Crypto, AES256CBC_Encrypt_Decrypt_LongKey) {
    const std::string key =
        "verylongkeyverylongkeyverylongkeyverylongkeyverylongkeyverylongkeyvery"
        "longkeyverylongkey";
    const std::string expected_plaintext =
        "The quick brown fox jumps over the lazy dog";

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);
    const CryptoState decrypted_state =
        Decrypt(encrypted_state.ciphertext, key, CryptoAlgorithm::kAES256CBC);

    EXPECT_EQ(decrypted_state.plaintext, expected_plaintext);
}

TEST(Crypto, AES256CBC_KeyEmptyError) {
    const std::string key = "";
    const std::string expected_plaintext =
        "The quick brown fox jumps over the lazy dog";

    const CryptoState state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);

    EXPECT_EQ(state.status.error().code(), ette::StatusCode::kInvalidKeySize);
}

TEST(Crypto, AES256CBC_KeyIncorrect) {
    const std::string key = "foo";
    const std::string incorrect_key = "bar";
    const std::string expected_plaintext =
        "The quick brown fox jumps over the lazy dog";

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);

    const CryptoState decrypted_state = Decrypt(
        encrypted_state.ciphertext, incorrect_key, CryptoAlgorithm::kAES256CBC);
    EXPECT_EQ(decrypted_state.status.error().code(),
              ette::StatusCode::kInvalidKey);
}

TEST(Crypto, AES256CBC_IsKeyCorrect_Correct) {
    std::string test_file = "/tmp/AES256CBC_IsKeyCorrect_Correct.ciphertext";
    const std::string key = "foo";
    const std::string expected_plaintext =
        "The quick brown fox jumps over the lazy dog";

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);

    std::remove(test_file.data());
    std::ofstream encrypted_state_file(test_file);
    encrypted_state_file << encrypted_state.ciphertext;
    encrypted_state_file.close();

    EXPECT_TRUE(IsKeyCorrect(key, test_file, CryptoAlgorithm::kAES256CBC));
    std::remove(test_file.data());
}

TEST(Crypto, AES256CBC_IsKeyCorrect_Incorrect) {
    std::string test_file = "/tmp/AES256CBC_IsKeyCorrect_Incorrect.ciphertext";
    const std::string key = "foo";
    const std::string incorrect_key = "bar";
    const std::string expected_plaintext =
        "The quick brown fox jumps over the lazy dog";

    const CryptoState encrypted_state =
        Encrypt(expected_plaintext, key, GenerateRandomAsciiByteVector(),
                CryptoAlgorithm::kAES256CBC);

    std::remove(test_file.data());
    std::ofstream encrypted_state_file(test_file);
    encrypted_state_file << encrypted_state.ciphertext;
    encrypted_state_file.close();

    EXPECT_FALSE(
        IsKeyCorrect(incorrect_key, test_file, CryptoAlgorithm::kAES256CBC));
    std::remove(test_file.data());
}

TEST(Crypto, AES256CBC_IsKeyCorrect_Malformed) {
    std::string test_file = "/tmp/AES256CBC_IsKeyCorrect_Malformed.ciphertext";
    const std::string key = "bar";

    std::remove(test_file.data());
    std::ofstream encrypted_state_file(test_file);
    encrypted_state_file << "malformed";
    encrypted_state_file.close();

    EXPECT_FALSE(IsKeyCorrect(key, test_file, CryptoAlgorithm::kAES256CBC));
    std::remove(test_file.data());
}