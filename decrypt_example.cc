#include "crypto.h"
#include "status.h"

#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using ::ette::CryptoAlgorithm;
using ::ette::CryptoState;
using ::ette::Decrypt;
using ::ette::StatusCode;

std::optional<std::string> ReadFileToString(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return content;
}

int main(int argc, char* argv[]) {
    // Use first argument from argv as file path. Use second argument as password
    if (argc != 3) {
        std::cerr << "Usage: decrypt_example <filename> <password>"
                  << std::endl;
        exit(1);
    }

    // Read file contents into string.
    std::optional<std::string> file_contents = ReadFileToString(argv[1]);
    if (!file_contents) {
        std::cerr << "Could not read file: " << argv[1] << std::endl;
        exit(1);
    }

    std::string password = argv[2];

    // Decrypt file contents.
    const CryptoState state =
        Decrypt(*file_contents, password, CryptoAlgorithm::kAES256CBC);

    if (!state.status.ok()) {
        std::cerr << "Could not decrypt file: " << argv[1] << std::endl;
        exit(1);
    }

    std::cout << state.plaintext << std::endl;
}