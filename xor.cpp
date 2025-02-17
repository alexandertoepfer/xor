#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <array>
#include <cstring>
#include <windows.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <charconv> // for std::from_chars (C++17 and later)

constexpr size_t SALT_SIZE = 32;
constexpr size_t KEY_SIZE = 32;
constexpr size_t IV_SIZE = 12;
constexpr int PBKDF2_ITERATIONS = 250000;
constexpr int FEISTEL_ROUNDS = 16;
constexpr size_t MAC_SIZE = SHA256_DIGEST_LENGTH;

struct HexEncoded {
    std::string value;
    explicit HexEncoded(std::string_view input) {
        std::ostringstream oss;
        for (unsigned char c : input) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        value = oss.str();
    }
    operator std::string() const { return value; }
};

struct HexDecoded {
    std::string value;
    explicit HexDecoded(std::string_view hex) {
        value.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            int byte;
            auto [ptr, ec] = std::from_chars(hex.data() + i, hex.data() + i + 2, byte, 16);
            // In a production system, check ec for errors.
            value.push_back(static_cast<char>(byte));
        }
    }
    operator std::string() const { return value; }
};

void ClearConsoleBuffer() {
    // Get handle to standard output
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE)
        return;

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
        return;

    // Calculate total number of character cells in the buffer
    DWORD consoleSize = csbi.dwSize.X * csbi.dwSize.Y;
    COORD topLeft = { 0, 0 };
    DWORD charsWritten;

    // Overwrite entire buffer with spaces
    FillConsoleOutputCharacter(hConsole, ' ', consoleSize, topLeft, &charsWritten);
    // Reset attributes (colors, etc.) to the current default
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, consoleSize, topLeft, &charsWritten);
    // Move the cursor to the top-left corner
    SetConsoleCursorPosition(hConsole, topLeft);
}

std::string generateRandomBytes(size_t length) {
    std::random_device rd;
    std::vector<unsigned char> buffer(length);
    for (auto& byte : buffer) {
        byte = static_cast<unsigned char>(rd() % 256);
    }
    return std::string(buffer.begin(), buffer.end());
}

std::string sha256(const std::string& input) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash{};
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash.data());
    return std::string(reinterpret_cast<char*>(hash.data()), hash.size());
}

// Derive a key of the given length using PBKDF2.
std::string pbkdf2(const std::string& password, const std::string& salt, size_t keyLength, int iterations) {
    std::vector<unsigned char> key(keyLength);
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
        reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
        iterations, EVP_sha256(), keyLength, key.data());
    return std::string(reinterpret_cast<char*>(key.data()), keyLength);
}

// Derive two independent subkeys from one long key.
std::pair<std::string, std::string> deriveSubkeys(const std::string& password, const std::string& salt) {
    // Derive 2 * KEY_SIZE bytes (e.g., 64 bytes if KEY_SIZE is 32)
    const size_t combinedKeySize = 2 * KEY_SIZE;
    std::string derived = pbkdf2(password, salt, combinedKeySize, PBKDF2_ITERATIONS);
    std::string encryptionKey = derived.substr(0, KEY_SIZE);
    std::string macKey = derived.substr(KEY_SIZE, KEY_SIZE);
    return { encryptionKey, macKey };
}

std::string hmacSha256(const std::string& key, const std::string& message) {
    std::array<unsigned char, MAC_SIZE> mac{};
    unsigned int macLength = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
        reinterpret_cast<const unsigned char*>(message.data()), message.size(),
        mac.data(), &macLength);
    return std::string(reinterpret_cast<char*>(mac.data()), macLength);
}

std::string feistelProcess(const std::string& input, const std::string& key, bool decrypt = false) {
    // Split the input into two halves.
    size_t halfSize = input.size() / 2;
    std::string L = input.substr(0, halfSize);
    std::string R = input.substr(halfSize);
    const int rounds = FEISTEL_ROUNDS;

    if (!decrypt) {
        // Encryption: apply rounds in forward order.
        for (int i = 0; i < rounds; i++) {
            // Generate a round-specific key.
            std::string roundKey = hmacSha256(key, std::to_string(i));
            // Compute the round function F(R, roundKey).
            std::string f = hmacSha256(roundKey, R);
            // Ensure f is exactly as long as L.
            f.resize(L.size(), '\0');

            // Compute newR = L XOR F(R, roundKey).
            std::string newR(L.size(), '\0');
            for (size_t j = 0; j < L.size(); j++) {
                newR[j] = L[j] ^ f[j];
            }
            // Update the halves.
            L = R;
            R = newR;
        }
    }
    else {
        // Decryption: apply rounds in reverse order.
        for (int i = rounds - 1; i >= 0; i--) {
            // Generate the same round-specific key.
            std::string roundKey = hmacSha256(key, std::to_string(i));
            // In decryption the round function is computed from L.
            std::string f = hmacSha256(roundKey, L);
            // Ensure f is exactly as long as R.
            f.resize(R.size(), '\0');

            // Compute original L = R XOR F(L, roundKey).
            std::string newL(R.size(), '\0');
            for (size_t j = 0; j < R.size(); j++) {
                newL[j] = R[j] ^ f[j];
            }
            // Reverse the swap.
            R = L;
            L = newL;
        }
    }
    return L + R;
}



bool secureCompare(const std::string& a, const std::string& b) {
    return (a.size() == b.size()) && (std::memcmp(a.data(), b.data(), a.size()) == 0);
}

int main() {
    std::string password;
    std::cout << "Enter password: ";
    std::getline(std::cin, password);

    std::ifstream inputFile("input.txt");
    if (!inputFile) {
        std::cerr << "Error: Unable to open input file." << std::endl;
        return 1;
    }

    std::vector<std::string> processedStrings;
    // This clear string is used later to overwrite sensitive data.
    const std::string clear = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.Praesent rutrum, dolor in sollicitudin scelerisque, tortor risus convallis orci, in cursus odio enim sit amet nulla.";
    std::string input;

    while (std::getline(inputFile, input)) {
        try {
            // If the line begins with "EN$", we encrypt the following text.
            if (input.starts_with("EN$")) {
                std::string rawText = input.substr(3);
                std::string salt = generateRandomBytes(SALT_SIZE);

                // Derive subkeys
                auto [encryptionKey, macKey] = deriveSubkeys(password, salt);

                // Compute MAC for the plaintext using macKey.
                std::string mac = hmacSha256(macKey, rawText);
                // Append the MAC to the plaintext.
                std::string dataWithMac = rawText + mac;
                // Encrypt the combined data using encryptionKey.
                std::string encrypted = feistelProcess(dataWithMac, encryptionKey);
                // Prepend the salt and then hex-encode the result.
                processedStrings.emplace_back(HexEncoded{ salt + encrypted });
            }
            else {
                // Otherwise, we assume the input is hex-encoded ciphertext.
                std::string decoded = HexDecoded{ input };
                if (decoded.size() < SALT_SIZE) {
                    processedStrings.emplace_back("Invalid input format");
                    continue;
                }
                // The salt is stored in the first SALT_SIZE bytes.
                std::string salt = decoded.substr(0, SALT_SIZE);
                std::string encryptedData = decoded.substr(SALT_SIZE);

                // Derive subkeys using the salt.
                auto [encryptionKey, macKey] = deriveSubkeys(password, salt);

                std::string decryptedData = feistelProcess(encryptedData, encryptionKey, true);
                if (decryptedData.size() < MAC_SIZE) {
                    processedStrings.emplace_back("Invalid decrypted data size");
                    continue;
                }
                // Separate out the plaintext and the appended MAC.
                std::string plaintext = decryptedData.substr(0, decryptedData.size() - MAC_SIZE);
                std::string receivedMac = decryptedData.substr(decryptedData.size() - MAC_SIZE);
                std::string computedMac = hmacSha256(macKey, plaintext);

                processedStrings.emplace_back("EN$" + plaintext);
            }
        }
        catch (const std::exception& e) {
            processedStrings.emplace_back(std::string("Error: ") + e.what());
        }
        catch (...) {
            processedStrings.emplace_back("Unknown error occurred");
        }
    }

    std::cout << "Processed output:\n";
    for (const auto& str : processedStrings) {
        std::cout << str << '\n';
    }

    // Overwrite sensitive data from memory.
    processedStrings.clear();
    for (int i = 0; i < 24; ++i) {
        processedStrings.emplace_back(clear);
    }

    std::cin.get();
    ClearConsoleBuffer();
    return 0;
}
