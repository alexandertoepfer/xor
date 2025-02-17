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
#include <cstdio>       // for snprintf
#include <windows.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <charconv>     // for std::from_chars (C++17 and later)

constexpr size_t SALT_SIZE = 32;
constexpr size_t KEY_SIZE = 32;
constexpr int PBKDF2_ITERATIONS = 250000;
// Use an odd number of rounds.
constexpr int FEISTEL_ROUNDS = 17;
constexpr size_t MAC_SIZE = SHA256_DIGEST_LENGTH;
constexpr size_t COUNTER_SIZE = 10;  // 10-digit counter (as ASCII)
constexpr size_t LENGTH_SIZE = 4;    // 4 bytes to store the original payload length

struct HexEncoded {
    std::string value;
    explicit HexEncoded(std::string_view input) {
        std::ostringstream oss;
        for (unsigned char c : input) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(c);
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
            // In production, check ec for errors.
            value.push_back(static_cast<char>(byte));
        }
    }
    operator std::string() const { return value; }
};

void ClearConsoleBuffer() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE)
        return;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
        return;
    DWORD consoleSize = csbi.dwSize.X * csbi.dwSize.Y;
    COORD topLeft = { 0, 0 };
    DWORD charsWritten;
    FillConsoleOutputCharacter(hConsole, ' ', consoleSize, topLeft, &charsWritten);
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, consoleSize, topLeft, &charsWritten);
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
    SHA256(reinterpret_cast<const unsigned char*>(input.data()),
        input.size(), hash.data());
    return std::string(reinterpret_cast<char*>(hash.data()), hash.size());
}

// Derive a key of the given length using PBKDF2.
std::string pbkdf2(const std::string& password, const std::string& salt, size_t keyLength, int iterations) {
    std::vector<unsigned char> key(keyLength);
    PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()),
        static_cast<int>(salt.size()),
        iterations, EVP_sha256(), static_cast<int>(keyLength), key.data());
    return std::string(reinterpret_cast<char*>(key.data()), keyLength);
}

// Derive two subkeys from one long key.
std::pair<std::string, std::string> deriveSubkeys(const std::string& password, const std::string& saltAndCounter) {
    const size_t combinedKeySize = 2 * KEY_SIZE;
    std::string derived = pbkdf2(password, saltAndCounter, combinedKeySize, PBKDF2_ITERATIONS);
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

/// HKDF-like expansion function (simplified).
std::string hkdfExpand(const std::string& prk, const std::string& info, size_t length) {
    size_t hashLen = SHA256_DIGEST_LENGTH;
    size_t N = (length + hashLen - 1) / hashLen;
    std::string T;
    std::string okm;
    for (size_t i = 1; i <= N; i++) {
        std::string data = T + info + std::string(1, static_cast<char>(i));
        T = hmacSha256(prk, data);
        okm += T;
    }
    okm.resize(length);
    return okm;
}

/// Expand the master key into a vector of round keys.
std::vector<std::string> expandRoundKeys(const std::string& masterKey, int rounds, size_t roundKeyLen = SHA256_DIGEST_LENGTH) {
    const std::string info = "FeistelRoundKey";
    std::vector<std::string> roundKeys;
    std::string okm = hkdfExpand(masterKey, info, rounds * roundKeyLen);
    for (int i = 0; i < rounds; i++) {
        roundKeys.push_back(okm.substr(i * roundKeyLen, roundKeyLen));
    }
    return roundKeys;
}

/// Final mixing stage: XOR data with a fixed mask derived from the key (self-inverting).
std::string finalMix(const std::string& data, const std::string& key) {
    std::string mixingKey = hmacSha256(key, "finalmix");
    std::string output = data;
    for (size_t i = 0; i < output.size(); ++i) {
        output[i] ^= mixingKey[i % mixingKey.size()];
    }
    return output;
}

/// Feistel process (assumes input length is even).
std::string feistelProcess(const std::string& input, const std::string& key, bool decrypt = false) {
    std::vector<std::string> roundKeys = expandRoundKeys(key, FEISTEL_ROUNDS, SHA256_DIGEST_LENGTH);
    size_t halfSize = input.size() / 2;
    std::string L = input.substr(0, halfSize);
    std::string R = input.substr(halfSize);
    const int rounds = FEISTEL_ROUNDS;
    if (!decrypt) {
        for (int i = 0; i < rounds; i++) {
            std::string f = hmacSha256(roundKeys[i], R);
            f.resize(L.size(), '\0');
            std::string newR(L.size(), '\0');
            for (size_t j = 0; j < L.size(); j++) {
                newR[j] = L[j] ^ f[j];
            }
            L = R;
            R = newR;
        }
    }
    else {
        for (int i = rounds - 1; i >= 0; i--) {
            std::string f = hmacSha256(roundKeys[i], L);
            f.resize(R.size(), '\0');
            std::string newL(R.size(), '\0');
            for (size_t j = 0; j < R.size(); j++) {
                newL[j] = R[j] ^ f[j];
            }
            R = L;
            L = newL;
        }
    }
    return L + R;
}

bool secureCompare(const std::string& a, const std::string& b) {
    return (a.size() == b.size()) && (std::memcmp(a.data(), b.data(), a.size()) == 0);
}

// Convert a 32-bit integer to 4-byte big-endian string.
std::string intToBytes(uint32_t n) {
    char buf[4];
    buf[0] = (n >> 24) & 0xFF;
    buf[1] = (n >> 16) & 0xFF;
    buf[2] = (n >> 8) & 0xFF;
    buf[3] = n & 0xFF;
    return std::string(buf, 4);
}

// Convert a 4-byte big-endian string to a 32-bit integer.
uint32_t bytesToInt(const std::string& bytes) {
    if (bytes.size() != 4) return 0;
    uint32_t n = (static_cast<unsigned char>(bytes[0]) << 24) |
        (static_cast<unsigned char>(bytes[1]) << 16) |
        (static_cast<unsigned char>(bytes[2]) << 8) |
        (static_cast<unsigned char>(bytes[3]));
    return n;
}

int main() {
    std::string password;
    std::cout << "Enter password: ";
    std::getline(std::cin, password);

    // A simple message counter (per session) to ensure each encryption uses a new key.
    unsigned int messageCounter = 0;

    std::ifstream inputFile("input.txt");
    if (!inputFile) {
        std::cerr << "Error: Unable to open input file." << std::endl;
        return 1;
    }

    std::vector<std::string> processedStrings;
    const std::string clear = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.Praesent rutrum, dolor in sollicitudin scelerisque, tortor risus convallis orci, in cursus odio enim sit amet nulla.";
    std::string input;

    while (std::getline(inputFile, input)) {
        try {
            // Encryption path: lines beginning with "EN$"
            if (input.rfind("EN$", 0) == 0) {
                messageCounter++;
                // Format the counter as a fixed 10-digit ASCII string.
                char counterBuf[COUNTER_SIZE + 1] = { 0 };
                std::snprintf(counterBuf, sizeof(counterBuf), "%010u", messageCounter);
                std::string counter(counterBuf);

                std::string rawText = input.substr(3);
                std::string salt = generateRandomBytes(SALT_SIZE);

                // Derive subkeys from the password and (salt || counter)
                auto [encryptionKey, macKey] = deriveSubkeys(password, salt + counter);

                // Compute MAC over (plaintext || counter)
                std::string mac = hmacSha256(macKey, rawText + counter);
                // Build payload: plaintext || MAC
                std::string payload = rawText + mac;
                // Save original payload length.
                uint32_t origLen = payload.size();
                // If payload length is odd, pad with one extra byte so that its length is even.
                if (payload.size() % 2 != 0) {
                    payload.push_back('\0');
                }

                // Encrypt payload using the Feistel process and final mixing.
                std::string feistelEncrypted = feistelProcess(payload, encryptionKey, false);
                std::string encrypted = finalMix(feistelEncrypted, encryptionKey);

                // Build header: salt || origLen (4 bytes) -- counter is NOT included
                std::string header = salt + intToBytes(origLen);
                processedStrings.emplace_back(HexEncoded{ header + encrypted });
            }
            else {
                // Decryption path: input is hex-encoded ciphertext.
                // Increment the internal counter to re-create the same counter value used during encryption.
                messageCounter++;
                std::string decoded = HexDecoded{ input };
                // Expect header to contain: salt (SALT_SIZE) + origLen (4 bytes)
                if (decoded.size() < SALT_SIZE + LENGTH_SIZE) {
                    processedStrings.emplace_back("Invalid input format");
                    continue;
                }
                std::string salt = decoded.substr(0, SALT_SIZE);
                std::string lengthBytes = decoded.substr(SALT_SIZE, LENGTH_SIZE);
                uint32_t origLen = bytesToInt(lengthBytes);
                std::string encryptedData = decoded.substr(SALT_SIZE + LENGTH_SIZE);

                // Re-create the counter from the internal message counter.
                char counterBuf[COUNTER_SIZE + 1] = { 0 };
                std::snprintf(counterBuf, sizeof(counterBuf), "%010u", messageCounter);
                std::string counter(counterBuf);

                // Derive subkeys using the password and (salt || counter)
                auto [encryptionKey, macKey] = deriveSubkeys(password, salt + counter);

                // Reverse final mixing and then decrypt.
                std::string unmixed = finalMix(encryptedData, encryptionKey);
                std::string decryptedPayload = feistelProcess(unmixed, encryptionKey, true);

                // Ensure the decrypted payload is at least as long as the original payload.
                if (decryptedPayload.size() < origLen) {
                    processedStrings.emplace_back("Invalid decrypted data size");
                    continue;
                }
                // Remove any extra padding by taking only origLen bytes.
                std::string payload = decryptedPayload.substr(0, origLen);

                // Split payload into plaintext and MAC.
                if (payload.size() < MAC_SIZE) {
                    processedStrings.emplace_back("Invalid payload size");
                    continue;
                }
                size_t plainTextLen = payload.size() - MAC_SIZE;
                std::string plaintext = payload.substr(0, plainTextLen);
                std::string receivedMac = payload.substr(plainTextLen, MAC_SIZE);
                std::string computedMac = hmacSha256(macKey, plaintext + counter);

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
