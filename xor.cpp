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
#include <openssl/sha.h>
#include <openssl/hmac.h>

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
            std::from_chars(hex.data() + i, hex.data() + i + 2, byte, 16);
            value.push_back(static_cast<char>(byte));
        }
    }
    operator std::string() const { return value; }
};

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

std::string pbkdf2(const std::string& password, const std::string& salt, size_t keyLength, int iterations) {
    std::array<unsigned char, KEY_SIZE> key{};
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(),
        reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
        iterations, keyLength, key.data());
    return std::string(reinterpret_cast<char*>(key.data()), keyLength);
}

std::string hmacSha256(const std::string& key, const std::string& message) {
    std::array<unsigned char, MAC_SIZE> mac{};
    unsigned int macLength = 0;

    HMAC(EVP_sha256(), key.data(), key.size(),
        reinterpret_cast<const unsigned char*>(message.data()), message.size(),
        mac.data(), &macLength);

    return std::string(reinterpret_cast<char*>(mac.data()), macLength);
}

std::string feistelEncryptDecrypt(const std::string& input, const std::string& key) {
    size_t halfSize = input.size() / 2;
    std::string left = input.substr(0, halfSize);
    std::string right = input.substr(halfSize);

    for (int i = 0; i < FEISTEL_ROUNDS; ++i) {
        std::string temp = right;
        std::string roundKey = key + std::to_string(i);
        right = hmacSha256(roundKey, right).substr(0, right.size());
        std::transform(right.begin(), right.end(), left.begin(), right.begin(),
            [](char r, char l) { return r ^ l; });
        right = left;
        left = temp;
    }
    return left + right;
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
    const std::string clear = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.Praesent rutrum, dolor in sollicitudin scelerisque, tortor risus convallis orci, in cursus odio enim sit amet nulla.";
    std::string input;

    while (std::getline(inputFile, input)) {
        try {
            if (input.starts_with("EN$")) {
                std::string rawText = input.substr(3);
                std::string salt = generateRandomBytes(SALT_SIZE);
                std::string key = pbkdf2(password, salt, KEY_SIZE, PBKDF2_ITERATIONS);
                std::string mac = hmacSha256(key, rawText);
                std::string dataWithMac = rawText + mac;
                std::string encrypted = feistelEncryptDecrypt(dataWithMac, key);
                processedStrings.emplace_back(HexEncoded{ salt + encrypted });
                salt = key = mac = dataWithMac = encrypted = clear;
            }
            else {
                std::string decoded = HexDecoded{ input };
                if (decoded.size() < SALT_SIZE) {
                    processedStrings.emplace_back("Invalid input format");
                    continue;
                }
                std::string salt = decoded.substr(0, SALT_SIZE);
                std::string encryptedData = decoded.substr(SALT_SIZE);
                std::string key = pbkdf2(password, salt, KEY_SIZE, PBKDF2_ITERATIONS);
                std::string decryptedData = feistelEncryptDecrypt(encryptedData, key);
                if (decryptedData.size() < MAC_SIZE) {
                    processedStrings.emplace_back("Invalid decrypted data size");
                    decryptedData = key = encryptedData = salt = clear;
                    continue;
                }
                std::string plaintext = decryptedData.substr(0, decryptedData.size() - MAC_SIZE);
                std::string receivedMac = decryptedData.substr(decryptedData.size() - MAC_SIZE);
                std::string computedMac = hmacSha256(key, plaintext);
                if (!secureCompare(computedMac, receivedMac)) {
                    processedStrings.emplace_back("MAC verification failed: Possible tampering");
                    plaintext = decryptedData = key = encryptedData = salt = clear;
                    continue;
                }
                processedStrings.emplace_back("EN$" + plaintext);
                plaintext = decryptedData = key = encryptedData = salt = clear;
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
    processedStrings.clear();
    for (int i = 0; i < 24; ++i) {
        processedStrings.emplace_back(clear);
    }
    std::cin.get();
    return 0;
}
