#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>

std::string toHex(const std::string& input) {
    std::ostringstream oss;
    for (unsigned char c : input)
        oss << std::hex << std::setw(2) << std::setfill('0') << int(c);
    return oss.str();
}

std::string fromHex(const std::string& hex) {
    std::string result;
    for (size_t i = 0; i < hex.size(); i += 2)
        result += static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16));
    return result;
}

std::string generateSalt(size_t length = 8) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    std::string salt;
    for (size_t i = 0; i < length; ++i)
        salt += static_cast<unsigned char>(dist(gen));

    return salt;
}

std::string encryptXOR(const std::string& plaintext, const std::string& key) {
    std::string result;
    for (size_t i = 0; i < plaintext.size(); ++i)
        result += plaintext[i] ^ key[i % key.size()];
    return result;
}

int main() {
    std::string password;
    std::cout << "Enter password: ";
    std::getline(std::cin, password);

    std::hash<std::string> hasher;
    std::string key = std::to_string(hasher(password));

    std::cout << "Enter ASCII strings (prefix with 'EN$' to encrypt, or enter encrypted text to decrypt):" << std::endl;
    std::vector<std::string> processedStrings;
    std::string input;
    while (std::getline(std::cin, input) && !input.empty()) {
        if (input.rfind("EN$", 0) == 0) {
            std::string rawText = input.substr(3);
            std::string salt = generateSalt(8);
            std::string saltedInput = salt + rawText;
            std::string encrypted = encryptXOR(saltedInput, key);
            processedStrings.push_back("EN$" + toHex(salt + encrypted));
        }
        else {
            try {
                std::string decrypted = fromHex(input);
                std::string receivedSalt = decrypted.substr(0, 8);
                std::string encryptedData = decrypted.substr(8);
                std::string decryptedText = encryptXOR(encryptedData, key);
                if (decryptedText.substr(0, receivedSalt.size()) == receivedSalt) {
                    processedStrings.push_back(decryptedText.substr(receivedSalt.size()));
                }
                else {
                    processedStrings.push_back("Decryption failed");
                }
            }
            catch (...) {
                processedStrings.push_back("Invalid input format");
            }
        }
    }

    std::cout << "Processed output:" << std::endl;
    for (const auto& str : processedStrings) {
        std::cout << str << std::endl;
    }

    return 0;
}
