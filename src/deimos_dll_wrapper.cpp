#include "deimos_cipher.h"
#include <cstring>
#include <cstdlib>

// C-style wrapper functions for Python ctypes integration
extern "C" {
    
    // Structure to return encrypted data with length
    struct EncryptedData {
        uint8_t* data;
        size_t length;
    };
    
    // Structure to return decrypted string with length
    struct DecryptedData {
        char* data;
        size_t length;
        int success; // 1 for success, 0 for failure
    };
    
    // Encrypt function wrapper
    __declspec(dllexport) EncryptedData* deimos_encrypt(const char* plaintext, const char* password) {
        try {
            std::string plaintextStr(plaintext);
            std::string passwordStr(password);
            
            std::vector<uint8_t> ciphertext = deimosCipherEncrypt(plaintextStr, passwordStr);
            
            // Allocate memory for the result
            EncryptedData* result = (EncryptedData*)malloc(sizeof(EncryptedData));
            result->length = ciphertext.size();
            result->data = (uint8_t*)malloc(result->length);
            
            // Copy the data
            memcpy(result->data, ciphertext.data(), result->length);
            
            return result;
        } catch (const std::exception& e) {
            // Return null on error
            return nullptr;
        }
    }
    
    // Decrypt function wrapper
    __declspec(dllexport) DecryptedData* deimos_decrypt(const uint8_t* ciphertext, size_t ciphertext_length, const char* password) {
        try {
            std::vector<uint8_t> ciphertextVec(ciphertext, ciphertext + ciphertext_length);
            std::string passwordStr(password);
            
            std::string plaintext = deimosCipherDecrypt(ciphertextVec, passwordStr);
            
            // Allocate memory for the result
            DecryptedData* result = (DecryptedData*)malloc(sizeof(DecryptedData));
            
            // Check if decryption failed (error messages start with "Error:")
            if (plaintext.substr(0, 6) == "Error:") {
                result->success = 0;
                result->length = plaintext.length();
                result->data = (char*)malloc(result->length + 1);
                strcpy(result->data, plaintext.c_str());
            } else {
                result->success = 1;
                result->length = plaintext.length();
                result->data = (char*)malloc(result->length + 1);
                strcpy(result->data, plaintext.c_str());
            }
            
            return result;
        } catch (const std::exception& e) {
            // Return error result
            DecryptedData* result = (DecryptedData*)malloc(sizeof(DecryptedData));
            result->success = 0;
            result->length = strlen(e.what());
            result->data = (char*)malloc(result->length + 1);
            strcpy(result->data, e.what());
            return result;
        }
    }
    
    // Memory cleanup functions
    __declspec(dllexport) void free_encrypted_data(EncryptedData* data) {
        if (data) {
            if (data->data) {
                free(data->data);
            }
            free(data);
        }
    }
    
    __declspec(dllexport) void free_decrypted_data(DecryptedData* data) {
        if (data) {
            if (data->data) {
                free(data->data);
            }
            free(data);
        }
    }
    
    // Initialize libsodium (call this once at startup)
    __declspec(dllexport) int deimos_init() {
        return sodium_init();
    }
}