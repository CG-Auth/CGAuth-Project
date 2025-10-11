/**
 * CGAuth Header File - C++ License Authentication Library
 * 
 * Provides hardware-based license authentication with encryption
 * Uses WMI for HWID generation and OpenSSL for cryptographic operations
 */

#pragma once

#include <string>
#include <windows.h>       // Windows API functions
#include <wbemidl.h>        // Windows Management Instrumentation (WMI)
#include <comdef.h>         // COM definitions
#include <nlohmann/json.hpp> // JSON library for C++
#include <openssl/sha.h>    // SHA256 hashing
#include <openssl/aes.h>    // AES encryption
#include <openssl/rand.h>   // Random number generation
#include <openssl/hmac.h>   // HMAC signature
#include <curl/curl.h>      // HTTP requests
#include <sstream>          // String streams
#include <iomanip>          // I/O manipulators
#include <iostream>         // Standard I/O

// Link required libraries
#pragma comment(lib, "wbemuuid.lib")  // WMI library
#pragma comment(lib, "libcurl.lib")   // cURL library
#pragma comment(lib, "libssl.lib")    // OpenSSL SSL library
#pragma comment(lib, "libcrypto.lib") // OpenSSL Crypto library

using json = nlohmann::json;

/**
 * CGAuth Class - Main authentication class
 * 
 * Provides static methods for:
 * - Hardware ID (HWID) generation
 * - Payload encryption/decryption
 * - HMAC verification
 * - License and user authentication
 */
class CGAuth {
private:
    // ========================================================================
    // CONFIGURATION CONSTANTS
    // ========================================================================
    
    /** @brief Base URL for CGAuth API endpoints */
    static const std::string API_URL;
    
    /** @brief Your application name - must match license configuration */
    static const std::string YOUR_APP_NAME;
    
    /** @brief API Key for authentication - public identifier */
    static std::string API_KEY;
    
    /** @brief API Secret for encryption and HMAC - MUST be kept private */
    static std::string API_SECRET;
    
    /** @brief Expected SSL certificate hash for certificate pinning */
    static const std::string SSL_KEY;

    // ========================================================================
    // HELPER FUNCTIONS (Private)
    // ========================================================================
    
    /**
     * Convert binary data to hexadecimal string
     * @param data Binary data array
     * @param len Length of data
     * @return Hexadecimal string representation
     */
    static std::string ToHex(const unsigned char* data, size_t len);
    
    /**
     * Convert string to uppercase
     * @param str Input string
     * @return Uppercase version of input
     */
    static std::string ToUpper(std::string str);
    
    /**
     * Retrieve WMI (Windows Management Instrumentation) property
     * Used to get hardware information like processor ID, serial numbers
     * 
     * @param wmiClass WMI class name (e.g., "Win32_Processor")
     * @param property Property to retrieve (e.g., "ProcessorId")
     * @return Property value as string
     */
    static std::string GetWMIProperty(const std::string& wmiClass, const std::string& property);
    
    /**
     * cURL write callback function
     * Called by cURL to write received data
     * 
     * @param contents Data buffer
     * @param size Size of each element
     * @param nmemb Number of elements
     * @param userp User pointer (output string)
     * @return Number of bytes written
     */
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
    
    /**
     * Encode binary data to Base64
     * @param input Binary data to encode
     * @return Base64-encoded string
     */
    static std::string Base64Encode(const std::string& input);
    
    /**
     * Decode Base64 string to binary data
     * @param input Base64-encoded string
     * @return Decoded binary data
     */
    static std::string Base64Decode(const std::string& input);

public:
    // ========================================================================
    // PUBLIC API FUNCTIONS
    // ========================================================================
    
    /**
     * Generate unique Hardware ID (HWID)
     * 
     * Uses Windows WMI to collect:
     * - Processor ID
     * - Motherboard Serial Number
     * - BIOS Serial Number
     * 
     * Falls back to computer name + username if WMI fails
     * 
     * @return SHA256 hash of hardware information (uppercase hex)
     */
    static std::string GetHWID();
    
    /**
     * Encrypt payload using AES-256-CBC
     * 
     * Process:
     * 1. Convert JSON to string
     * 2. Derive 256-bit key from API_SECRET
     * 3. Generate random IV
     * 4. Encrypt with AES-256-CBC
     * 5. Combine IV + ciphertext
     * 6. Base64 encode
     * 
     * @param params JSON parameters to encrypt
     * @return Base64-encoded encrypted string
     */
    static std::string EncryptPayload(const json& params);
    
    /**
     * Decrypt AES-256-CBC encrypted payload
     * Reverses the encryption process
     * 
     * @param encrypted Base64-encoded encrypted string
     * @return Decrypted JSON string
     */
    static std::string DecryptPayload(const std::string& encrypted);
    
    /**
     * Verify HMAC-SHA256 signature
     * Ensures data integrity and prevents tampering
     * 
     * @param data Data to verify
     * @param hmac Received HMAC signature
     * @return true if HMAC is valid, false otherwise
     */
    static bool VerifyHMAC(const std::string& data, const std::string& hmac);
    
    /**
     * Authenticate using license key
     * 
     * Process:
     * 1. Encrypt authentication parameters
     * 2. Send POST request to API via cURL
     * 3. Verify timestamp (replay attack protection)
     * 4. Verify HMAC (data integrity)
     * 5. Decrypt response
     * 
     * @param licenseKey License key to validate
     * @param hwid Hardware ID of the machine
     * @return JSON object with authentication result
     */
    static json AuthLicense(const std::string& licenseKey, const std::string& hwid);
    
    /**
     * Authenticate using username and password
     * 
     * Process:
     * 1. Encrypt authentication parameters (including password)
     * 2. Send POST request to API via cURL
     * 3. Verify timestamp (replay attack protection)
     * 4. Verify HMAC (data integrity)
     * 5. Decrypt response
     * 
     * @param username User's username
     * @param password User's password
     * @param hwid Hardware ID of the machine
     * @return JSON object with authentication result
     */
    static json AuthUser(const std::string& username, const std::string& password, const std::string& hwid);
};