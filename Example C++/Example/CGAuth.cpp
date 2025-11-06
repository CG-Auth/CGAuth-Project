/**
 * CGAuth Implementation File
 * 
 * Implements all authentication and cryptographic functions
 * for the CGAuth license system with Replay Attack Protection
 */

#include "CGAuth.h"

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

/** Base URL for CGAuth API endpoints */
const std::string CGAuth::API_URL = "https://cgauth.com/api/v1/";

/** Your application name - must match license configuration */
const std::string CGAuth::YOUR_APP_NAME = "PUBG";

/** API Key - public identifier for your application */
std::string CGAuth::API_KEY = "7a311cc779bd2500bfc29e7e3fd90027d2eb96d7225fe8932e0543ef7b23af01";

/** API Secret - used for encryption and HMAC (keep private!) */
std::string CGAuth::API_SECRET = "da14cd6591ce136dae7407e2087dca97a70eebf5fc3b4f2b2e8f779f2bf20b13";

/** SSL certificate hash for certificate pinning (prevents MITM attacks) */
const std::string CGAuth::SSL_KEY = "c43c660c3fc787c858e5df98743f607b88471689bf215fe197c5e7a40fea58ca";

// ============================================================================
// BASE64 HELPER FUNCTIONS
// ============================================================================

/**
 * Encode binary data to Base64 using OpenSSL BIO
 * Base64 encoding is used for safe transmission of binary data
 * 
 * @param input Binary data to encode
 * @return Base64-encoded string
 */
std::string CGAuth::Base64Encode(const std::string& input) {
    // Create BIO chain: base64 filter -> memory buffer
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    bio = BIO_push(b64, bio);

    // Write input data to BIO chain (automatically encodes)
    BIO_write(bio, input.c_str(), input.size());
    BIO_flush(bio);

    // Read encoded data from memory buffer
    char* encoded_data = nullptr;
    long encoded_len = BIO_get_mem_data(bio, &encoded_data);

    std::string result(encoded_data, encoded_len);
    BIO_free_all(bio);  // Free all BIOs in the chain

    return result;
}

/**
 * Decode Base64 string to binary data using OpenSSL BIO
 * 
 * @param input Base64-encoded string
 * @return Decoded binary data
 */
std::string CGAuth::Base64Decode(const std::string& input) {
    // Create BIO chain: memory buffer -> base64 filter
    BIO* bio = BIO_new_mem_buf(input.c_str(), input.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    bio = BIO_push(b64, bio);

    // Read and decode data
    char decoded[4096];
    int decoded_len = BIO_read(bio, decoded, 4096);
    BIO_free_all(bio);

    return std::string(decoded, decoded_len);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Convert binary data to hexadecimal string
 * Used for converting hash outputs to readable strings
 * 
 * @param data Binary data array
 * @param len Length of data in bytes
 * @return Hexadecimal string (lowercase)
 */
std::string CGAuth::ToHex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');  // Hex format with leading zeros
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << (int)data[i];  // 2 characters per byte
    }
    return ss.str();
}

/**
 * Convert string to uppercase
 * 
 * @param str Input string
 * @return Uppercase version of input
 */
std::string CGAuth::ToUpper(std::string str) {
    for (auto& c : str) c = toupper(c);
    return str;
}

/**
 * Retrieve Windows Management Instrumentation (WMI) property
 * 
 * WMI is used to query hardware information from Windows
 * This function can retrieve any WMI property like:
 * - Processor ID
 * - Motherboard Serial Number
 * - BIOS Serial Number
 * 
 * @param wmiClass WMI class name (e.g., "Win32_Processor")
 * @param property Property to retrieve (e.g., "ProcessorId")
 * @return Property value as string, or empty string on failure
 */
std::string CGAuth::GetWMIProperty(const std::string& wmiClass, const std::string& property) {
    HRESULT hres;
    std::string result = "";

    // Initialize COM library (required for WMI)
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return "";

    // Set COM security levels
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    // Create WMI locator object
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) {
        CoUninitialize();
        return "";
    }

    // Connect to WMI namespace
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    // Set security blanket for WMI connection
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    // Build WQL query (WMI Query Language)
    std::wstring query = L"SELECT " + std::wstring(property.begin(), property.end()) +
        L" FROM " + std::wstring(wmiClass.begin(), wmiClass.end());

    // Execute WMI query
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

    if (SUCCEEDED(hres)) {
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;

        // Iterate through query results
        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;  // No more results

            // Get property value
            VARIANT vtProp;
            std::wstring wProp(property.begin(), property.end());
            hr = pclsObj->Get(wProp.c_str(), 0, &vtProp, 0, 0);

            // Convert BSTR to std::string if successful
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                _bstr_t bstrVal(vtProp.bstrVal);
                result = (char*)bstrVal;
            }

            VariantClear(&vtProp);
            pclsObj->Release();
            break;  // Take first result only
        }
        pEnumerator->Release();
    }

    // Cleanup COM objects
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return result;
}

/**
 * cURL write callback function
 * Called by cURL when receiving data from HTTP response
 * 
 * @param contents Data buffer
 * @param size Size of each element
 * @param nmemb Number of elements
 * @param userp User pointer (cast to std::string*)
 * @return Number of bytes processed
 */
size_t CGAuth::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    // Append received data to the output string
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// ============================================================================
// REQUEST ID GENERATION (NEW)
// ============================================================================

/**
 * Generate unique request ID for each authentication attempt
 * Prevents replay attacks by ensuring each request is unique
 * 
 * @return SHA256 hash of timestamp + random bytes (lowercase hex)
 */
std::string CGAuth::GenerateRequestId() {
    // Get current timestamp in milliseconds
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::string timestamp = std::to_string(ms);
    
    // Generate 16 random bytes
    unsigned char randomBytes[16];
    RAND_bytes(randomBytes, 16);
    std::string randomHex = ToHex(randomBytes, 16);
    
    // Combine timestamp + random bytes
    std::string combined = timestamp + randomHex;
    
    // Hash using SHA256 for consistent length
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined.c_str(), combined.size(), hash);
    
    // Return as lowercase hex string
    std::string result = ToHex(hash, SHA256_DIGEST_LENGTH);
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// ============================================================================
// HWID GENERATION
// ============================================================================

/**
 * Generate unique Hardware ID (HWID)
 * 
 * Primary method: Uses WMI to collect hardware information
 * - Processor ID (unique CPU identifier)
 * - Motherboard Serial Number
 * - BIOS Serial Number
 * 
 * Fallback method: Uses computer name + username
 * 
 * @return SHA256 hash of hardware information (uppercase hex)
 */
std::string CGAuth::GetHWID() {
    try {
        std::string hwid;
        
        // Collect hardware information via WMI
        hwid += GetWMIProperty("Win32_Processor", "ProcessorId");
        hwid += GetWMIProperty("Win32_BaseBoard", "SerialNumber");
        hwid += GetWMIProperty("Win32_BIOS", "SerialNumber");

        // Clean up: Remove spaces, dashes, and underscores
        hwid.erase(std::remove(hwid.begin(), hwid.end(), ' '), hwid.end());
        hwid.erase(std::remove(hwid.begin(), hwid.end(), '-'), hwid.end());
        hwid.erase(std::remove(hwid.begin(), hwid.end(), '_'), hwid.end());
        hwid = ToUpper(hwid);

        // Validate that HWID was generated
        if (hwid.empty()) {
            throw std::runtime_error("Failed to generate HWID");
        }

        // Hash the HWID using SHA256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)hwid.c_str(), hwid.size(), hash);

        return ToUpper(ToHex(hash, SHA256_DIGEST_LENGTH));
    }
    catch (...) {
        // Fallback method: Use computer name + username
        char computerName[256];
        char userName[256];
        DWORD size = 256;

        GetComputerNameA(computerName, &size);
        size = 256;
        GetUserNameA(userName, &size);

        std::string fallback = std::string(computerName) + std::string(userName);

        // Hash the fallback HWID
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)fallback.c_str(), fallback.size(), hash);

        return ToUpper(ToHex(hash, SHA256_DIGEST_LENGTH));
    }
}

// ============================================================================
// ENCRYPTION/DECRYPTION
// ============================================================================

/**
 * Encrypt payload using AES-256-CBC
 * 
 * Process:
 * 1. Convert JSON to string
 * 2. Derive 256-bit key from API_SECRET using SHA256
 * 3. Generate random 16-byte IV (Initialization Vector)
 * 4. Encrypt data using AES-256-CBC
 * 5. Combine IV + ciphertext
 * 6. Base64 encode for safe transmission
 * 
 * @param params JSON parameters to encrypt
 * @return Base64-encoded encrypted string
 */
std::string CGAuth::EncryptPayload(const json& params) {
    // Convert JSON to string
    std::string jsonStr = params.dump();

    // Derive 256-bit encryption key from API_SECRET
    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)API_SECRET.c_str(), API_SECRET.size(), key);

    // Generate random Initialization Vector (IV)
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    // Encrypt using AES-256-CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    int ciphertext_len;
    unsigned char ciphertext[4096];

    // Encrypt data (may produce multiple blocks)
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)jsonStr.c_str(), jsonStr.size());
    ciphertext_len = len;

    // Finalize encryption (adds padding if necessary)
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Combine IV + Ciphertext (IV is needed for decryption)
    std::string combined;
    combined.append((char*)iv, AES_BLOCK_SIZE);
    combined.append((char*)ciphertext, ciphertext_len);

    // Base64 encode for safe transmission
    return Base64Encode(combined);
}

/**
 * Decrypt AES-256-CBC encrypted payload
 * Reverses the encryption process
 * 
 * @param encrypted Base64-encoded encrypted string
 * @return Decrypted JSON string
 */
std::string CGAuth::DecryptPayload(const std::string& encrypted) {
    // Base64 decode
    std::string decoded = Base64Decode(encrypted);

    // Extract IV (first 16 bytes) and ciphertext
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, decoded.c_str(), AES_BLOCK_SIZE);

    unsigned char* ciphertext = (unsigned char*)(decoded.c_str() + AES_BLOCK_SIZE);
    int ciphertext_len = decoded.size() - AES_BLOCK_SIZE;

    // Derive the same encryption key from API_SECRET
    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)API_SECRET.c_str(), API_SECRET.size(), key);

    // Decrypt using AES-256-CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char plaintext[4096];
    int len;
    int plaintext_len;

    // Decrypt data
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    // Finalize decryption (removes padding)
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string((char*)plaintext, plaintext_len);
}

// ============================================================================
// HMAC VERIFICATION (UPDATED WITH REQUEST BINDING)
// ============================================================================

/**
 * Verify HMAC-SHA256 signature with request binding to ensure data integrity
 * 
 * HMAC (Hash-based Message Authentication Code) prevents:
 * - Data tampering
 * - Message forgery
 * - Unauthorized modifications
 * - Replay attacks (when combined with request_id)
 * 
 * @param data Data to verify
 * @param hmac Received HMAC signature (hex string)
 * @param requestId Request ID for binding (NEW parameter)
 * @return true if HMAC is valid, false otherwise
 */
bool CGAuth::VerifyHMAC(const std::string& data, const std::string& hmac, const std::string& requestId) {
    // Combine data + request_id for HMAC calculation
    std::string combined = data + requestId;
    
    // Compute HMAC-SHA256 of the combined data
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int len;

    HMAC(EVP_sha256(), API_SECRET.c_str(), API_SECRET.size(),
        (unsigned char*)combined.c_str(), combined.size(), hash, &len);

    // Convert hash to hexadecimal string
    std::string computed = ToHex(hash, SHA256_DIGEST_LENGTH);

    // Compare computed HMAC with received HMAC (case-insensitive)
    return ToUpper(computed) == ToUpper(hmac);
}

// ============================================================================
// AUTHENTICATION FUNCTIONS (WITH REPLAY ATTACK PROTECTION)
// ============================================================================

/**
 * Authenticate using license key with replay attack protection
 * 
 * Complete authentication flow:
 * 1. Generate unique request ID
 * 2. Prepare authentication parameters (with request_id and timestamp)
 * 3. Encrypt payload with AES-256-CBC
 * 4. URL-encode parameters
 * 5. Send POST request via cURL
 * 6. Parse JSON response
 * 7. Verify timestamp (prevent replay attacks - 2 min tolerance)
 * 8. Verify HMAC with request_id binding (ensure data integrity)
 * 9. Verify request_id in response matches request
 * 10. Decrypt response data
 * 
 * @param licenseKey License key to validate
 * @param hwid Hardware ID of the machine
 * @return JSON object with authentication result
 */
json CGAuth::AuthLicense(const std::string& licenseKey, const std::string& hwid) {
    try {
        // ✅ Generate unique request ID
        std::string requestId = GenerateRequestId();
        
        // ✅ Prepare authentication parameters with request_id and timestamp
        json params = {
            {"api_secret", API_SECRET},
            {"type", "license"},
            {"key", licenseKey},
            {"hwid", hwid},
            {"request_id", requestId},  // NEW
            {"timestamp", std::to_string(std::time(nullptr))}  // NEW
        };

        // Encrypt payload for secure transmission
        std::string encrypted = EncryptPayload(params);

        // URL encode parameters (required for POST data)
        CURL* curl = curl_easy_init();
        char* encoded_key = curl_easy_escape(curl, API_KEY.c_str(), API_KEY.size());
        char* encoded_payload = curl_easy_escape(curl, encrypted.c_str(), encrypted.size());

        std::string postData = std::string("api_key=") + encoded_key +
            "&payload=" + encoded_payload;

        curl_free(encoded_key);
        curl_free(encoded_payload);

        // Send POST request via cURL
        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, API_URL.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);  // Verify SSL certificate

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        // Check for cURL errors
        if (res != CURLE_OK) {
            throw std::runtime_error(curl_easy_strerror(res));
        }

        // Parse JSON response
        json jsonResponse = json::parse(response);
        
        // Validate response structure
        if (!jsonResponse.contains("data") || !jsonResponse.contains("hmac") || !jsonResponse.contains("timestamp")) {
            throw std::runtime_error("Invalid response structure");
        }
        
        std::string encData = jsonResponse["data"];
        std::string receivedHmac = jsonResponse["hmac"];
        long timestamp = jsonResponse["timestamp"];

        // ✅ Verify timestamp (stricter: 2 minutes tolerance)
        long now = std::time(nullptr);
        if (std::abs(now - timestamp) > 120) {
            throw std::runtime_error("Response expired");
        }

        // ✅ Verify HMAC with request_id binding
        if (!VerifyHMAC(encData, receivedHmac, requestId)) {
            throw std::runtime_error("HMAC verification failed - possible replay attack");
        }

        // Decrypt the response data
        std::string decrypted = DecryptPayload(encData);
        json result = json::parse(decrypted);
        
        // ✅ Verify request_id in response matches our request
        if (result.contains("request_id") && result["request_id"] != requestId) {
            throw std::runtime_error("Request ID mismatch - possible replay attack");
        }
        
        return result;
    }
    catch (const std::exception& e) {
        // Return error response if authentication fails
        return json{ {"success", false}, {"error", e.what()} };
    }
}

/**
 * Authenticate using username and password with replay attack protection
 * 
 * Same authentication flow as AuthLicense but with user credentials
 * Password is encrypted before transmission
 * 
 * @param username User's username
 * @param password User's password
 * @param hwid Hardware ID of the machine
 * @return JSON object with authentication result
 */
json CGAuth::AuthUser(const std::string& username, const std::string& password, const std::string& hwid) {
    try {
        // ✅ Generate unique request ID
        std::string requestId = GenerateRequestId();
        
        // ✅ Prepare authentication parameters with request_id and timestamp
        json params = {
            {"api_secret", API_SECRET},
            {"type", "user"},
            {"key", username},
            {"password", password},
            {"hwid", hwid},
            {"request_id", requestId},  // NEW
            {"timestamp", std::to_string(std::time(nullptr))}  // NEW
        };

        // Encrypt payload for secure transmission
        std::string encrypted = EncryptPayload(params);

        // URL encode parameters
        CURL* curl = curl_easy_init();
        char* encoded_key = curl_easy_escape(curl, API_KEY.c_str(), API_KEY.size());
        char* encoded_payload = curl_easy_escape(curl, encrypted.c_str(), encrypted.size());

        std::string postData = std::string("api_key=") + encoded_key +
            "&payload=" + encoded_payload;

        curl_free(encoded_key);
        curl_free(encoded_payload);

        // Send POST request via cURL
        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, API_URL.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);  // Verify SSL certificate

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        // Check for cURL errors
        if (res != CURLE_OK) {
            throw std::runtime_error(curl_easy_strerror(res));
        }

        // Parse JSON response
        json jsonResponse = json::parse(response);
        
        // Validate response structure
        if (!jsonResponse.contains("data") || !jsonResponse.contains("hmac") || !jsonResponse.contains("timestamp")) {
            throw std::runtime_error("Invalid response structure");
        }
        
        std::string encData = jsonResponse["data"];
        std::string receivedHmac = jsonResponse["hmac"];
        long timestamp = jsonResponse["timestamp"];

        // ✅ Verify timestamp (stricter: 2 minutes tolerance)
        long now = std::time(nullptr);
        if (std::abs(now - timestamp) > 120) {
            throw std::runtime_error("Response expired");
        }

        // ✅ Verify HMAC with request_id binding
        if (!VerifyHMAC(encData, receivedHmac, requestId)) {
            throw std::runtime_error("HMAC verification failed - possible replay attack");
        }

        // Decrypt the response data
        std::string decrypted = DecryptPayload(encData);
        json result = json::parse(decrypted);
        
        // ✅ Verify request_id in response matches our request
        if (result.contains("request_id") && result["request_id"] != requestId) {
            throw std::runtime_error("Request ID mismatch - possible replay attack");
        }
        
        return result;
    }
    catch (const std::exception& e) {
        // Return error response if authentication fails
        return json{ {"success", false}, {"error", e.what()} };
    }
}