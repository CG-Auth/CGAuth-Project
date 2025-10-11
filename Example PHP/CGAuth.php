<?php

/**
 * CGAuth Class - License Authentication System
 * Handles license key and user authentication with hardware ID binding
 */
class CGAuth {
    // ========================================================================
    // API CONFIGURATION CONSTANTS
    // ========================================================================
    
    /** @var string Base URL for CGAuth API endpoints */
    const API_URL = "https://cgauth.com/api/v1/";
    
    /** @var string Your application name - must match license configuration */
    const YOUR_APP_NAME = "WRITE_YOUR_APP_NAME";
    
    /** @var string API Key for authentication - public identifier */
    const API_KEY = "WRITE_YOUR_API_KEY";
    
    /** @var string API Secret for encryption and HMAC - MUST be kept private */
    const API_SECRET = "WRITE_YOUR_API_SECRET";
    
    /** @var string Expected SSL certificate hash for certificate pinning */
    const SSL_KEY = "WRITE_YOUR_SSL_KEY";

    // ========================================================================
    // HWID GENERATION (Web Compatible)
    // ========================================================================
    
    /**
     * Generate unique Hardware ID
     * Adapts to both CLI and Web environments
     * 
     * CLI Mode: Uses actual hardware information (CPU, motherboard)
     * Web Mode: Uses server information (hostname, IP, software)
     * 
     * @return string SHA256 hash of hardware/server information
     */
    public static function getHWID() {
        try {
            $hwid = "";
            
            // Check if running in CLI (Command Line Interface) or Web mode
            if (php_sapi_name() === 'cli') {
                // CLI MODE - Get actual hardware information
                
                // Check if shell commands are available
                if (function_exists('shell_exec')) {
                    // Detect operating system
                    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                        // Windows - Get CPU Processor ID via WMIC
                        try {
                            $cpu = @shell_exec("wmic cpu get processorid 2>&1");
                            if ($cpu) {
                                $lines = explode("\n", trim($cpu));
                                // Extract processor ID from second line
                                if (isset($lines[1])) {
                                    $hwid .= trim($lines[1]);
                                }
                            }
                        } catch (Exception $e) {}
                    } else {
                        // Linux/Unix - Get CPU Serial or UUID
                        try {
                            // Try to get CPU serial from /proc/cpuinfo
                            $hwid = @shell_exec("cat /proc/cpuinfo | grep Serial | awk '{print $3}'");
                            
                            // Fallback: Get product UUID
                            if (!$hwid) {
                                $hwid = @shell_exec("cat /sys/class/dmi/id/product_uuid");
                            }
                        } catch (Exception $e) {}
                    }
                }
            } else {
                // WEB MODE - Use server information as HWID
                // Combine multiple server parameters for uniqueness
                $hwid .= $_SERVER['SERVER_NAME'] ?? '';      // Domain name
                $hwid .= $_SERVER['SERVER_ADDR'] ?? '';      // Server IP address
                $hwid .= $_SERVER['SERVER_SOFTWARE'] ?? '';  // Web server software
                $hwid .= $_SERVER['DOCUMENT_ROOT'] ?? '';    // Document root path
                $hwid .= php_uname('n');                     // Hostname
            }
            
            // Clean up: Remove spaces, dashes, underscores, and newlines
            $hwid = str_replace([' ', '-', '_', "\n", "\r"], '', strtoupper($hwid));
            
            // Validate that HWID was successfully generated
            if (empty($hwid)) {
                throw new Exception("Failed to generate HWID");
            }
            
            // Hash the HWID using SHA256 for consistency and anonymization
            return strtoupper(hash('sha256', $hwid));
            
        } catch (Exception $e) {
            // Ultimate Fallback: Use various system identifiers
            $fallback = '';
            $fallback .= php_uname('n');                 // Hostname
            $fallback .= $_SERVER['SERVER_NAME'] ?? '';   // Server name
            $fallback .= $_SERVER['DOCUMENT_ROOT'] ?? ''; // Document root
            $fallback .= __DIR__;                         // Current script directory
            
            // Last resort: Use timestamp-based identifier
            if (empty($fallback)) {
                $fallback = 'DEFAULT_HWID_' . time();
            }
            
            return strtoupper(hash('sha256', $fallback));
        }
    }

    // ========================================================================
    // ENCRYPTION/DECRYPTION
    // ========================================================================
    
    /**
     * Encrypt payload using AES-256-CBC encryption
     * Ensures secure transmission of sensitive data
     * 
     * @param array $params Parameters to encrypt
     * @return string Base64-encoded encrypted string
     */
    public static function encryptPayload($params) {
        // Convert parameters to JSON string
        $json = json_encode($params);
        
        // Derive 256-bit encryption key from API_SECRET
        $key = hash('sha256', self::API_SECRET, true);
        
        // Generate random 16-byte initialization vector (IV)
        $iv = openssl_random_pseudo_bytes(16);
        
        // Encrypt using AES-256-CBC mode
        $encrypted = openssl_encrypt(
            $json,
            'AES-256-CBC',
            $key,
            OPENSSL_RAW_DATA,  // Return raw binary data
            $iv
        );
        
        // Combine IV and encrypted data (IV is needed for decryption)
        $combined = $iv . $encrypted;
        
        // Encode to Base64 for safe transmission
        return base64_encode($combined);
    }
    
    /**
     * Decrypt AES-256-CBC encrypted payload
     * Reverses the encryption process
     * 
     * @param string $encrypted Base64-encoded encrypted string
     * @return string Decrypted JSON string
     */
    public static function decryptPayload($encrypted) {
        // Decode from Base64
        $data = base64_decode($encrypted);
        
        // Extract IV (first 16 bytes) and ciphertext
        $iv = substr($data, 0, 16);
        $ciphertext = substr($data, 16);
        
        // Derive the same encryption key from API_SECRET
        $key = hash('sha256', self::API_SECRET, true);
        
        // Decrypt using AES-256-CBC mode
        $decrypted = openssl_decrypt(
            $ciphertext,
            'AES-256-CBC',
            $key,
            OPENSSL_RAW_DATA,  // Expect raw binary data
            $iv
        );
        
        return $decrypted;
    }

    // ========================================================================
    // HMAC VERIFICATION (DATA INTEGRITY)
    // ========================================================================
    
    /**
     * Verify HMAC-SHA256 signature to ensure data integrity
     * Prevents tampering with response data
     * 
     * @param string $data Data to verify
     * @param string $receivedHmac Received HMAC signature
     * @return bool True if HMAC is valid, false otherwise
     */
    public static function verifyHMAC($data, $receivedHmac) {
        // Compute HMAC-SHA256 of the data
        $computed = hash_hmac('sha256', $data, self::API_SECRET);
        
        // Compare computed HMAC with received HMAC (case-insensitive)
        return strtolower($computed) === strtolower($receivedHmac);
    }

    // ========================================================================
    // AUTHENTICATION FUNCTIONS
    // ========================================================================
    
    /**
     * Authenticate using a license key
     * 
     * @param string $licenseKey License key to validate
     * @param string $hwid Hardware ID of the machine
     * @return array Authentication result with success status and data
     */
    public static function authLicense($licenseKey, $hwid) {
        try {
            // Prepare authentication parameters
            $params = [
                'api_secret' => self::API_SECRET,
                'type' => 'license',
                'key' => $licenseKey,
                'hwid' => $hwid
            ];
            
            // Encrypt the payload for secure transmission
            $encrypted = self::encryptPayload($params);
            
            // Build POST data with URL-encoded parameters
            $postData = http_build_query([
                'api_key' => self::API_KEY,
                'payload' => $encrypted
            ]);
            
            // Configure HTTP request options
            $options = [
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/x-www-form-urlencoded',
                    'content' => $postData,
                    'timeout' => 10  // 10 second timeout
                ],
                'ssl' => [
                    'verify_peer' => true,       // Verify SSL certificate
                    'verify_peer_name' => true   // Verify certificate name
                ]
            ];
            
            // Create stream context with options
            $context = stream_context_create($options);
            
            // Send POST request to API (@ suppresses warnings)
            $response = @file_get_contents(self::API_URL, false, $context);
            
            // Check if request was successful
            if ($response === false) {
                throw new Exception("Failed to connect to API");
            }
            
            // Parse JSON response
            $jsonResponse = json_decode($response, true);
            
            // Validate JSON parsing
            if (!$jsonResponse) {
                throw new Exception("Invalid JSON response");
            }
            
            // Extract response components
            $encData = $jsonResponse['data'];
            $receivedHmac = $jsonResponse['hmac'];
            $timestamp = $jsonResponse['timestamp'];
            
            // Verify timestamp to prevent replay attacks (5 minutes tolerance)
            if (abs(time() - $timestamp) > 300) {
                throw new Exception("Response expired");
            }
            
            // Verify HMAC to ensure data integrity
            if (!self::verifyHMAC($encData, $receivedHmac)) {
                throw new Exception("HMAC verification failed");
            }
            
            // Decrypt the response data
            $decrypted = self::decryptPayload($encData);
            return json_decode($decrypted, true);
            
        } catch (Exception $e) {
            // Return error response if authentication fails
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Authenticate using username and password
     * 
     * @param string $username User's username
     * @param string $password User's password
     * @param string $hwid Hardware ID of the machine
     * @return array Authentication result with success status and data
     */
    public static function authUser($username, $password, $hwid) {
        try {
            // Prepare authentication parameters
            $params = [
                'api_secret' => self::API_SECRET,
                'type' => 'user',
                'key' => $username,
                'password' => $password,
                'hwid' => $hwid
            ];
            
            // Encrypt the payload for secure transmission
            $encrypted = self::encryptPayload($params);
            
            // Build POST data with URL-encoded parameters
            $postData = http_build_query([
                'api_key' => self::API_KEY,
                'payload' => $encrypted
            ]);
            
            // Configure HTTP request options
            $options = [
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/x-www-form-urlencoded',
                    'content' => $postData,
                    'timeout' => 10  // 10 second timeout
                ],
                'ssl' => [
                    'verify_peer' => true,       // Verify SSL certificate
                    'verify_peer_name' => true   // Verify certificate name
                ]
            ];
            
            // Create stream context with options
            $context = stream_context_create($options);
            
            // Send POST request to API (@ suppresses warnings)
            $response = @file_get_contents(self::API_URL, false, $context);
            
            // Check if request was successful
            if ($response === false) {
                throw new Exception("Failed to connect to API");
            }
            
            // Parse JSON response
            $jsonResponse = json_decode($response, true);
            
            // Validate JSON parsing
            if (!$jsonResponse) {
                throw new Exception("Invalid JSON response");
            }
            
            // Extract response components
            $encData = $jsonResponse['data'];
            $receivedHmac = $jsonResponse['hmac'];
            $timestamp = $jsonResponse['timestamp'];
            
            // Verify timestamp to prevent replay attacks (5 minutes tolerance)
            if (abs(time() - $timestamp) > 300) {
                throw new Exception("Response expired");
            }
            
            // Verify HMAC to ensure data integrity
            if (!self::verifyHMAC($encData, $receivedHmac)) {
                throw new Exception("HMAC verification failed");
            }
            
            // Decrypt the response data
            $decrypted = self::decryptPayload($encData);
            return json_decode($decrypted, true);
            
        } catch (Exception $e) {
            // Return error response if authentication fails
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}