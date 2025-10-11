/**
 * CGAuth Client Library - Browser Edition
 * 
 * Provides client-side authentication with license key or username/password
 * Uses Web Crypto API for encryption and browser fingerprinting for HWID
 */
class CGAuth {
    // ========================================================================
    // API CONFIGURATION CONSTANTS
    // ========================================================================
    
    /** @type {string} Base URL for CGAuth API endpoints */
    static API_URL = "https://cgauth.com/api/v1/";
    
    /** @type {string} Your application name - must match license configuration */
    static YOUR_APP_NAME = "WRITE_YOUR_APP_NAME";
    
    /** @type {string} API Key for authentication - public identifier */
    static API_KEY = "WRITE_YOUR_API_KEY";
    
    /** @type {string} API Secret for encryption and HMAC - MUST be kept private */
    static API_SECRET = "WRITE_YOUR_API_SECRET";

    // ========================================================================
    // HWID GENERATION (Browser Fingerprinting)
    // ========================================================================
    
    /**
     * Generate unique browser fingerprint as Hardware ID
     * 
     * Collects various browser and device properties to create a unique identifier:
     * - User Agent, Language, Platform
     * - Screen Resolution and Color Depth
     * - Timezone Offset
     * - Canvas Fingerprint (unique rendering characteristics)
     * - WebGL Fingerprint (GPU information)
     * 
     * @returns {Promise<string>} SHA256 hash of browser fingerprint
     */
    static async getHWID() {
        try {
            let hwid = '';
            
            // Collect browser information
            hwid += navigator.userAgent;      // Browser identification string
            hwid += navigator.language;       // Preferred language
            hwid += navigator.platform;       // Operating system platform
            hwid += screen.width + 'x' + screen.height;  // Screen resolution
            hwid += screen.colorDepth;        // Color depth (bits per pixel)
            hwid += new Date().getTimezoneOffset();  // Timezone offset in minutes
            
            // Canvas Fingerprinting
            // Different browsers/systems render canvas slightly differently
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('CGAuth', 2, 2);  // Render test text
            hwid += canvas.toDataURL();     // Get rendered image as data URL
            
            // WebGL Fingerprinting
            // GPU information can help identify unique devices
            const gl = canvas.getContext('webgl');
            if (gl) {
                hwid += gl.getParameter(gl.RENDERER);  // GPU renderer info
                hwid += gl.getParameter(gl.VENDOR);    // GPU vendor info
            }
            
            // Clean up: Remove spaces, dashes, and underscores
            hwid = hwid.replace(/[\s\-_]/g, '').toUpperCase();
            
            // Hash using SHA-256 via Web Crypto API
            const encoder = new TextEncoder();
            const data = encoder.encode(hwid);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            
            // Convert hash buffer to hexadecimal string
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            return hashHex.toUpperCase();
            
        } catch (error) {
            // Fallback: Use basic browser info + timestamp
            const fallback = navigator.userAgent + Date.now();
            const encoder = new TextEncoder();
            const data = encoder.encode(fallback);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            return hashHex.toUpperCase();
        }
    }

    // ========================================================================
    // ENCRYPTION/DECRYPTION (Web Crypto API)
    // ========================================================================
    
    /**
     * Encrypt payload using AES-256-CBC encryption
     * Uses Web Crypto API for secure client-side encryption
     * 
     * @param {Object} params - Parameters to encrypt
     * @returns {Promise<string>} Base64-encoded encrypted string
     */
    static async encryptPayload(params) {
        // Convert parameters to JSON string
        const json = JSON.stringify(params);
        
        // Derive 256-bit encryption key from API_SECRET
        const encoder = new TextEncoder();
        const keyMaterial = encoder.encode(CGAuth.API_SECRET);
        const keyHash = await crypto.subtle.digest('SHA-256', keyMaterial);
        
        // Import the key for AES-CBC encryption
        const key = await crypto.subtle.importKey(
            'raw',
            keyHash,
            { name: 'AES-CBC' },
            false,           // Not extractable
            ['encrypt']      // Can only be used for encryption
        );
        
        // Generate random 16-byte initialization vector (IV)
        const iv = crypto.getRandomValues(new Uint8Array(16));
        
        // Encrypt the JSON data
        const jsonData = encoder.encode(json);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: iv },
            key,
            jsonData
        );
        
        // Combine IV + Ciphertext (IV is needed for decryption)
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        
        // Base64 encode for safe transmission
        return btoa(String.fromCharCode(...combined));
    }
    
    /**
     * Decrypt AES-256-CBC encrypted payload
     * Reverses the encryption process
     * 
     * @param {string} encrypted - Base64-encoded encrypted string
     * @returns {Promise<string>} Decrypted JSON string
     */
    static async decryptPayload(encrypted) {
        // Base64 decode
        const combined = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        
        // Extract IV (first 16 bytes) and ciphertext
        const iv = combined.slice(0, 16);
        const ciphertext = combined.slice(16);
        
        // Derive the same encryption key from API_SECRET
        const encoder = new TextEncoder();
        const keyMaterial = encoder.encode(CGAuth.API_SECRET);
        const keyHash = await crypto.subtle.digest('SHA-256', keyMaterial);
        
        // Import the key for AES-CBC decryption
        const key = await crypto.subtle.importKey(
            'raw',
            keyHash,
            { name: 'AES-CBC' },
            false,           // Not extractable
            ['decrypt']      // Can only be used for decryption
        );
        
        // Decrypt the ciphertext
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv },
            key,
            ciphertext
        );
        
        // Convert decrypted data back to string
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    // ========================================================================
    // HMAC VERIFICATION (DATA INTEGRITY)
    // ========================================================================
    
    /**
     * Verify HMAC-SHA256 signature to ensure data integrity
     * Prevents tampering with response data
     * 
     * @param {string} data - Data to verify
     * @param {string} receivedHmac - Received HMAC signature
     * @returns {Promise<boolean>} True if HMAC is valid, false otherwise
     */
    static async verifyHMAC(data, receivedHmac) {
        // Prepare the HMAC key
        const encoder = new TextEncoder();
        const keyData = encoder.encode(CGAuth.API_SECRET);
        
        // Import the key for HMAC-SHA256
        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,        // Not extractable
            ['sign']      // Can only be used for signing
        );
        
        // Compute HMAC signature
        const messageData = encoder.encode(data);
        const signature = await crypto.subtle.sign('HMAC', key, messageData);
        
        // Convert signature to hexadecimal string
        const hashArray = Array.from(new Uint8Array(signature));
        const computed = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        // Compare computed HMAC with received HMAC (case-insensitive)
        return computed.toLowerCase() === receivedHmac.toLowerCase();
    }

    // ========================================================================
    // AUTHENTICATION FUNCTIONS
    // ========================================================================
    
    /**
     * Authenticate using a license key
     * 
     * Process:
     * 1. Encrypt authentication parameters
     * 2. Send POST request to API
     * 3. Verify timestamp (prevent replay attacks)
     * 4. Verify HMAC (ensure data integrity)
     * 5. Decrypt response data
     * 
     * @param {string} licenseKey - License key to validate
     * @param {string} hwid - Browser fingerprint (Hardware ID)
     * @returns {Promise<Object>} Authentication result with success status and data
     */
    static async authLicense(licenseKey, hwid) {
        try {
            // Prepare authentication parameters
            const params = {
                api_secret: CGAuth.API_SECRET,
                type: 'license',
                key: licenseKey,
                hwid: hwid
            };
            
            // Encrypt the payload for secure transmission
            const encrypted = await CGAuth.encryptPayload(params);
            
            // Send POST request to CGAuth API
            const response = await fetch(CGAuth.API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    api_key: CGAuth.API_KEY,
                    payload: encrypted
                })
            });
            
            // Parse JSON response
            const jsonResponse = await response.json();
            const encData = jsonResponse.data;
            const receivedHmac = jsonResponse.hmac;
            const timestamp = jsonResponse.timestamp;
            
            // Verify timestamp to prevent replay attacks (5 minutes tolerance)
            const now = Math.floor(Date.now() / 1000);  // Current Unix timestamp
            if (Math.abs(now - timestamp) > 300) {
                throw new Error('Response expired');
            }
            
            // Verify HMAC to ensure data integrity
            if (!await CGAuth.verifyHMAC(encData, receivedHmac)) {
                throw new Error('HMAC verification failed');
            }
            
            // Decrypt the response data
            const decrypted = await CGAuth.decryptPayload(encData);
            return JSON.parse(decrypted);
            
        } catch (error) {
            // Return error response if authentication fails
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Authenticate using username and password
     * 
     * Process:
     * 1. Encrypt authentication parameters (including password)
     * 2. Send POST request to API
     * 3. Verify timestamp (prevent replay attacks)
     * 4. Verify HMAC (ensure data integrity)
     * 5. Decrypt response data
     * 
     * @param {string} username - User's username
     * @param {string} password - User's password
     * @param {string} hwid - Browser fingerprint (Hardware ID)
     * @returns {Promise<Object>} Authentication result with success status and data
     */
    static async authUser(username, password, hwid) {
        try {
            // Prepare authentication parameters
            const params = {
                api_secret: CGAuth.API_SECRET,
                type: 'user',
                key: username,
                password: password,
                hwid: hwid
            };
            
            // Encrypt the payload for secure transmission
            const encrypted = await CGAuth.encryptPayload(params);
            
            // Send POST request to CGAuth API
            const response = await fetch(CGAuth.API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    api_key: CGAuth.API_KEY,
                    payload: encrypted
                })
            });
            
            // Parse JSON response
            const jsonResponse = await response.json();
            const encData = jsonResponse.data;
            const receivedHmac = jsonResponse.hmac;
            const timestamp = jsonResponse.timestamp;
            
            // Verify timestamp to prevent replay attacks (5 minutes tolerance)
            const now = Math.floor(Date.now() / 1000);  // Current Unix timestamp
            if (Math.abs(now - timestamp) > 300) {
                throw new Error('Response expired');
            }
            
            // Verify HMAC to ensure data integrity
            if (!await CGAuth.verifyHMAC(encData, receivedHmac)) {
                throw new Error('HMAC verification failed');
            }
            
            // Decrypt the response data
            const decrypted = await CGAuth.decryptPayload(encData);
            return JSON.parse(decrypted);
            
        } catch (error) {
            // Return error response if authentication fails
            return {
                success: false,
                error: error.message
            };
        }
    }
}