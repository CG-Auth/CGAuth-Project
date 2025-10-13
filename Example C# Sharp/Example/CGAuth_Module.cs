using System;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using Newtonsoft.Json.Linq;
using System.Net.Security;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Linq;

namespace Example
{
    public static class CGAuth_Module
    {
        // API endpoint for CGAuth authentication service
        public const string API_URL = "https://cgauth.com/api/v1/";
        
        // Application identifier - must match the app registered on CGAuth
        public static string YOUR_APP_NAME = "WRITE_YOUR_APP_NAME";
        
        // API credentials for authenticating with CGAuth service
        public static string API_KEY = "WRITE_YOUR_API_KEY";
        public static string API_SECRET = "WRITE_YOUR_API_SECRET";
        
        // SSL certificate hash for certificate pinning (security validation)
        public const string SSL_KEY = "WRITE_YOUR_SSL_KEY";

        // ========================================================================
        // REQUEST ID GENERATION (NEW)
        // ========================================================================

        /// <summary>
        /// Generates a unique request ID for each authentication attempt
        /// Prevents replay attacks by ensuring each request is unique
        /// </summary>
        /// <returns>SHA256 hash of timestamp + random bytes (lowercase hex)</returns>
        public static string GenerateRequestId()
        {
            // Combine timestamp (milliseconds) + random bytes for uniqueness
            long timestamp = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            
            byte[] randomBytes = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }
            
            string randomHex = BitConverter.ToString(randomBytes).Replace("-", "");
            string combined = timestamp.ToString() + randomHex;
            
            // Hash for consistent length using SHA256
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hashBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(combined));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        // ========================================================================
        // HWID GENERATION
        // ========================================================================

        /// <summary>
        /// Generates a unique Hardware ID (HWID) based on system components
        /// Used for hardware-based license binding
        /// </summary>
        public static string GetHWID()
        {
            try
            {
                string hwid = "";
                
                // Collect hardware identifiers from multiple components
                hwid += GetComponent("Win32_Processor", "ProcessorId");      // CPU ID
                hwid += GetComponent("Win32_BaseBoard", "SerialNumber");     // Motherboard serial
                hwid += GetComponent("Win32_BIOS", "SerialNumber");          // BIOS serial
                
                // Clean up the combined string (remove spaces, dashes, underscores)
                hwid = hwid.Replace(" ", "").Replace("-", "").Replace("_", "").ToUpper();

                if (string.IsNullOrEmpty(hwid))
                    throw new Exception("Failed to generate HWID");

                // Hash the hardware ID using SHA256 for consistent length and privacy
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(hwid);
                    byte[] hash = sha.ComputeHash(bytes);
                    return BitConverter.ToString(hash).Replace("-", "").ToUpper();
                }
            }
            catch
            {
                // Fallback method: use machine name and username if hardware detection fails
                string fallback = Environment.MachineName + Environment.UserName;
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(fallback);
                    byte[] hash = sha.ComputeHash(bytes);
                    return BitConverter.ToString(hash).Replace("-", "").ToUpper();
                }
            }
        }

        /// <summary>
        /// Retrieves a specific component property using WMI (Windows Management Instrumentation)
        /// </summary>
        public static string GetComponent(string wmiClass, string wmiProperty)
        {
            try
            {
                string result = "";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher($"SELECT {wmiProperty} FROM {wmiClass}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        object value = obj[wmiProperty];
                        if (value != null)
                        {
                            result = value.ToString();
                            break;
                        }
                    }
                }
                return result;
            }
            catch
            {
                return "";
            }
        }

        // ========================================================================
        // SSL CERTIFICATE VALIDATION
        // ========================================================================

        /// <summary>
        /// Validates SSL certificate using certificate pinning
        /// Prevents man-in-the-middle attacks by verifying the server's certificate hash
        /// </summary>
        public static bool ValidateCert(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            if (cert == null) return false;

            using (SHA256 sha256 = SHA256.Create())
            {
                // Get the raw certificate data and compute its SHA256 hash
                byte[] certBytes = cert.GetRawCertData();
                byte[] hashBytes = sha256.ComputeHash(certBytes);
                string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                // Compare the computed hash with the expected SSL_KEY
                if (hash != SSL_KEY)
                {
                    // Certificate mismatch - potential security threat
                    MessageBox.Show("SSL verification failed! Possible attack detected.",
                                  "Security Alert",
                                  MessageBoxButtons.OK,
                                  MessageBoxIcon.Error);
                    Environment.Exit(0);  // Terminate application immediately
                    return false;
                }
            }
            return true;
        }

        // ========================================================================
        // ENCRYPTION/DECRYPTION
        // ========================================================================

        /// <summary>
        /// Encrypts the payload using AES-256-CBC encryption
        /// Parameters are encrypted to protect sensitive data during transmission
        /// </summary>
        public static string EncryptPayload(Dictionary<string, string> parameters)
        {
            // Serialize parameters to JSON
            string json = Newtonsoft.Json.JsonConvert.SerializeObject(parameters);

            using (SHA256 sha = SHA256.Create())
            {
                // Derive 256-bit key from API_SECRET
                byte[] key = sha.ComputeHash(Encoding.UTF8.GetBytes(API_SECRET));
                
                // Generate random 16-byte initialization vector (IV)
                byte[] iv = new byte[16];
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(iv);
                }

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;          // Cipher Block Chaining mode
                    aes.Padding = PaddingMode.PKCS7;    // PKCS7 padding

                    using (ICryptoTransform enc = aes.CreateEncryptor())
                    {
                        // Encrypt the JSON data
                        byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
                        byte[] encrypted = enc.TransformFinalBlock(jsonBytes, 0, jsonBytes.Length);
                        
                        // Prepend IV to encrypted data (IV is needed for decryption)
                        byte[] combined = new byte[iv.Length + encrypted.Length];
                        Array.Copy(iv, 0, combined, 0, iv.Length);
                        Array.Copy(encrypted, 0, combined, iv.Length, encrypted.Length);
                        
                        // Return Base64-encoded result
                        return Convert.ToBase64String(combined);
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts the encrypted payload received from the server
        /// </summary>
        public static string DecryptPayload(string encrypted)
        {
            // Decode Base64 string
            byte[] data = Convert.FromBase64String(encrypted);
            
            // Extract IV (first 16 bytes)
            byte[] iv = new byte[16];
            Array.Copy(data, 0, iv, 0, 16);
            
            // Extract ciphertext (remaining bytes)
            byte[] ciphertext = new byte[data.Length - 16];
            Array.Copy(data, 16, ciphertext, 0, data.Length - 16);

            using (SHA256 sha = SHA256.Create())
            {
                // Derive the same key from API_SECRET
                byte[] key = sha.ComputeHash(Encoding.UTF8.GetBytes(API_SECRET));

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform dec = aes.CreateDecryptor())
                    {
                        // Decrypt the ciphertext
                        byte[] decrypted = dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                        return Encoding.UTF8.GetString(decrypted);
                    }
                }
            }
        }

        // ========================================================================
        // HMAC VERIFICATION (UPDATED WITH REQUEST BINDING)
        // ========================================================================

        /// <summary>
        /// Verifies HMAC signature with request binding to ensure data integrity
        /// Prevents tampering and replay attacks
        /// </summary>
        /// <param name="data">Data to verify</param>
        /// <param name="hmac">Received HMAC signature</param>
        /// <param name="requestId">Request ID for binding (NEW parameter)</param>
        /// <returns>True if HMAC is valid, false otherwise</returns>
        public static bool VerifyHMAC(string data, string hmac, string requestId)
        {
            // Combine data + request_id for HMAC calculation
            string combined = data + requestId;
            
            using (HMACSHA256 h = new HMACSHA256(Encoding.UTF8.GetBytes(API_SECRET)))
            {
                // Compute HMAC of the combined data
                string computed = BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(combined)))
                                             .Replace("-", "").ToLower();
                
                // Compare computed HMAC with received HMAC
                return computed == hmac.ToLower();
            }
        }

        // ========================================================================
        // AUTHENTICATION FUNCTIONS (WITH REPLAY ATTACK PROTECTION)
        // ========================================================================

        /// <summary>
        /// Authenticates using a license key with replay attack protection
        /// Validates the license and binds it to the current hardware
        /// </summary>
        public static JObject AuthLicense(string licenseKey, string hwid)
        {
            try
            {
                // ✅ Generate unique request ID
                string requestId = GenerateRequestId();
                
                // ✅ Prepare authentication parameters with request_id and timestamp
                var parameters = new Dictionary<string, string>
                {
                    { "api_secret", API_SECRET },
                    { "type", "license" },
                    { "key", licenseKey },
                    { "hwid", hwid },
                    { "request_id", requestId },  // NEW
                    { "timestamp", DateTimeOffset.Now.ToUnixTimeSeconds().ToString() }  // NEW
                };

                // Encrypt the payload for secure transmission
                string encrypted = EncryptPayload(parameters);
                string postData = string.Format("api_key={0}&payload={1}",
                    Uri.EscapeDataString(API_KEY),
                    Uri.EscapeDataString(encrypted));

                using (WebClient client = new WebClient())
                {
                    client.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                    
                    // Send POST request to the API
                    string response = client.UploadString(API_URL, postData);

                    // Parse the JSON response
                    JObject json = JObject.Parse(response);
                    
                    // Validate response structure
                    if (json["data"] == null || json["hmac"] == null || json["timestamp"] == null)
                    {
                        throw new Exception("Invalid response structure");
                    }
                    
                    string encData = json["data"].Value<string>();
                    string receivedHmac = json["hmac"].Value<string>();
                    long timestamp = json["timestamp"].Value<long>();

                    // ✅ Verify timestamp (stricter: 2 minutes tolerance)
                    if (Math.Abs(DateTimeOffset.Now.ToUnixTimeSeconds() - timestamp) > 120)
                        throw new Exception("Response expired");

                    // ✅ Verify HMAC signature with request_id binding
                    if (!VerifyHMAC(encData, receivedHmac, requestId))
                        throw new Exception("HMAC verification failed - possible replay attack");

                    // Decrypt the response data
                    string decrypted = DecryptPayload(encData);
                    JObject result = JObject.Parse(decrypted);
                    
                    // ✅ Verify request_id in response matches our request
                    if (result["request_id"] != null && result["request_id"].Value<string>() != requestId)
                    {
                        throw new Exception("Request ID mismatch - possible replay attack");
                    }
                    
                    return result;
                }
            }
            catch (Exception ex)
            {
                // Return error response in JSON format
                return JObject.Parse($"{{\"success\":false,\"error\":\"{ex.Message}\"}}");
            }
        }

        /// <summary>
        /// Authenticates using username and password with replay attack protection
        /// Validates user credentials and binds the session to hardware
        /// </summary>
        public static JObject AuthUser(string username, string password, string hwid)
        {
            try
            {
                // ✅ Generate unique request ID
                string requestId = GenerateRequestId();
                
                // ✅ Prepare authentication parameters with request_id and timestamp
                var parameters = new Dictionary<string, string>
                {
                    { "api_secret", API_SECRET },
                    { "type", "user" },
                    { "key", username },
                    { "password", password },
                    { "hwid", hwid },
                    { "request_id", requestId },  // NEW
                    { "timestamp", DateTimeOffset.Now.ToUnixTimeSeconds().ToString() }  // NEW
                };

                // Encrypt the payload for secure transmission
                string encrypted = EncryptPayload(parameters);
                string postData = string.Format("api_key={0}&payload={1}",
                    Uri.EscapeDataString(API_KEY),
                    Uri.EscapeDataString(encrypted));

                using (WebClient client = new WebClient())
                {
                    client.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                    
                    // Send POST request to the API
                    string response = client.UploadString(API_URL, postData);

                    // Parse the JSON response
                    JObject json = JObject.Parse(response);
                    
                    // Validate response structure
                    if (json["data"] == null || json["hmac"] == null || json["timestamp"] == null)
                    {
                        throw new Exception("Invalid response structure");
                    }
                    
                    string encData = json["data"].Value<string>();
                    string receivedHmac = json["hmac"].Value<string>();
                    long timestamp = json["timestamp"].Value<long>();

                    // ✅ Verify timestamp (stricter: 2 minutes tolerance)
                    if (Math.Abs(DateTimeOffset.Now.ToUnixTimeSeconds() - timestamp) > 120)
                        throw new Exception("Response expired");

                    // ✅ Verify HMAC signature with request_id binding
                    if (!VerifyHMAC(encData, receivedHmac, requestId))
                        throw new Exception("HMAC verification failed - possible replay attack");

                    // Decrypt the response data
                    string decrypted = DecryptPayload(encData);
                    JObject result = JObject.Parse(decrypted);
                    
                    // ✅ Verify request_id in response matches our request
                    if (result["request_id"] != null && result["request_id"].Value<string>() != requestId)
                    {
                        throw new Exception("Request ID mismatch - possible replay attack");
                    }
                    
                    return result;
                }
            }
            catch (Exception ex)
            {
                // Return error response in JSON format
                return JObject.Parse($"{{\"success\":false,\"error\":\"{ex.Message}\"}}");
            }
        }
    }
}