Imports System.Security.Cryptography
Imports System.Text
Imports System.Net
Imports Newtonsoft.Json.Linq
Imports System.Net.Security
Imports System.Management
Imports System.Security.Cryptography.X509Certificates

Module CGAuth_Module
    ' ========================================================================
    ' API CONFIGURATION CONSTANTS
    ' ========================================================================
    
    ''' <summary>
    ''' Base URL for CGAuth API endpoints
    ''' </summary>
    Public Const API_URL As String = "https://cgauth.com/api/v1/"
    
    ''' <summary>
    ''' Your application name - must match the license/user configuration
    ''' </summary>
    Public YOUR_APP_NAME As String = "WRITE_YOUR_APP_NAME"
    
    ''' <summary>
    ''' API Key for authentication - public identifier for your app
    ''' </summary>
    Public API_KEY As String = "WRITE_YOUR_API_KEY"
    
    ''' <summary>
    ''' API Secret for encryption and HMAC - MUST be kept private
    ''' </summary>
    Public API_SECRET As String = "WRITE_YOUR_API_SECRET"
    
    ''' <summary>
    ''' Expected SSL certificate hash for certificate pinning
    ''' Prevents man-in-the-middle attacks
    ''' </summary>
    Public Const SSL_KEY As String = "WRITE_YOUR_SSL_KEY"

    ' ========================================================================
    ' HARDWARE ID (HWID) GENERATION
    ' ========================================================================
    
    ''' <summary>
    ''' Generate unique Hardware ID based on system components
    ''' Uses WMI to collect processor, motherboard, and BIOS information
    ''' </summary>
    ''' <returns>SHA256 hash of hardware components</returns>
    Public Function GetHWID() As String
        Try
            Dim hwid As String = ""
            
            ' Collect hardware information from Windows Management Instrumentation
            ' Processor ID - unique identifier for CPU
            hwid += GetComponent("Win32_Processor", "ProcessorId")
            ' Motherboard serial number
            hwid += GetComponent("Win32_BaseBoard", "SerialNumber")
            ' BIOS serial number
            hwid += GetComponent("Win32_BIOS", "SerialNumber")
            
            ' Clean the HWID string (remove spaces, dashes, underscores)
            hwid = hwid.Replace(" ", "").Replace("-", "").Replace("_", "").ToUpper()
            
            ' Validate that HWID was successfully generated
            If String.IsNullOrEmpty(hwid) Then
                Throw New Exception("Failed to generate HWID")
            End If
            
            ' Hash the HWID using SHA256 for consistency and anonymization
            Using sha As SHA256 = SHA256.Create()
                Dim bytes As Byte() = Encoding.UTF8.GetBytes(hwid)
                Dim hash As Byte() = sha.ComputeHash(bytes)
                Return BitConverter.ToString(hash).Replace("-", "").ToUpper()
            End Using
            
        Catch ex As Exception
            ' Fallback method: Use machine name + username
            ' This is less reliable but ensures the system always has an HWID
            Dim fallback As String = Environment.MachineName & Environment.UserName
            Using sha As SHA256 = SHA256.Create()
                Dim bytes As Byte() = Encoding.UTF8.GetBytes(fallback)
                Dim hash As Byte() = sha.ComputeHash(bytes)
                Return BitConverter.ToString(hash).Replace("-", "").ToUpper()
            End Using
        End Try
    End Function
    
    ''' <summary>
    ''' Helper function to retrieve specific WMI component information
    ''' </summary>
    ''' <param name="wmiClass">WMI class name (e.g., Win32_Processor)</param>
    ''' <param name="wmiProperty">Property to retrieve (e.g., ProcessorId)</param>
    ''' <returns>Property value as string</returns>
    Public Function GetComponent(wmiClass As String, wmiProperty As String) As String
        Try
            Dim result As String = ""
            ' Query WMI for the specified class and property
            Dim searcher As New ManagementObjectSearcher("SELECT " & wmiProperty & " FROM " & wmiClass)
            
            ' Iterate through results and get the first non-null value
            For Each obj As ManagementObject In searcher.Get()
                Dim value = obj(wmiProperty)
                If value IsNot Nothing Then
                    result = value.ToString()
                    Exit For
                End If
            Next
            Return result
        Catch
            ' Return empty string if WMI query fails
            Return ""
        End Try
    End Function

    ' ========================================================================
    ' SSL CERTIFICATE VALIDATION (CERTIFICATE PINNING)
    ' ========================================================================
    
    ''' <summary>
    ''' Validate SSL certificate to prevent man-in-the-middle attacks
    ''' Implements certificate pinning by comparing certificate hash
    ''' </summary>
    ''' <returns>True if certificate is valid, False otherwise</returns>
    Public Function ValidateCert(sender As Object, cert As X509Certificate, chain As X509Chain, errors As SslPolicyErrors) As Boolean
        ' Check if certificate exists
        If cert Is Nothing Then Return False
        
        ' Calculate SHA256 hash of the certificate
        Using sha256 As SHA256 = SHA256.Create()
            Dim certBytes As Byte() = cert.GetRawCertData()
            Dim hashBytes As Byte() = sha256.ComputeHash(certBytes)
            Dim hash As String = BitConverter.ToString(hashBytes).Replace("-", "").ToLower()
            
            ' Compare with expected SSL_KEY
            If hash <> SSL_KEY Then
                ' CRITICAL SECURITY ALERT: Certificate mismatch detected
                ' This could indicate a man-in-the-middle attack
                MsgBox("SSL verification failed! Possible attack detected.", MsgBoxStyle.Critical, "Security Alert")
                Environment.Exit(0) ' Terminate application immediately
                Return False
            End If
        End Using
        
        ' Certificate is valid
        Return True
    End Function

    ' ========================================================================
    ' ENCRYPTION/DECRYPTION FUNCTIONS
    ' ========================================================================
    
    ''' <summary>
    ''' Encrypt payload using AES-256-CBC encryption
    ''' This ensures secure transmission of sensitive data
    ''' </summary>
    ''' <param name="params">Dictionary of parameters to encrypt</param>
    ''' <returns>Base64-encoded encrypted string</returns>
    Public Function EncryptPayload(params As Dictionary(Of String, String)) As String
        ' Convert parameters to JSON string
        Dim json As String = Newtonsoft.Json.JsonConvert.SerializeObject(params)
        
        ' Derive 256-bit encryption key from API_SECRET
        Using sha As SHA256 = SHA256.Create()
            Dim key() As Byte = sha.ComputeHash(Encoding.UTF8.GetBytes(API_SECRET))
            
            ' Generate random 16-byte initialization vector (IV)
            Dim iv(15) As Byte
            Using rng As New RNGCryptoServiceProvider()
                rng.GetBytes(iv)
            End Using
            
            ' Create AES cipher in CBC mode with PKCS7 padding
            Using aes As Aes = Aes.Create()
                aes.Key = key
                aes.IV = iv
                aes.Mode = CipherMode.CBC
                aes.Padding = PaddingMode.PKCS7
                
                ' Encrypt the JSON data
                Using enc = aes.CreateEncryptor()
                    Dim jsonBytes() = Encoding.UTF8.GetBytes(json)
                    Dim encrypted() = enc.TransformFinalBlock(jsonBytes, 0, jsonBytes.Length)
                    
                    ' Combine IV and encrypted data (IV is needed for decryption)
                    Dim combined(iv.Length + encrypted.Length - 1) As Byte
                    Array.Copy(iv, 0, combined, 0, iv.Length)
                    Array.Copy(encrypted, 0, combined, iv.Length, encrypted.Length)
                    
                    ' Encode to Base64 for safe transmission
                    Return Convert.ToBase64String(combined)
                End Using
            End Using
        End Using
    End Function
    
    ''' <summary>
    ''' Decrypt AES-256-CBC encrypted payload
    ''' Reverses the encryption process
    ''' </summary>
    ''' <param name="encrypted">Base64-encoded encrypted string</param>
    ''' <returns>Decrypted JSON string</returns>
    Public Function DecryptPayload(encrypted As String) As String
        ' Decode from Base64
        Dim data() = Convert.FromBase64String(encrypted)
        
        ' Extract IV (first 16 bytes) and ciphertext
        Dim iv(15) As Byte
        Array.Copy(data, 0, iv, 0, 16)
        Dim ciphertext(data.Length - 17) As Byte
        Array.Copy(data, 16, ciphertext, 0, data.Length - 16)
        
        ' Derive the same encryption key from API_SECRET
        Using sha As SHA256 = SHA256.Create()
            Dim key() = sha.ComputeHash(Encoding.UTF8.GetBytes(API_SECRET))
            
            ' Create AES cipher with the extracted IV
            Using aes As Aes = Aes.Create()
                aes.Key = key
                aes.IV = iv
                aes.Mode = CipherMode.CBC
                aes.Padding = PaddingMode.PKCS7
                
                ' Decrypt the ciphertext
                Using dec = aes.CreateDecryptor()
                    Dim decrypted() = dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length)
                    Return Encoding.UTF8.GetString(decrypted)
                End Using
            End Using
        End Using
    End Function

    ' ========================================================================
    ' HMAC VERIFICATION (DATA INTEGRITY)
    ' ========================================================================
    
    ''' <summary>
    ''' Verify HMAC-SHA256 signature to ensure data integrity
    ''' Prevents tampering with response data
    ''' </summary>
    ''' <param name="data">Data to verify</param>
    ''' <param name="hmac">Received HMAC signature</param>
    ''' <returns>True if HMAC is valid, False otherwise</returns>
    Public Function VerifyHMAC(data As String, hmac As String) As Boolean
        Using h As New HMACSHA256(Encoding.UTF8.GetBytes(API_SECRET))
            ' Compute HMAC of the data
            Dim computed = BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(data))).Replace("-", "").ToLower()
            ' Compare computed HMAC with received HMAC (case-insensitive)
            Return computed = hmac.ToLower()
        End Using
    End Function

    ' ========================================================================
    ' AUTHENTICATION FUNCTIONS
    ' ========================================================================
    
    ''' <summary>
    ''' Authenticate using a license key
    ''' </summary>
    ''' <param name="licenseKey">License key to validate</param>
    ''' <param name="hwid">Hardware ID of the machine</param>
    ''' <returns>JObject containing authentication result</returns>
    Public Function AuthLicense(licenseKey As String, hwid As String) As JObject
        Try
            ' Prepare authentication parameters
            Dim params As New Dictionary(Of String, String) From {
                {"api_secret", API_SECRET},
                {"type", "license"},
                {"key", licenseKey},
                {"hwid", hwid}
            }
            
            ' Encrypt the payload for secure transmission
            Dim encrypted = EncryptPayload(params)
            
            ' Build POST data with URL-encoded parameters
            Dim postData = String.Format("api_key={0}&payload={1}",
                Uri.EscapeDataString(API_KEY),
                Uri.EscapeDataString(encrypted))
            
            ' Send POST request to API
            Using client As New WebClient()
                ' Set content type header
                client.Headers(HttpRequestHeader.ContentType) = "application/x-www-form-urlencoded"
                
                ' Upload data and get response
                Dim response = client.UploadString(API_URL, postData)
                
                ' Parse JSON response
                Dim json = JObject.Parse(response)
                Dim encData = json("data").Value(Of String)()
                Dim hmac = json("hmac").Value(Of String)()
                Dim timestamp = json("timestamp").Value(Of Long)()
                
                ' Verify timestamp to prevent replay attacks (5 minutes tolerance)
                If Math.Abs(DateTimeOffset.Now.ToUnixTimeSeconds() - timestamp) > 300 Then
                    Throw New Exception("Expired")
                End If
                
                ' Verify HMAC to ensure data integrity
                If Not VerifyHMAC(encData, hmac) Then
                    Throw New Exception("HMAC failed")
                End If
                
                ' Decrypt the response data
                Dim decrypted = DecryptPayload(encData)
                Return JObject.Parse(decrypted)
            End Using
            
        Catch ex As Exception
            ' Return error response if authentication fails
            Return JObject.Parse("{""success"":false,""error"":""" & ex.Message & """}")
        End Try
    End Function
    
    ''' <summary>
    ''' Authenticate using username and password
    ''' </summary>
    ''' <param name="username">User's username</param>
    ''' <param name="password">User's password</param>
    ''' <param name="hwid">Hardware ID of the machine</param>
    ''' <returns>JObject containing authentication result</returns>
    Public Function AuthUser(username As String, password As String, hwid As String) As JObject
        Try
            ' Prepare authentication parameters
            Dim params As New Dictionary(Of String, String) From {
                {"api_secret", API_SECRET},
                {"type", "user"},
                {"key", username},
                {"password", password},
                {"hwid", hwid}
            }
            
            ' Encrypt the payload for secure transmission
            Dim encrypted = EncryptPayload(params)
            
            ' Build POST data with URL-encoded parameters
            Dim postData = String.Format("api_key={0}&payload={1}",
                Uri.EscapeDataString(API_KEY),
                Uri.EscapeDataString(encrypted))
            
            ' Send POST request to API
            Using client As New WebClient()
                ' Set content type header
                client.Headers(HttpRequestHeader.ContentType) = "application/x-www-form-urlencoded"
                
                ' Upload data and get response
                Dim response = client.UploadString(API_URL, postData)
                
                ' Parse JSON response
                Dim json = JObject.Parse(response)
                Dim encData = json("data").Value(Of String)()
                Dim hmac = json("hmac").Value(Of String)()
                Dim timestamp = json("timestamp").Value(Of Long)()
                
                ' Verify timestamp to prevent replay attacks (5 minutes tolerance)
                If Math.Abs(DateTimeOffset.Now.ToUnixTimeSeconds() - timestamp) > 300 Then
                    Throw New Exception("Expired")
                End If
                
                ' Verify HMAC to ensure data integrity
                If Not VerifyHMAC(encData, hmac) Then
                    Throw New Exception("HMAC failed")
                End If
                
                ' Decrypt the response data
                Dim decrypted = DecryptPayload(encData)
                Return JObject.Parse(decrypted)
            End Using
            
        Catch ex As Exception
            ' Return error response if authentication fails
            Return JObject.Parse("{""success"":false,""error"":""" & ex.Message & """}")
        End Try
    End Function
End Module