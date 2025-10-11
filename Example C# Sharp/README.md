# CGAuth License Verification System (C#)

A secure and fully functional **license & authentication system** built for desktop applications.  
This project demonstrates how to integrate your software with the [CGAuth.com](https://cgauth.com) API to verify **license keys** or **user accounts** using AES encryption, HMAC validation, and SSL pinning.

---

## 🧩 Overview

This module allows your C# application to:
- Authenticate **licenses** or **user credentials** through CGAuth.
- Bind each license to the machine’s **Hardware ID (HWID)**.
- Ensure **secure data exchange** via AES-256-CBC encryption and HMAC-SHA256 integrity checks.
- Protect against **MITM attacks** using SSL certificate pinning.
- Support both **license key** and **username/password** authentication flows.

---

## 🧠 How It Works

1. The system collects a unique HWID based on CPU, motherboard, and BIOS serials.
2. Authentication data is AES-encrypted and sent to the CGAuth API.
3. The server verifies the license or account, then returns an encrypted JSON payload.
4. The client decrypts and validates the response using HMAC and timestamp checks.
5. Access is granted only if:
   - The API credentials are correct.
   - The license or account is valid and belongs to the current application.

---

## 🔐 Getting Started

### 1. Sign Up & Get API Credentials
Create an account and obtain your API information:

➡️ [Sign in or register at CGAuth.com](https://cgauth.com/sign-in)

You’ll need:
- **YOUR_APP_NAME**
- **API_KEY**
- **API_SECRET**
- **SSL_KEY**

All of these can be found in your dashboard or via the [API Help page](https://cgauth.com/api-help).

---

### 2. Configure the Module

Open the file `CGAuth_Module.cs` and set the following constants:

```csharp
public static string YOUR_APP_NAME = "YOUR_APP_NAME_HERE";
public static string API_KEY = "YOUR_API_KEY_HERE";
public static string API_SECRET = "YOUR_API_SECRET_HERE";
public const string SSL_KEY = "YOUR_SSL_CERT_HASH_HERE";
```

> 💡 Tip: Do **not** share your `API_SECRET` publicly. Treat it like a password.

---

### 3. How to Use

- To **authenticate a license key**, use the `AuthLicense()` function:
  ```csharp
  JObject result = CGAuth_Module.AuthLicense("LICENSE-KEY-HERE", CGAuth_Module.GetHWID());
  ```

- To **authenticate a user account**, use the `AuthUser()` function:
  ```csharp
  JObject result = CGAuth_Module.AuthUser("USERNAME", "PASSWORD", CGAuth_Module.GetHWID());
  ```

> Both return a structured JSON object with `success`, `data`, and `error` fields.

---

### 4. Testing Forms

The repository includes example forms for demonstration:
- **Select_Form.cs** — lets you choose between license or account authentication.
- **Test_License.cs** — demonstrates license key authentication flow.
- **Test_Account.cs** — demonstrates user login authentication flow.

Run the project, select a mode, and input your credentials or license key.

---

## ⚙️ Dependencies

This project requires the following libraries:
- **Newtonsoft.Json** (`JObject` parsing)
- **System.Management** (for HWID generation)
- **System.Security.Cryptography** (for AES & HMAC)
- **System.Net** (for HTTPS requests)

These can be installed via NuGet:
```bash
Install-Package Newtonsoft.Json
```

---

## 🚨 Error Codes & Meanings

| Error Code | Description |
|-------------|-------------|
| `INVALID_API_KEY` | Your API key is invalid or not recognized. |
| `INVALID_LICENSE` | License key not found or expired. |
| `INVALID_USER` | Username or password is incorrect. |
| `HWID_MISMATCH` | License is bound to a different device. |
| `EXPIRED` | License or session has expired. |
| `HMAC_FAILED` | Integrity verification failed. |
| `SSL_VERIFICATION_FAILED` | SSL certificate mismatch detected. |
| `CONNECTION_ERROR` | Network or server could not be reached. |

If you encounter any of these, double-check your API credentials and configuration.

---

## 🧾 API Reference

For detailed usage instructions, request formats, and server response examples, visit:

➡️ [CGAuth API Documentation](https://cgauth.com/api-help)

---

## ✅ Quick Setup Summary

1. Register or log in at [cgauth.com/sign-in](https://cgauth.com/sign-in)  
2. Create your application and get your credentials  
3. Update your constants in `CGAuth_Module.cs`  
4. Compile and run the project  
5. Test authentication using provided demo forms  

After entering your API details, you can immediately create licenses and start verifying them in your software.

---

## 📜 License

This project is distributed for **educational and integration purposes** under the MIT License.  
Use it as a foundation to integrate CGAuth into your own applications.

---

**Created for developers integrating CGAuth license systems into C# desktop software.**