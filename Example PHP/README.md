# CGAuth License Verification System (C++)

A secure, high-performance **license and authentication system** for C++ applications, fully integrated with the [CGAuth](https://cgauth.com) API.  
This system allows you to protect your software with hardware-bound licenses, encrypted communication, and tamper-proof validation.

---

## 🧩 Overview

This C++ module enables developers to:
- 🔐 Validate **license keys** and **user accounts** via the CGAuth API  
- 💻 Bind each license to a **Hardware ID (HWID)** for device-level protection  
- 🧠 Use **AES-256-CBC** encryption and **HMAC-SHA256** verification  
- 🛡️ Protect against replay and MITM attacks through timestamp checks and SSL pinning  
- ⚙️ Build both GUI and console-based license verification flows  

> ⚠️ **Note:** Always compile your project in **x64 Release mode** for correct operation.

---

## 🔐 Getting Started

### 1. Create Your CGAuth Account

Sign up or log in at:

➡️ [https://cgauth.com/sign-in](https://cgauth.com/sign-in)

Once you register, you’ll receive:
- **YOUR_APP_NAME**
- **API_KEY**
- **API_SECRET**
- **SSL_KEY**

These credentials are essential for your software to connect to the CGAuth API.

---

### 2. Install Required Libraries

Use **vcpkg** to install dependencies before building your project:

```bash
vcpkg install openssl curl nlohmann-json
vcpkg install openssl:x64-windows
vcpkg install curl:x64-windows
vcpkg install nlohmann-json:x64-windows
vcpkg integrate install
```

These libraries provide:
- **OpenSSL** → for encryption, hashing, and HMAC  
- **cURL** → for HTTP/HTTPS requests  
- **nlohmann-json** → for JSON parsing and serialization  

---

## 🧠 Project Configuration

Open the `CGAuth.cpp` file and fill in your own API credentials:

```cpp
const std::string CGAuth::YOUR_APP_NAME = "YOUR_APP_NAME_HERE";
std::string CGAuth::API_KEY = "YOUR_API_KEY_HERE";
std::string CGAuth::API_SECRET = "YOUR_API_SECRET_HERE";
const std::string CGAuth::SSL_KEY = "YOUR_SSL_CERT_HASH_HERE";
```

> 🔑 You can find detailed explanations for these values on the [API Help Page](https://cgauth.com/api-help).

After inserting your API credentials, you can start generating and verifying licenses instantly.

---

## 🚀 Example Usage

### ▶ License Key Authentication

```cpp
std::string hwid = CGAuth::GetHWID();
json result = CGAuth::AuthLicense("LICENSE-KEY-HERE", hwid);

if (result["success"]) {
    std::cout << "License Valid!" << std::endl;
} else {
    std::cout << "Error: " << result["error"] << std::endl;
}
```

### ▶ Username/Password Authentication

```cpp
std::string hwid = CGAuth::GetHWID();
json result = CGAuth::AuthUser("USERNAME", "PASSWORD", hwid);

if (result["success"]) {
    std::cout << "User Authenticated!" << std::endl;
} else {
    std::cout << "Error: " << result["error"] << std::endl;
}
```

### ▶ Generate Hardware ID (HWID)

```cpp
std::cout << "HWID: " << CGAuth::GetHWID() << std::endl;
```

> Each HWID is a unique SHA-256 hash generated using CPU, BIOS, and motherboard identifiers.

---

## 🧱 PHP Software Licensing (Optional)

If you want to license your **PHP software**, you can specify and validate a license key using the CGAuth API.  
For example:
- You can configure your PHP script to **automatically terminate** when the license expires.
- Optionally, you can integrate **AI-assisted license management** for adaptive protection.

Example:
```php
if ($licenseExpired) {
    exit("License expired. Contact support.");
}
```

> This ensures your PHP or web-based products remain protected and tamper-proof — even on shared hosting environments.

---

## ⚙️ Build Instructions

1. Open your project in **Visual Studio**
2. Select `Release` and `x64` build mode
3. Link with OpenSSL, libcurl, and nlohmann-json
4. Build and run your program

The system will connect to `https://cgauth.com/api/v1/` for license verification.

---

## 🚨 Error Codes & Meanings

| Error Code | Description |
|-------------|-------------|
| `INVALID_API_KEY` | Your API key is invalid or missing. |
| `INVALID_LICENSE` | License key not found or expired. |
| `INVALID_USER` | Username or password is incorrect. |
| `HWID_MISMATCH` | The license is registered to another device. |
| `EXPIRED` | The license or session has expired. |
| `HMAC_FAILED` | Data integrity verification failed. |
| `SSL_VERIFICATION_FAILED` | SSL certificate mismatch detected. |
| `CONNECTION_ERROR` | Could not connect to CGAuth API. |

If an error occurs, verify your credentials and ensure the API key and SSL hash are correctly set.

---

## 🧾 API Reference

For detailed documentation, encryption formats, and examples:

➡️ [https://cgauth.com/api-help](https://cgauth.com/api-help)

This page includes full JSON structures, example requests, and parameter definitions.

---

## ✅ Quick Setup Summary

1. Register at [cgauth.com/sign-in](https://cgauth.com/sign-in)  
2. Get your API credentials  
3. Edit `CGAuth.cpp` with your app details  
4. Install dependencies via `vcpkg`  
5. Build in **x64 Release mode**  
6. Run the sample authentication functions  

After entering your credentials, you can create, verify, and manage licenses instantly.

---

## 📜 License

This project is distributed under the **MIT License**.  
You can freely modify and integrate it into your software as long as CGAuth attribution remains visible.

---

**Developed for developers securing C++ and PHP software using CGAuth — a complete, intelligent licensing solution.**
