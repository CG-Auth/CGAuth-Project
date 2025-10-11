# CGAuth License Verification System (C++)

A high-security **license and authentication system** for C++ desktop applications.  
This module connects to the [CGAuth](https://cgauth.com) API to verify **license keys** or **user credentials**, providing AES encryption, HMAC verification, and SSL certificate pinning for maximum security.

---

## 🧩 Overview

This library provides:
- 🔐 **License Key** and **User/Password** authentication
- 💻 **Hardware-based binding** (HWID)
- 🧠 **AES-256-CBC encryption** and **HMAC-SHA256** verification
- 🛡️ **SSL Certificate Pinning** to prevent MITM attacks
- ⚡ Fast and simple integration with the CGAuth API

> ⚠️ **Important:** Always build in **x64 Release mode** — otherwise it will not work properly.

---

## 🔐 Getting Started

### 1. Register on CGAuth
Create an account and obtain your API credentials here:

➡️ [Sign in or Register at CGAuth.com](https://cgauth.com/sign-in)

You’ll receive:
- **YOUR_APP_NAME**
- **API_KEY**
- **API_SECRET**
- **SSL_KEY**

These values are required for your application to communicate with CGAuth.

---

### 2. Install Required Libraries

Before building, make sure to install the following libraries via **vcpkg**:

```bash
vcpkg install openssl curl nlohmann-json
vcpkg install openssl:x64-windows
vcpkg install curl:x64-windows
vcpkg install nlohmann-json:x64-windows
vcpkg integrate install
```

These provide:
- **OpenSSL** → Encryption, hashing, and HMAC
- **cURL** → HTTP requests
- **nlohmann-json** → JSON serialization

---

### 3. Project Configuration

Open the `CGAuth.cpp` file and fill in your API credentials:

```cpp
const std::string CGAuth::YOUR_APP_NAME = "YOUR_APP_NAME_HERE";
std::string CGAuth::API_KEY = "YOUR_API_KEY_HERE";
std::string CGAuth::API_SECRET = "YOUR_API_SECRET_HERE";
const std::string CGAuth::SSL_KEY = "YOUR_SSL_CERT_HASH_HERE";
```

> 🔑 You can find these values in your [API Help page](https://cgauth.com/api-help).

---

### 4. Example Usage

The repository includes a sample program (`Example.cpp`) demonstrating both authentication flows:

#### ▶ License Key Authentication
```cpp
std::string hwid = CGAuth::GetHWID();
json result = CGAuth::AuthLicense("LICENSE-KEY-HERE", hwid);

if (result["success"]) {
    std::cout << "License Verified! App: " << result["data"]["app_name"] << std::endl;
} else {
    std::cout << "Error: " << result["error"] << std::endl;
}
```

#### ▶ Username/Password Authentication
```cpp
std::string hwid = CGAuth::GetHWID();
json result = CGAuth::AuthUser("USERNAME", "PASSWORD", hwid);

if (result["success"]) {
    std::cout << "Login Successful! Welcome " << result["data"]["identifier"] << std::endl;
} else {
    std::cout << "Error: " << result["error"] << std::endl;
}
```

#### ▶ Display Hardware ID (HWID)
```cpp
std::cout << "Your HWID: " << CGAuth::GetHWID() << std::endl;
```

> The HWID binds each license to a unique machine using CPU, motherboard, and BIOS identifiers.

---

## ⚙️ Build Instructions

1. Open your project in **Visual Studio**
2. Set the configuration to **Release** and **x64**
3. Make sure all vcpkg libraries are integrated (`vcpkg integrate install`)
4. Build and run the project

If configured correctly, you can immediately test license or user authentication through the console menu.

---

## 🚨 Error Codes & Meanings

| Error Code | Meaning |
|-------------|----------|
| `INVALID_API_KEY` | Your API key is invalid or unrecognized. |
| `INVALID_LICENSE` | The license key is invalid, expired, or not found. |
| `INVALID_USER` | The username or password is incorrect. |
| `HWID_MISMATCH` | The license is bound to a different device. |
| `EXPIRED` | The license or session has expired. |
| `HMAC_FAILED` | Data integrity verification failed. |
| `SSL_VERIFICATION_FAILED` | SSL certificate mismatch (possible MITM). |
| `CONNECTION_ERROR` | Unable to connect to the CGAuth server. |

If any of these occur, verify your API credentials and ensure your system clock and SSL libraries are correct.

---

## 🧾 API Reference

For full parameter definitions, encryption examples, and response formats, visit:

➡️ [CGAuth API Documentation](https://cgauth.com/api-help)

---

## ✅ Quick Setup Summary

1. Register at [cgauth.com/sign-in](https://cgauth.com/sign-in)  
2. Create your app and get your API credentials  
3. Install dependencies using `vcpkg`  
4. Configure your `CGAuth.cpp` constants  
5. Build in **x64 Release mode**  
6. Run `Example.cpp` and test authentication  

After entering your credentials, you can immediately create and validate licenses in your software.

---

## 📜 License

This project is released under the **MIT License** for educational and integration purposes.  
You may freely use and modify it for your applications integrating CGAuth.

---

**Developed for C++ developers integrating CGAuth into secure desktop applications.**
