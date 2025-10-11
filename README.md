# CGAuth Multi-Language License Verification System

Welcome to the official **CGAuth License Verification System Repository**.  
This repository provides **ready-to-use client integrations** for different programming languages, enabling developers to add **secure license authentication** to their applications using the [CGAuth](https://cgauth.com) API.

---

## 🧩 What is CGAuth?

**CGAuth** is a universal license and authentication API designed for developers who want to:
- Protect their software with **license key or account-based authentication**
- Bind each license to a specific **device (HWID)**
- Secure communications with **AES encryption + HMAC validation**
- Prevent tampering, replay attacks, or key sharing

---

## 🗂️ Repository Structure

Each folder in this repository contains a fully functional example project for a specific programming language:

| Folder | Language | Description |
|--------|-----------|-------------|
| **Example C# Sharp** | C# (.NET Framework) | A Windows Forms demo with account and license verification |
| **Example C++** | C++ | A cross-platform implementation using OpenSSL and libcurl |
| **Example JavaScript** | JavaScript (Browser) | A web-based authentication example using Web Crypto API |
| **Example PHP** | PHP | A lightweight server-side integration with license expiration logic |
| **Example Python** | Python | A console-based client using AES, HMAC, and WMI for HWID |
| **Example VB.NET** | VB.NET | A .NET WinForms example with license and user authentication |

> Each example includes its own **README.md** file explaining dependencies, setup, and usage.

---

## 🔐 Getting Started

1. **Create an Account**  
   Sign up at [https://cgauth.com/sign-in](https://cgauth.com/sign-in)

2. **Get Your API Credentials**  
   Once logged in, create your application and copy:
   - `YOUR_APP_NAME`
   - `API_KEY`
   - `API_SECRET`
   - `SSL_KEY`

3. **Open the Example Folder**  
   Choose your preferred language and follow the instructions in its `README.md`.

4. **Test and Integrate**  
   After adding your API credentials, you can start generating and validating licenses immediately.

---

## 🧰 Common Dependencies

Depending on your selected language, you may need to install certain libraries:

| Language | Required Libraries / Tools |
|-----------|----------------------------|
| **C# / VB.NET** | `Newtonsoft.Json`, `System.Net`, `System.Security.Cryptography`, `System.Management` |
| **C++** | `openssl`, `curl`, `nlohmann-json` |
| **JavaScript** | Native Web APIs (Fetch, Web Crypto) — no installation required |
| **PHP** | Built-in cURL & OpenSSL extensions |
| **Python** | `requests`, `pycryptodome`, `wmi` |

> Follow the installation instructions provided in each language’s subfolder.

---

## 🧠 How the System Works

All integrations follow the same core logic:
1. Generate a **Hardware ID (HWID)** from unique device information  
2. Encrypt request payload using **AES-256-CBC**  
3. Sign data using **HMAC-SHA256**  
4. Send the encrypted payload to CGAuth’s API  
5. Validate server response integrity via timestamp and HMAC  
6. Decrypt the response and verify the license or account data  

This ensures every authentication request is **secure, unique, and tamper-proof**.

---

## 🚨 Common Error Codes

| Error Code | Meaning |
|-------------|-------------|
| `RATE_LIMIT_EXCEEDED` | Too many requests — rate limit exceeded. |
| `METHOD_NOT_ALLOWED` | Invalid HTTP method (only POST is allowed). |
| `INVALID_TYPE` | The “type” parameter must be either `license` or `user`. |
| `MISSING_PARAMETERS` | Required parameters (e.g., key, HWID) are missing. |
| `MISSING_PASSWORD` | Password is required for user authentication. |
| `INVALID_LICENSE` | The license key is invalid or not found. |
| `LICENSE_BANNED` | The license has been banned. |
| `LICENSE_EXPIRED` | The license has expired. |
| `UNKNOWN_STATUS` | The license has an unknown status. |
| `HWID_MISMATCH` | This account or license is registered to another device. |
| `USER_EXPIRED` | The user’s license period has expired. |
| `FROZEN` | The account or license is temporarily frozen. |
| `FROZEN_EXPIRED` | The frozen period has expired. |
| `BANNED` | The user or IP is banned. |
| `Decrypt error` | AES decryption failed (invalid key or IV). |

If any of these occur, ensure your API credentials and SSL hash are correctly set.  
For more details, visit the [API Documentation](https://cgauth.com/api-help).

---

## 🧾 API Documentation

Comprehensive usage details, request examples, and encryption specs are available at:

➡️ [https://cgauth.com/api-help](https://cgauth.com/api-help)

---

## ⚙️ Supported Platforms

| Language | Platform | Status |
|-----------|-----------|--------|
| C# / VB.NET | Windows (.NET Framework 4.7+) | ✅ Supported |
| C++ | Windows, Linux, macOS | ✅ Supported |
| JavaScript | Browser / Node.js | ✅ Supported |
| PHP | Any Web Server (PHP 7.4+) | ✅ Supported |
| Python | Windows, Linux, macOS | ✅ Supported |

---

## ✅ Quick Setup Summary

1. Clone this repository  
2. Open your preferred **Example folder**  
3. Install the required dependencies  
4. Edit your API credentials in the main module (e.g., `CGAuth_Module`, `cgauth_module.py`, etc.)  
5. Run or compile the example project  

You can now issue, verify, and manage licenses directly from your own software.

---

## 📜 License

This repository is distributed under the **MIT License**.  
You may freely use, modify, and integrate it into your applications.

---

**Created for developers integrating CGAuth into C#, C++, JavaScript, PHP, Python, and VB.NET projects.**
