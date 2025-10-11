# CGAuth License Verification System (JavaScript)

A modern, browser-compatible **license and authentication system** written in JavaScript.  
This client library allows secure license verification and user authentication directly from the browser or any Node.js-compatible environment, integrated with the [CGAuth](https://cgauth.com) API.

---

## 🧩 Overview

This JavaScript version of CGAuth provides:

- 🔐 **License Key** and **User/Password** authentication  
- 💻 **Browser-based HWID (fingerprint) generation**  
- 🧠 **AES-256-CBC encryption** and **HMAC-SHA256** integrity verification  
- 🛡️ **Timestamp validation** to prevent replay attacks  
- ⚡ Lightweight and easy integration using native **Web Crypto API**

---

## 🔐 Getting Started

### 1. Register on CGAuth
Create your developer account and get your API credentials here:

➡️ [Sign in or Register at CGAuth.com](https://cgauth.com/sign-in)

You will receive:
- **YOUR_APP_NAME**
- **API_KEY**
- **API_SECRET**
- **SSL_KEY**

These credentials are required for your project to communicate securely with CGAuth.

---

### 2. Project Setup

Simply include the `cgauth.js` file in your web project:

```html
<script src="cgauth.js"></script>
```

Or import it into your JavaScript module:
```js
import './cgauth.js';
```

If you’re using Node.js, ensure the environment supports the Web Crypto API (Node 18+).

---

### 3. Configure Your Credentials

Open the file `cgauth.js` and set the following constants at the top of the class:

```js
static YOUR_APP_NAME = "YOUR_APP_NAME_HERE";
static API_KEY = "YOUR_API_KEY_HERE";
static API_SECRET = "YOUR_API_SECRET_HERE";
```

> 🔑 You can find all required values on your [API Help page](https://cgauth.com/api-help).

---

### 4. Example Usage

#### ▶ License Key Authentication
```js
const hwid = await CGAuth.getHWID();
const result = await CGAuth.authLicense("LICENSE-KEY-HERE", hwid);

if (result.success) {
  console.log("License Verified:", result.data);
} else {
  console.error("Error:", result.error);
}
```

#### ▶ Username/Password Authentication
```js
const hwid = await CGAuth.getHWID();
const result = await CGAuth.authUser("USERNAME", "PASSWORD", hwid);

if (result.success) {
  console.log("Login Successful:", result.data);
} else {
  console.error("Error:", result.error);
}
```

#### ▶ Retrieve Browser HWID
```js
const hwid = await CGAuth.getHWID();
console.log("Your Browser HWID:", hwid);
```

> Each user/device receives a **unique browser fingerprint** based on system details, WebGL, canvas rendering, and screen data.

---

## ⚙️ Browser Demo (Optional)

You can test your integration using the included `preview.html` file.  
It provides an interactive UI with tabs for:
- License Key authentication  
- Username/Password authentication  
- Viewing and copying your HWID  

Just open `preview.html` in any browser to try it out.

---

## 📦 Dependencies

No external libraries are required — this version uses built-in **Web APIs**:

- **Fetch API** → for HTTPS communication  
- **Web Crypto API** → for AES & HMAC  
- **Canvas & WebGL** → for HWID generation  

Works natively in all modern browsers (Chrome, Edge, Firefox, Safari) and Node.js 18+.

---

## 🚨 Error Codes & Meanings

| Error Code | Description |
|-------------|-------------|
| `INVALID_API_KEY` | Your API key is invalid or not recognized. |
| `INVALID_LICENSE` | The license key is invalid, expired, or not found. |
| `INVALID_USER` | Username or password is incorrect. |
| `HWID_MISMATCH` | License is tied to a different device/browser. |
| `EXPIRED` | License or session has expired. |
| `HMAC_FAILED` | Data integrity verification failed. |
| `SSL_VERIFICATION_FAILED` | SSL certificate mismatch detected. |
| `CONNECTION_ERROR` | Network issue or unreachable CGAuth server. |

If you see any of these errors, double-check your API credentials and ensure your `API_SECRET` and system clock are correct.

---

## 🧾 API Reference

For detailed usage instructions, authentication flow, encryption examples, and JSON schema, visit:

➡️ [CGAuth API Documentation](https://cgauth.com/api-help)

---

## ✅ Quick Setup Summary

1. Register or log in at [cgauth.com/sign-in](https://cgauth.com/sign-in)  
2. Create an app and get your API credentials  
3. Set your credentials in `cgauth.js`  
4. Open `preview.html` and test authentication  
5. You can immediately start creating and validating licenses  

> After adding your credentials, your system will be ready to create new licenses and validate them within seconds.

---

## 📜 License

This project is released under the **MIT License**.  
It is free for educational and commercial integration with the CGAuth platform.

---

**Developed for JavaScript developers integrating CGAuth into secure web or desktop (Electron) applications.**
