# CGAuth License Verification System (Python)

A secure, production-ready **license & authentication system** for Python apps, integrated with the [CGAuth](https://cgauth.com) API. It supports **license-key** and **username/password** flows, hardware‑bound access (HWID), AES‑256‑CBC encryption, and HMAC integrity checks. fileciteturn3file0

---

## 🧩 What’s inside

- 🔐 **License key / user login** verification via CGAuth API
- 💻 **HWID binding** using system identifiers (WMI on Windows; cross‑platform fallback) fileciteturn3file0
- 🧠 **AES‑256‑CBC** payload encryption + **HMAC‑SHA256** verification fileciteturn3file0
- ⏱️ **Timestamp check** to prevent replay attacks fileciteturn3file0
- 🧪 A ready‑to‑run **console demo** (`main_console.py`) to test both flows fileciteturn3file1

---

## 🔐 Create your CGAuth account

Sign in or register to obtain your credentials:

➡️ https://cgauth.com/sign-in

You’ll need the following values for your app:

- **YOUR_APP_NAME**
- **API_KEY**
- **API_SECRET**
- **SSL_KEY**

For parameter details and request/response formats, see: https://cgauth.com/api-help

---

## 📦 Requirements

You **must** install these packages (otherwise it will not work):

```bash
pip install requests pycryptodome wmi
```

> `wmi` is required for Windows HWID; non‑Windows platforms use a fallback strategy automatically. fileciteturn3file0

---

## ⚙️ Configuration

Open **`cgauth_module.py`** and set your credentials near the top of the file:

```python
class CGAuth:
    API_URL = "https://cgauth.com/api/v1/"
    YOUR_APP_NAME = "YOUR_APP_NAME"
    API_KEY = "YOUR_API_KEY"
    API_SECRET = "YOUR_API_SECRET"
    SSL_KEY = "YOUR_SSL_KEY"
```
fileciteturn3file0

Once these are saved, you can immediately create licenses in your dashboard and start validating them from your app.

---

## 🚀 Quick start (console demo)

Run the included demo to test **License** and **User** authentication, or to print your **HWID**:

```bash
python main_console.py
```
The menu lets you:
- `1` → Test License Key (calls `CGAuth.auth_license(...)`) fileciteturn3file1
- `2` → Test Username/Password (calls `CGAuth.auth_user(...)`) fileciteturn3file1
- `3` → Show HWID (`CGAuth.get_hwid()`) fileciteturn3file1

Behind the scenes `CGAuth` encrypts your payload, posts to the API, verifies the timestamp/HMAC, decrypts the data, and returns a JSON object with `success`, `data`, or `error`. fileciteturn3file0

---

## 💡 Use in your code

### License key authentication
```python
from cgauth_module import CGAuth

hwid = CGAuth.get_hwid()
res = CGAuth.auth_license("LICENSE-KEY-HERE", hwid)
if res.get("success"):
    print("OK:", res["data"])
else:
    print("ERR:", res.get("error"))
```
fileciteturn3file0

### Username/password authentication
```python
from cgauth_module import CGAuth

hwid = CGAuth.get_hwid()
res = CGAuth.auth_user("USERNAME", "PASSWORD", hwid)
```
fileciteturn3file0

### Get the HWID only
```python
from cgauth_module import CGAuth
print(CGAuth.get_hwid())
```
fileciteturn3file0

---

## 🧰 How it works (security)

- **HWID**: Built from CPU/board/BIOS via WMI on Windows, otherwise falls back to host/user; then SHA‑256 hashed. fileciteturn3file0  
- **Encryption**: Payloads encrypted with **AES‑256‑CBC** using a key derived from `API_SECRET`; IV is randomized per request and prepended. fileciteturn3file0  
- **Integrity**: Server returns `data` + `hmac` + `timestamp`; client checks timestamp and validates HMAC (**SHA‑256**) before decrypting. fileciteturn3file0

---

## 🚨 Error codes & meanings

| Code | Meaning |
|---|---|
| `INVALID_API_KEY` | API key is invalid or missing. |
| `INVALID_LICENSE` | License key is invalid, expired, or not found. |
| `INVALID_USER` | Username or password is incorrect. |
| `HWID_MISMATCH` | License is bound to a different device. |
| `EXPIRED` | License/session has expired. |
| `HMAC_FAILED` | Data integrity (HMAC) verification failed. |
| `SSL_VERIFICATION_FAILED` | SSL certificate mismatch detected. |
| `CONNECTION_ERROR` | Network/HTTP error while contacting the API. |

If you encounter errors, verify your **App Name**, **API Key/Secret**, and system time; then re‑run the request. (See API docs for full reference.)

---

## ✅ Setup checklist

1. Create an account and app: **cgauth.com/sign-in**  
2. Install dependencies: `pip install requests pycryptodome wmi`  
3. Edit credentials in `cgauth_module.py`  
4. Run `python main_console.py` and test both flows  
5. Start issuing licenses and using them in your software

---

## 📜 License

This project is provided under the **MIT License**. You can modify and integrate it in your apps that use CGAuth.
