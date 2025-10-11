# CGAuth License Verification System (VB.NET)

A secure, full-featured **license and authentication system** built with VB.NET.  
This system integrates directly with the [CGAuth](https://cgauth.com) API to provide **license key** and **user authentication** functionality for your desktop software.

---

## 🧩 Overview

This VB.NET implementation of CGAuth provides:
- 🔐 **License key** and **user login** verification  
- 💻 Hardware-based **HWID (Hardware ID)** binding  
- 🧠 **AES-256-CBC** encryption and **HMAC-SHA256** integrity checks  
- 🛡️ SSL pinning to prevent tampering and MITM attacks  
- ⚙️ Easy integration into WinForms or console-based VB.NET applications  

> ⚠️ **Note:** Always compile the project in **x64 Release mode** for proper operation.

---

## 🔐 Getting Started

### 1. Create Your CGAuth Account
You must first register on CGAuth to obtain your API credentials:

➡️ [Sign in or Register at CGAuth.com](https://cgauth.com/sign-in)

You’ll receive:
- **YOUR_APP_NAME**
- **API_KEY**
- **API_SECRET**
- **SSL_KEY**

These are required for your application to authenticate with the CGAuth API.

---

### 2. Configure Your Project

Open the file **`CGAuth_Module.vb`** and fill in your API details:

```vbnet
Public Const YOUR_APP_NAME As String = "YOUR_APP_NAME_HERE"
Public Const API_KEY As String = "YOUR_API_KEY_HERE"
Public Const API_SECRET As String = "YOUR_API_SECRET_HERE"
Public Const SSL_KEY As String = "YOUR_SSL_CERT_HASH_HERE"
```

> 🔑 You can find all this information on your [API Help page](https://cgauth.com/api-help).

Once these values are entered, your application can immediately start generating and verifying licenses.

---

### 3. Usage Examples

#### ▶ License Key Authentication

```vbnet
Dim hwid As String = GetHWID()
Dim result As JObject = AuthLicense(txtLicenseKey.Text, hwid)

If result("success").ToObject(Of Boolean)() Then
    Dim data = result("data")
    MessageBox.Show("License valid for: " & data("app_name").ToString())
Else
    MessageBox.Show("Error: " & result("error").ToString())
End If
```

#### ▶ User Login Authentication

```vbnet
Dim hwid As String = GetHWID()
Dim result As JObject = AuthUser(txtUsername.Text, txtPassword.Text, hwid)

If result("success").ToObject(Of Boolean)() Then
    MessageBox.Show("Login successful!")
Else
    MessageBox.Show("Error: " & result("error").ToString())
End If
```

#### ▶ Get Hardware ID

```vbnet
Dim hwid As String = GetHWID()
MessageBox.Show("Your HWID: " & hwid)
```

> The HWID is generated based on CPU, motherboard, and BIOS identifiers to uniquely bind each license to a device.

---

## ⚙️ Forms Included

The project includes several prebuilt forms to simplify testing and implementation:

| File | Description |
|------|-------------|
| **Select_Form.vb** | Lets you choose between License or Account authentication. |
| **Test_License.vb** | Example form for license key validation. |
| **Test_Account.vb** | Example form for username/password authentication. |
| **CGAuth_Module.vb** | The main authentication module (edit this to configure your credentials). |

Simply open `Select_Form.vb`, run the project, and start testing.

---

## 🧰 Dependencies

This project requires the following:
- **Newtonsoft.Json** → for JSON parsing  
- **System.Net** → for HTTPS requests  
- **System.Security.Cryptography** → for encryption and HMAC  
- **System.Management** → for HWID generation  

You can install the JSON library via NuGet:
```bash
Install-Package Newtonsoft.Json
```

---

## 🚨 Error Codes & Meanings

| Error Code | Meaning |
|-------------|----------|
| `INVALID_API_KEY` | API key is invalid or missing. |
| `INVALID_LICENSE` | The license key does not exist or is expired. |
| `INVALID_USER` | Incorrect username or password. |
| `HWID_MISMATCH` | The license is bound to another device. |
| `EXPIRED` | The license or session has expired. |
| `HMAC_FAILED` | Data integrity check failed. |
| `SSL_VERIFICATION_FAILED` | SSL certificate mismatch detected. |
| `CONNECTION_ERROR` | Could not connect to the CGAuth server. |

If you encounter these errors, verify your API credentials and ensure the SSL key and app name match your CGAuth dashboard configuration.

---

## 🧾 API Reference

Full documentation and integration examples are available here:

➡️ [CGAuth API Documentation](https://cgauth.com/api-help)

This includes complete parameter lists, encryption details, and response structures.

---

## ✅ Quick Setup Summary

1. Register at [cgauth.com/sign-in](https://cgauth.com/sign-in)  
2. Obtain your API credentials  
3. Edit `CGAuth_Module.vb` with your credentials  
4. Build your project in **x64 Release mode**  
5. Run `Select_Form.vb` to test the authentication system  

Once configured, you can create and validate licenses in seconds.

---

## 📜 License

This project is provided under the **MIT License** for educational and commercial integration purposes.  
You are free to modify, distribute, and integrate it with your own VB.NET projects using CGAuth.

---

**Developed for VB.NET developers integrating CGAuth into secure desktop software.**
