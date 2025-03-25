# 🔐 Secure File Sharing App

A secure file sharing and transfer platform that ensures **confidentiality, integrity, and authenticity** through **end-to-end encryption**, **two-factor authentication**, and **role-based access control**. Designed for both individual and collaborative use cases, this system offers robust privacy features, anomaly detection, and smart storage handling.

---

## 🚀 Features

### 🔐 Authentication & User Management
- User registration with email-based OTP verification
- Secure login with OTP-based two-factor authentication (2FA)
- JWT-based session management
- Public/Private RSA key generation for each user
- Profile management (update info, upload avatar, toggle privacy)

### 📤 Secure File Upload
- AES-256 encrypted file content
- RSA-encrypted AES keys for recipients
- File segmentation for large file handling
- Visibility levels: `friends`, `closeFriends`, `public`
- File expiration options (1 hour, 1 day, 1 week, 1 month, 1 year, never)

### 📥 Secure File Download
- Private key decryption of AES keys
- File reassembly after decryption
- Integrity check (SHA-256 hash comparison)
- File download tracking and notifications

### 📁 File Management
- Chunked upload support with encrypted segments
- Soft delete (trash) and restore functionality
- Permanent deletion (owner-only)
- File listing with filters (owner, friends, shared)
- Storage usage monitoring with warnings at 90% capacity

### 👥 Friend System
- Friend requests and acceptance
- Manage close friends
- Profile visibility control
- Friend profile viewer with shared files

### 📊 Anomaly Detection
- File download frequency monitoring
- Flags files accessed unusually often
- Logs suspicious activity to `application.log`

### 🔔 Notifications
- Real-time system notifications:
  - File upload success
  - Download by other users
  - Friend request / acceptance
  - Storage nearing capacity
  - Integrity violation alerts

---


---

## 🛡️ Tech Stack

- **Node.js + Express** — backend REST APIs
- **MongoDB + Mongoose** — database & ODM
- **Multer** — file handling
- **Crypto** — AES + RSA encryption
- **JWT** — stateless authentication
- **Nodemailer** — OTP via email
- **Winston** — logging & anomaly detection
- **HTML/CSS/JS** — frontend interface

---

## 🧪 Security Model
____________________________________________________________________ 
| Security Feature     | Description                                |
|----------------------|--------------------------------------------|
| AES-256 Encryption   | Encrypts file content before upload        |
| RSA Key Wrapping     | Encrypts AES keys for each recipient       |
| Private Key Required | Decryption only possible with private key  |
| OTP-based 2FA        | Verifies user identity on login            |
| Hash Verification    | SHA-256 hash ensures integrity             |
| File Expiry Support  | Auto-deletes file access after expiry      |
| Visibility Control   | `friends`, `closeFriends`, `public`        |
| Anomaly Detection    | Detects suspicious download patterns       |
---------------------------------------------------------------------

---

## 🧠 Future Enhancements

- ✅ True streaming upload/download for very large files
- ⏳ Partial download resume and resume-token
- 📱 SMS-based OTP (optional)
- 📤 File versioning and history
- 📁 Shared folder feature
- 📈 Admin dashboard for system usage

---

## ⚙️ Setup & Run

```bash
# Clone and install dependencies
git clone https://github.com/your-repo/secure-file-sharing.git
cd secure-file-sharing
npm install

# Set up your .env file
cp .env.example .env
# Add MONGO_URI and JWT_SECRET

# Start server
node server.js
