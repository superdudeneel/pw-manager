# 🔐 Password Manager

A simple, secure password manager web application built with Node.js, Express, and vanilla HTML/CSS/JavaScript. Store, retrieve, and manage your service credentials securely with a session-based master password.

---

## 🚀 Features

- 🔑 Master password login
- 💾 Add, edit, delete stored passwords
- 🔍 Search and filter by service
- 📋 Copy to clipboard feature
- 🔐 Passwords encrypted in the database
- 🕒 Session-based authentication
- 🛡️ Breach Detection Enabled

---

## 🧱 Tech Stack

- **Backend:** Node.js, Express
- **Frontend:** HTML, CSS, JavaScript
- **Database:** MongoDB (via Mongoose)
- **Authentication:** Session + Master password
- **Security:** bcrypt hashing, AES-256 encryption, dotenv

---

## 🛠 Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/superdudeneel/pw-manager.git
cd pw-manager
touch .env
npm install
npm start

