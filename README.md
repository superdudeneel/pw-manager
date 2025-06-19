# 🔐 Password Manager

A lightweight, secure password manager built with Node.js, Express, and vanilla JavaScript. Store, retrieve, and manage your credentials locally with session-based authentication and strong encryption.

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" />
  <img src="https://img.shields.io/github/license/superdudeneel/pw-manager" />
  <img src="https://img.shields.io/badge/Security-AES--256%20%2B%20bcrypt-blue" />
</p>

---

## ✨ Features

- 🔐 **Master Password Authentication** – Secure access to all stored credentials.
- 💾 **CRUD Support** – Add, edit, delete services and credentials.
- 🔍 **Search & Filter** – Quickly find saved credentials by service name.
- 📋 **One-click Copy** – Easily copy passwords to clipboard.
- 🔐 **End-to-End Encryption** – AES-256 encryption for stored passwords.
- 🔒 **Hashed Authentication** – Master password stored using bcrypt.
- 🛡️ **Session-based Security** – Safe login sessions using cookies.
- 🚨 **Breach Detection** – (Optional) Integration-ready for checking password leaks.

---

## 🧱 Tech Stack

| Layer        | Tech                           |
|--------------|--------------------------------|
| **Backend**  | Node.js, Express               |
| **Frontend** | HTML, CSS, Vanilla JavaScript  |
| **Database** | MongoDB with Mongoose          |
| **Security** | bcrypt, AES-256, dotenv        |
| **Auth**     | Session-based authentication   |

---

## ⚙️ Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/superdudeneel/pw-manager.git
cd pw-manager
