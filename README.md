# 🔐 Secure Vault Pro

🛡️ A robust, encrypted data vault built with **Streamlit**, using **Fernet encryption** from the `cryptography` library. This app allows you to **securely store and retrieve sensitive data** in-memory with user-defined passkeys, completely independent of external databases.

---

## 🚀 Features

- ✅ **In-memory Encryption** – No external DB required
- 🔑 **Passkey-Protected Storage** – Data locked behind your custom passphrase
- 🧠 **Hint System** – Add reminders to help recall your stored data
- 🏷️ **Tags Support** – Categorize your saved secrets for better organization
- 🔐 **Secure Login Flow** – Only authorized users can store or retrieve data
- 🧼 **3 Failed Login Attempts Lockout** – Enhanced protection against brute-force
- ⚙️ **Admin Utilities** – View or clear vault data via advanced tools section

---

## 🧪 Tech Stack

| Tech             | Purpose                            |
|------------------|-------------------------------------|
| [Streamlit](https://streamlit.io) | UI rendering & session management |
| `cryptography.fernet` | Secure symmetric encryption     |
| `hashlib`        | SHA-256 password hashing           |
| Python           | Core logic & backend               |

---

## 📦 Installation

```bash
git clone https://github.com/Tayyaba-Ramzan/Secure-Data-Encryption-using-Streamlit-Fernet.git
pip install -r requirements.txt
streamlit run app.py

💡 Make sure Python 3.8+ is installed and activated.

🔐 How It Works
🔐 Login using the master password (admin123 by default — can be improved).

➕ Store Encrypted Data with a unique ID and your custom passkey.

🔓 Retrieve Data only by entering the correct ID and corresponding passkey.

⚠️ 3 Failed Attempts = auto lockout from the system.

🔄 Sample Flow
Login from 🔐 Login tab

Navigate to ➕ Store Data

Add your text, passkey, tags, and an optional hint

View stored entries under ⚙️ Advanced Features

🛡️ Security Notes
🔒 All data is stored in-memory only (no saving to disk or server)

🔑 Encryption with Fernet (AES 128 under the hood)

🧮 Passwords are hashed with SHA-256 before storage

🚫 No hardcoded sensitive data (except temporary master password for demo)

📁 Project Structure
├── app.py               # Main Streamlit app
├── requirements.txt     # All required dependencies
└── README.md            # You are here

🔧 To-Do (Optional Enhancements)
 Persistent storage with optional DB toggle (SQLite or Firebase)

 Custom user authentication system

 Password strength meter

 Encrypted file uploads

🤝 Contributing
PRs are welcome! Feel free to fork and enhance the vault 🚀

📜 License
MIT License © 2025 – Made with ❤️ and 💻 by 𝒯𝒶𝓎𝓎𝒶𝒷𝒶 𝑅𝒶𝓂𝓏𝒶𝓃
