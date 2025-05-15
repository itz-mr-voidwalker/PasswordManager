# 🔐 GUI Password Manager
A secure, modular, and user-friendly **Password Manager** built in Python using `Tkinter`, `Fernet Encryption`, and `OS keyring` for secure key management.

## 🚀 Features

- GUI-based password management using `Tkinter`
- Encrypted data storage with `cryptography.fernet`
- Fernet keys stored securely in **OS keyring**
- First-time setup and returning user login
- Environment-based configuration via `.env`
- Persistent storage of passwords in encrypted `.dat` file
- Logging for debugging and auditing
- Smart password generator
- Clean modular codebase (`auth/`, `app/` structure)

## 🛠 Installation
    git clone <this-repo>
    cd PractisePlayground
    pip install -r requirements.txt

## 📦 Running the App

    python main.py

-On first run: it will initialize setup for user authentication.
-On subsequent runs: it will launch the login screen.

## 🧠 Developer Notes

- All sensitive data is encrypted using Fernet (AES-based symmetric encryption).
- The encryption key is stored in OS keyring, not in plaintext anywhere.
- Weak passwords are allowed for storage to reflect real-world use cases.

## 📁 Project Structure

```
PractisePlayground/
├── main.py # Main launcher (entry point)
├── .env # Global environment config
├── requirements.txt # Python package list
├── README.md # Project documentation
│
├── app/
│ ├── app.py # GUI logic (Password Manager)
│ ├── .env # App-level environment variables
│ └── data/
│ └── records.dat # Encrypted password store
│
└── auth/
├── SecureLayer.py # Fernet-based encryption handler
├── login.py # Login screen logic
├── onboarding.py # First-time setup UI
└── auth_logging.py # Logging setup

## 👑 Credits
    Made with Passion by Sai Vignesh

## 📜 License
- This project is open-source. Feel free to modify and build on top of it.
