# Antigravity Account Switcher

> Fast, seamless one-click multi-account switcher for **Google Antigravity IDE**, built as a lightweight desktop widget for **Rainmeter**.

<p align="center">
  <img src="assets/preview.png" alt="Antigravity Account Switcher Preview" width="380">
</p>

---

## ✨ Features

- **One-Click Switch:** Instantly toggle between up to 4 accounts.
- **Auto Detection:** Automatically detects and captures your active logged-in session.
- **Fluent UI:** Clean, modern desktop card supporting Windows Light & Dark themes natively.
- **Zero Dependencies:** Pure Python standard library with Windows Credential API (no `pip install` needed).
- **Standalone:** No external Rainmeter plugins or DLLs required.

---

## 📋 Prerequisites

1. **[Rainmeter](https://www.rainmeter.net/)** (v4.5 or newer)
2. **[Python 3.8+](https://www.python.org/)**  
   *(Make sure to check **"Add Python to PATH"** during installation)*
3. **Google Antigravity IDE**

---

## 🚀 Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/IamVAGENT/antigravity-account-switcher.git
   ```

2. Place the project folder into your Rainmeter skins directory:
   ```text
   Documents\Rainmeter\Skins\Antigravity-Switcher
   ```

3. Open **Rainmeter Manage**, navigate to `Antigravity-Switcher`, select `Antigravity-Switcher.ini`, and click **Load**.

---

## 💡 How to Use

### 1. First Launch (Automatic Binding)
When loaded, the widget automatically detects your current signed-in Antigravity account and binds it to **Slot 1**.

### 2. Adding Another Account
1. Click **+ SETUP** on any empty slot (e.g. `Slot 2`).
2. Antigravity will automatically relaunch into a clean sign-in screen.
3. Sign in to your secondary Google account.
4. Click **SYNC STATUS** on the widget. That account is now stored in that slot.

### 3. Switching Between Accounts
- Simply click on any configured slot row or **LAUNCH**.
- The widget handles closing the app, swapping your credentials in Windows Credential Manager, and relaunching Antigravity seamlessly.

### 4. Resetting a Slot
- Click **RESET** next to any slot to remove its stored credentials.

---

## 🔒 Privacy & Security

- All session tokens are kept strictly **local** on your own computer inside the `vault/` folder.
- Tokens are never sent anywhere.
- The `vault/` credentials folder is pre-configured in `.gitignore` to prevent accidental commits.

---

## 👤 Author

Crafted by **[VAGENT](https://github.com/IamVAGENT)**

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
