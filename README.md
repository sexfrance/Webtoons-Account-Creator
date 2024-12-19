<div align="center">
  <h2 align="center">Webtoons Account Creator</h2>
  <p align="center">
This script is an asynchronous account generator for Webtoons that features proxy support, RSA encryption, and efficient batch processing. It automatically creates Webtoons accounts with random credentials, validates the creation process, and provides formatted output.
    <br />
    <br />
    <a href="https://discord.cyberious.xyz">💬 Discord</a>
    ·
    <a href="https://github.com/sexfrance/Webtoons-Account-Creator#-changelog">📜 ChangeLog</a>
    ·
    <a href="https://github.com/sexfrance/Webtoons-Account-Creator/issues">⚠️ Report Bug</a>
    ·
    <a href="https://github.com/sexfrance/Webtoons-Account-Creator/issues">💡 Request Feature</a>
  </p>
</div>

### ⚙️ Installation

- Requires: `Python 3.7+`
- Make a python virtual environment: `python3 -m venv venv`
- Source the environment: `venv\Scripts\activate` (Windows) / `source venv/bin/activate` (macOS, Linux)
- Install the requirements: `pip install -r requirements.txt`

---

### 🔥 Features

- Creates Webtoons accounts automatically with random or custom credentials
- Supports both proxy and proxyless modes
- Logs results with different levels (success, failure)
- Generates random valid email addresses and secure passwords
- Saves the created accounts to a file with email:password format

---

### 📝 Usage

- (Optional) Prepare a file named `proxies.txt` with proxies, one per line in user:pass@ip:port format, if you want to use proxies.

- (Optional) Configure input/config.yaml with settings such as proxyless, debug mode, threading and rate limit handling

- Run the script:
  ```sh
  python main.py
  ```

---

### 📹 Preview

![Preview](https://i.imgur.com/qPJpXTs.gif)

---

### ❗ Disclaimers

- I am not responsible for anything that may happen, such as API Blocking, IP ban, etc.
- This was a quick project that was made for fun and personal use if you want to see further updates, star the repo & create an "issue" [here](https://github.com/sexfrance/Webtoons-Account-Creator/issues/)

---

### 📜 ChangeLog

```diff
v0.0.1 ⋮ 12/07/2024
! Initial release
```

---

<p align="center">
  <img src="https://img.shields.io/github/license/sexfrance/Webtoons-Account-Creator.svg?style=for-the-badge&labelColor=black&color=f429ff&logo=IOTA"/>
  <img src="https://img.shields.io/github/stars/sexfrance/Webtoons-Account-Creator.svg?style=for-the-badge&labelColor=black&color=f429ff&logo=IOTA"/>
  <img src="https://img.shields.io/github/languages/top/sexfrance/Webtoons-Account-Creator.svg?style=for-the-badge&labelColor=black&color=f429ff&logo=python"/>
</p>
