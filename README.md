# 🔓 LCPDF Export

> Decrypt Readium LCP-protected PDF files with a clean, minimal GUI.

A lightweight Python tool that exports `.lcpdf` / `.lcpdf.zip` files to plain `.pdf` using **your own purchased passphrase**. Ships with a dark-themed Tkinter interface, automatic cover preview, and support for all known Readium LCP encryption profiles (basic, 1.0, and 2.0 → 2.9).

---

## ✨ Features

- 🖥️ **Simple GUI** — pick a file, enter a passphrase, hit Export.
- 🔑 **All LCP profiles supported** — basic, 1.0, and 2.0 through 2.9.
- 📖 **Cover preview** — shows the book cover before decryption (via Pillow).
- 📝 **Metadata readout** — displays title and detected encryption profile.
- 🧠 **Thorium Reader integration** — auto-fills the passphrase if the book was previously opened in [Thorium Reader](https://www.edrlab.org/software/thorium-reader/).
- 🧾 **Live log panel** — see exactly what's happening during decryption.
- 🪶 **Zero config** — single-file Python script, no build step.

---

## 📦 Installation

### Requirements

- Python **3.8+**
- [`pycryptodome`](https://pypi.org/project/pycryptodome/) (required)
- [`Pillow`](https://pypi.org/project/Pillow/) (optional — enables cover preview)

### Setup

```bash
git clone https://github.com/<your-username>/lcpdf_export.git
cd lcpdf_export

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
python lcpdf_export.py
```

Then:

1. Click **Browse** and select your `.lcpdf` or `.lcpdf.zip` file.
2. Enter the **passphrase** provided by your distributor.
   *(If you've already opened the book in Thorium Reader, the passphrase may be auto-filled.)*
3. Hit **🔓 Export as PDF** — the decrypted PDF is saved next to the original file.

---

## 🔐 Supported LCP Profiles

| Profile                        | Status        |
| ------------------------------ | ------------- |
| `basic-profile`                | ✅ Supported  |
| `profile-1.0`                  | ✅ Supported  |
| `profile-2.0` – `profile-2.9`  | ✅ Supported  |

If your file uses a profile not in the list, the tool will still attempt every known transform as a best-effort fallback.

---

## 🗂️ Project structure

```
lcpdf_export/
├── lcpdf_export.py    # main script (GUI + crypto)
├── requirements.txt   # Python dependencies
├── .gitignore
├── LICENSE
└── README.md
```

---

## ⚖️ Disclaimer

This tool exports content that **you already have legal access to** via your own purchased passphrase. It does not bypass, break, or circumvent any security — it simply decrypts with the key you were legitimately given. Use it for **personal, legal use only** — e.g. reading books you have purchased on a device or application of your choice. You are responsible for ensuring your use complies with your local laws and the terms of service of your content provider.

---

## 📜 License

Released under the MIT License. See [LICENSE](LICENSE) for details.
