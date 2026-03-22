<div align="center">



# 🛡️ PHANTOM

### تشفير وإخفاء البيانات داخل الملفات · Encryption & Data Steganography

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20ARM-blue?style=flat-square)](#-الأنظمة-المدعومة--supported-platforms)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-red?style=flat-square)](#-المميزات--features)

</div>

---

## 📖 عن الأداة | About

**AR:** PHANTOM أداة تتيح لك تشفير وحقن الملفات الحساسة داخل ملفات أخرى (ناقلات) مثل الصور أو الفيديوهات أو الملفات الصوتية، دون التأثير على مظهر أو وظيفة الملف الأصلي.

**EN:** PHANTOM allows you to encrypt and inject sensitive files into carrier files (images, videos, audio, etc.) without affecting the appearance or function of the original file.

---

## ✨ المميزات | Features

| الميزة | Feature | التفاصيل |
|--------|---------|----------|
| 🔐 تشفير  | Strong Encryption | AES-256-GCM + Argon2id (OWASP recommended) |
| 🖼️ إخفاء متعدد الوسائط | Multi-media Steganography | يدعم أي صيغة رقمية كناقل · Any file format as carrier |
| 🔗 ارتباط تكاملي | Integrity Binding (AAD) | فك التشفير مرتبط بـ Hash الملف الناقل · Decryption tied to carrier hash |
| 🎭 كلمة مرور وهمية | Decoy Password | Plausible Deniability — ملف وهمي عند الإكراه |
| 📁 دعم المجلدات | Directory Support | يضغط المجلدات تلقائياً قبل الإخفاء |
| 💾 عداد محاولات دائم | Persistent Attempt Counter | العداد محفوظ داخل الـ vault — لا يُعاد عند إعادة تشغيل الأداة |
| 🔥 مسح آمن | Secure Wipe | 3 passes من random data قبل الحذف |
| ⚡ Streaming | Chunked Streaming | يدعم ملفات ضخمة بدون استهلاك RAM |

---

## ⚠️ تحذير مهم | Important Warning

> **AR:** إدخال كلمة مرور خاطئة 3 مرات (في حال تفعيل خيار المسح) سيؤدي إلى **تدمير الـ vault نهائياً** بشكل لا يمكن التراجع عنه.
>
> **EN:** Entering the wrong password 3 times (if wipe is enabled) will **permanently destroy the vault** with no recovery possible.

---

## 🚀 دليل التشغيل | Usage Guide

### الصيغة العامة | General Syntax

```
hide   [--wipe] <secret_file_or_dir> <carrier_file> <output_name>
reveal <vault_file> <output_name>
```

---

### 🪟 Windows

افتح **PowerShell** أو **Terminal** داخل مجلد الأداة:

**إخفاء ملف | Hide a file:**
```powershell
.\phantom.exe hide secret.txt cover.jpg output
# → output.jpg (امتداد الـ carrier تلقائياً)
```

**إخفاء مع تفعيل المسح التلقائي | Hide with auto-wipe:**
```powershell
.\phantom.exe hide --wipe secret.txt cover.jpg output
```

**إخفاء مجلد كامل | Hide a directory:**
```powershell
.\phantom.exe hide --wipe my_folder\ cover.jpg output
```

**استخراج | Reveal:**
```powershell
.\phantom.exe reveal output.jpg restored
# → restored.txt (امتداد الملف الأصلي تلقائياً)
```

---

### 🐧 Linux

**منح صلاحيات التنفيذ | Grant permissions:**
```bash
chmod +x phantom_linux_amd64
```

**إخفاء ملف | Hide a file:**
```bash
./phantom_linux_amd64 hide secret.txt cover.mp4 output
```

**استخراج | Reveal:**
```bash
./phantom_linux_amd64 reveal output.mp4 restored
```

---

### 🍎 macOS

```bash
chmod +x phantom_macos_apple_silicon   # or phantom_macos_intel

./phantom_macos_apple_silicon hide secret.pdf cover.jpg output
./phantom_macos_apple_silicon reveal output.jpg restored
```

---

## 💻 الأنظمة المدعومة | Supported Platforms

| النظام | الملف التنفيذي |
|--------|--------------|
| Windows 64-bit | `phantom_windows_amd64.exe` |
| Windows 32-bit | `phantom_windows_386.exe` |
| Windows ARM64 | `phantom_windows_arm64.exe` |
| Linux 64-bit | `phantom_linux_amd64` |
| Linux ARM64 (Pi 4+) | `phantom_linux_arm64` |
| Linux ARM32 (Pi 2/3) | `phantom_linux_arm32` |
| Linux 32-bit | `phantom_linux_32bit` |
| macOS Intel | `phantom_macos_intel` |
| macOS Apple Silicon (M1/M2/M3/M4) | `phantom_macos_apple_silicon` |

---

## 🔨 البناء من المصدر | Build from Source

**متطلبات | Requirements:** Go 1.21+

```bash
git clone https://github.com/Marwan-Omar729/fcrypto
cd fcrypto
go mod tidy
```

**Linux / macOS:**
```bash
chmod +x build.sh
./build.sh
```

**Windows (PowerShell):**
```powershell
.\build.ps1
```

---

## 🔒 التفاصيل الأمنية | Security Details

| المكوّن | التفاصيل |
|--------|---------|
| **Key Derivation** | Argon2id — time=3, memory=64MB, threads=4 |
| **Encryption** | AES-256-GCM — Chunked (1MB chunks) |
| **Nonce** | Per-chunk unique nonce via XOR with chunk index |
| **AAD** | carrier hash + version + slot type |
| **Secure Wipe** | 3-pass random overwrite + `fsync` before delete |
| **Attempt Counter** | Persisted inside vault header — survives restarts |
| **Decoy Slot** | Always present — prevents structural fingerprinting |

---

## 👥 المطورون | Developers

<table>
<tr>

<td align="center">

### Marwan-Omar (kitsune) 🦊

[![YouTube](https://img.shields.io/badge/YouTube-red?style=flat-square&logo=youtube)](https://youtube.com/@kitsune_prog)
[![TikTok](https://img.shields.io/badge/TikTok-black?style=flat-square&logo=tiktok)](https://www.tiktok.com/@kitsune_fire0)
[![Facebook](https://img.shields.io/badge/Facebook-blue?style=flat-square&logo=facebook)](https://www.facebook.com/share/14acL8gk5jS/)
[![GitHub](https://img.shields.io/badge/GitHub-333?style=flat-square&logo=github)](https://github.com/Marwan-Omar729/fcrypto)

</td>

<td align="center">

### Youssef-Zakaria (JOURIFT) 

[![YouTube](https://img.shields.io/badge/YouTube-red?style=flat-square&logo=youtube)](https://www.youtube.com/@JOURIFT)
[![TikTok](https://img.shields.io/badge/TikTok-black?style=flat-square&logo=tiktok)](https://www.tiktok.com/@jourift)
[![Facebook](https://img.shields.io/badge/Facebook-blue?style=flat-square&logo=facebook)](https://www.facebook.com/share/1DPT7MsVwj/)
[![GitHub](https://img.shields.io/badge/GitHub-333?style=flat-square&logo=github)](https://github.com/Joussef76)

</td>

</tr>
</table>

---

<div align="center">

**PHANTOM v2** — Zero-Knowledge Shadow Vault

*Kitsune & JOURIFT · 2026*

</div>


