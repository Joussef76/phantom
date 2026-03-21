# 🛡️ PHANTOM: التشفير وإخفاء البيانات داخل الملفات
# 🛡️ PHANTOM: Encryption & Data Steganography

**PHANTOM** هي أداة تتيح لك تشفير وحقن الملفات الحساسة داخل ملفات أخرى (ناقلات) مثل الصور، الفيديوهات، أو الملفات الصوتية، دون التأثير على وظيفة أو مظهر الملف الأصلي.

**PHANTOM** is a tool that allows you to encrypt and inject sensitive files into other files (carriers) such as images, videos, or audio files, without affecting the function or appearance of the original file.

---

## ✨ المميزات | Features 
* **تشفير قياسي:** تعتمد الأداة على خوارزمية $AES-256-GCM$ لضمان أقصى درجات السرية والتحقق.
  * **Standard Encryption:** Uses $AES-256-GCM$ algorithm to ensure maximum confidentiality and integrity.
* **إخفاء متعدد الوسائط:** لا تقتصر الأداة على الصور فقط، بل تدعم إخفاء "ملف داخل ملف" لأي صيغة رقمية.
  * **Multi-media Steganography:** Not limited to images; supports "file-in-file" hiding for any digital format.
* **الارتباط التكاملي (AAD):** عملية فك التشفير مرتبطة بالبصمة الرقمية (Hash) للملف الحامل؛ أي تعديل في الملف الأصلي سيؤدي لفشل العملية.
  * **Associated Data (AAD):** Decryption is linked to the carrier file's Hash; any tampering with the original file will cause the process to fail.

---

## ⚠️ تحذير | Important Warning
إدخال كلمة مرور خاطئة أثناء محاولة الاستخراج سيؤدي فوراً إلى تدمير الملف (**Self-destruct mechanism**).

Entering an incorrect password during extraction will immediately lead to file destruction (**Self-destruct mechanism**).

---

## 🚀 دليل التشغيل | Usage Guide

### 1️⃣ نظام ويندوز (Windows)
افتح واجهة الأوامر (**PowerShell**) داخل مجلد الأداة:
Open **PowerShell** inside the tool directory:

**للإخفاء (Hide):**
```powershell
.\phantom.exe hide secret.zip cover.jpg "password123"
للاستخراج (Reveal):

PowerShell
.\phantom.exe reveal vault_file "password" output_file
### 2️⃣ أنظمة لينكس (Linux)
افتح الطرفية ونفذ الأوامر التالية:
Open the Terminal and execute the following commands:

منح صلاحيات التنفيذ (Grant Permissions):

Bash
chmod +x phantom_linux
للإخفاء (Hide):

Bash
./phantom hide secret.txt cover.mp4 pass123
للاستخراج (Reveal):

Bash
./phantom reveal vault_file "password" output_file


المطورين(Developers) 

### Marwan-Omar (kitsune)
*  [YouTube](https://youtube.com/@kitsune_prog)
*  [TikTok](https://www.tiktok.com/@kitsune_fire0)
*  [Facebook](https://www.facebook.com/share/14acL8gk5jS/)
*  [GitHub](https://github.com/Marwan-Omar729/fcrypto)
########################################################################

### Youssef-Zakaria (JOURIFT)
*  [YouTube](https://www.youtube.com/@JOURIFT)
*  [TikTok](https://www.tiktok.com/@jourift)
*  [Facebook](https://www.facebook.com/share/1DPT7MsVwj/)
*  [GitHub](https://github.com/Joussef76)
