# 0x01 - Python Scripting

## Requirements

### General

- Python `3.8+` required
- Allowed editors: `vi`, `vim`, `emacs`
- All scripts are tested on **Kali Linux**
- All files must be **executable**
- All files should end with a new line
- The first line of all files must be exactly:
  ```
  #!/usr/bin/env python3
  ```
- Code must follow the `pycodestyle` style
- Code must not execute when imported (use `if __name__ == "__main__":`)
- Using a **Virtual Environment** is best practice

---

## Required Libraries

```bash
pip install scapy>=2.5.0
pip install dnspython>=2.4.0
pip install requests>=2.31.0
pip install beautifulsoup4>=4.12.0
pip install python-whois>=0.8.0
pip install shodan>=1.31.0
pip install colorama>=0.4.6
```
---

## Tasks
 
### 0. Get IP Address (IPv4 DNS Resolution)
 
**File:** `0-dns_resolver.py`

Resolves a domain name to its IPv4 address using the `socket` library.

**Returns:**
- The IPv4 address (string) if resolved successfully
- `None` if the domain cannot be resolved (`socket.gaierror`)
- An error message string for any other exception
**Usage:**
```bash
./0-main.py
```
 
**Example output:**
```
DNS Resolver Test
============================================================
holbertonschool.com                      -> 75.2.70.75
google.com                               -> 142.250.180.174
github.com                               -> 140.82.121.3
example.com                              -> 23.220.75.245
this-is-not-a-site.com                   -> Failed to resolve
============================================================
```
 
> **Note:** You might see different IPs depending on CDN and geographic location.
 
---
