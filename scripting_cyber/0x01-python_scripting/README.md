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

### 1. Get All DNS Records


**File:** `1-dns_records.py`
Queries and displays all DNS record types for a given domain using the `dnspython` library.

**Returns:**

- A dictionary with record types as keys and resolver answer objects as values
- Format: `{'A': answers_object, 'AAAA': answers_object, 'MX': answers_object, ...}`
- Only includes record types that were successfully queried
- Empty dictionary if the domain cannot be resolved

**Usage:**

```bash
./1-main.py google.com
```
 
**Example output:**

```
======================================================================
DNS Record Enumeration: google.com
======================================================================
 
A Records (1):
  • 216.58.204.142
 
AAAA Records (1):
  • 2a00:1450:4002:414::200e
 
MX Records (1):
  • 10 smtp.google.com.
 
NS Records (4):
  • ns1.google.com.
  • ns2.google.com.
  • ns3.google.com.
  • ns4.google.com.
 
TXT Records (12):
  • "v=spf1 include:_spf.google.com ~all"
  • "google-site-verification=..."
  • ...
 
SOA Records (1):
  • Primary: ns1.google.com., Admin: dns-admin.google.com., Serial: 843371293
 
======================================================================
Summary: Found 6 record types with 20 total records
======================================================================
```
 
> **Note:** DNS records may vary over time as infrastructure changes.

---

### 2. Download a Web Page

**File:** `2-download_page.py`

Downloads a web page and returns its formatted HTML content using the `requests` and `BeautifulSoup` libraries.

**Returns:**

- The formatted HTML content (string) if the page downloads successfully
- An error message string if the download fails (`requests.exceptions.RequestException`)

**Usage:**
```bash
./2-main.py http://example.com
```
 
**Example output:**

```
Page content from http://example.com:
==================================================
<!DOCTYPE html>
<html lang="en">
 <head>
  <title>
   Example Domain
  </title>
  <meta content="width=device-width, initial-scale=1" name="viewport"/>
  <style>
   body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}
  </style>
  <body>
   <div>
    <h1>
     Example Domain
    </h1>
    <p>
     This domain is for use in documentation examples without needing permission. Avoid use in operations.
     <p>
      <a href="https://iana.org/domains/example">
       Learn more
      </a>
     </p>
    </p>
   </div>
  </body>
 </head>
</html>

==================================================
Content length: 638 characters
```
---

### 3. Get HTTP Headers
 
**File:** `3-http_headers.py`
 
Retrieves and displays HTTP response headers from a website using the `requests` library.

**Returns:**

- A dictionary `{'status_code': int, 'headers': dict}` if the request succeeds
- `None` if the request fails (`requests.exceptions.RequestException`)
**Usage:**

```bash
./3-main.py https://www.google.com
```
 
**Example output:**

```
HTTP Headers for: https://www.google.com
==================================================
Status Code: 200
Headers:
 
  Date: Tue, 02 Dec 2025 14:30:55 GMT
  Expires: -1
  Cache-Control: private, max-age=0
  Content-Type: text/html; charset=ISO-8859-1
  Server: gws
  X-XSS-Protection: 0
  X-Frame-Options: SAMEORIGIN
  ...
```
---


