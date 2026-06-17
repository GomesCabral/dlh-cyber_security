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
