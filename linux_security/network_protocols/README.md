# Cybersecurity Scripts — iptables

## Tasks

---

### 0 - Analize iptables Rules

**File:** `0-iptbles.sh`

Displays **all current firewall rules** in a redables format, with line numbers for easy reference.

---
### 1 - Basic Firewall Rules

**file:** `1-firewall.sh`

Sets up basic iptables rules that block all incoming traffic except SSH.

---
### 2 - Harden Linux Server

**file:** 2-harden.sh

Finds all world-writable directories and removes write permission for others, hardening the system against unauthorised file modification.

---
### 3 -  Identify Common Vulnerabilities

**file:** 3-identify.sh

Runs a full system security audit using lynis to identify unpatched vulnerabilities, misconfigurations, and security risks

---
### 4 - Audit SSH Configuration

**file:** 4-audit.sh

Reports all **active (non-standard) SSH configuration settings** from `/etc/ssh/sshd_config` by stripping out comments and blank lines.

---
### 5 - SSH Configuration Hardening

**file:** 5-sshd_config

Replaces the insecure default settings with safe values.

Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
X11Forwarding no
Port 22

---
### 6 - Check for NFS Vulnerabilities

**file:** 6-nfs.sh

Scans a target host for **NFS shares accessible by anyone** on the network using `showmount`.

---
### 7 - Audit SNMP Configuration

**file:** `7-snmp.sh`

Finds all **SNMP configurations allowing public access** by searching for the default `public` community string in `/etc/snmp/`.
