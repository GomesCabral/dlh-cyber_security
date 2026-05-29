# 0x04 - Nmap Live Hosts Discovery
 
## Description
 
This project contains Bash scripts for scanning subnetworks and discovering live hosts using different techniques with `nmap`. Each script focuses on a specific host discovery method.

## Tasks
 
### 0. Will arp be enough?
 
**File:** `0-arp_scan.sh`
 
Scans a subnetwork to discover live hosts using an **ARP scan**.
 
- Uses `nmap` with the `-sn` flag (no port scan) and `-PR` flag (ARP discovery)
- Must be run as a privileged user
- Accepts a subnetwork as argument `$1`
**Usage:**
```bash
sudo ./0-arp_scan.sh <subnetwork>
```
 
**Example:**
```bash
sudo ./0-arp_scan.sh 192.168.1.0/24
```
### 1. ICMP Echo scan
 
**File:** `1-icmp_echo_scan.sh`
 
Scans a subnetwork to discover live hosts using an **ICMP Echo scan** (ping-based).
 
- Uses `nmap` with the `-sn` flag (no port scan) and `-PE` flag (ICMP Echo discovery)
- Must be run as a privileged user
- Accepts a subnetwork as argument `$1`
**Usage:**
```bash
sudo ./1-icmp_echo_scan.sh <subnetwork>
```
 
**Example:**
```bash
sudo ./1-icmp_echo_scan.sh 6.19.100.0/24
```
