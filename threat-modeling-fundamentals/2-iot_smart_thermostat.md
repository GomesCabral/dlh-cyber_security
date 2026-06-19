# IoT Smart Thermostat Threat Model

## System Overview

The system is a smart thermostat device that connects to home Wi-Fi, controls heating and cooling systems, collects temperature information, receives commands from a mobile application, and supports Over-The-Air (OTA) firmware updates.


##  Architecture

```
Mobile Application
    |
    v
Cloud/API Server
    |
    v
Home Wi-Fi Network
    |
    v
Smart Thermostat Device
    |
    v
Heating/Cooling System

OTA Update Server
    |
    v
Smart Thermostat Firmware
```

### IoT-Specific Threats

Unlike traditional web applications, IoT devices introduce additional risks because attackers may physically access hardware and firmware.

### Threat 1: Physical Device Tampering

### Description

An attacker physically opens the thermostat and modifies hardware components.

### Attack Scenario

The attacker removes the device casing and connects directly to internal interfaces.

Examples:

-   UART
-   JTAG debug ports
-   Flash memory chips

### Impact

-   Extraction of secrets or encryption keys
-   Firmware modification
-   Device takeover

### Mitigation

-   Disable debug ports in production
-   Use secure hardware modules
-   Protect sensitive storage
-   Enable tamper detection
---
### Threat 2: Weak Default Credentials

### Description

IoT devices are often shipped with default usernames and passwords.

### Attack Scenario

Example:

```
Username: admin
Password: admin
```

An attacker scans devices and logs in using known credentials.

### Impact

-   Unauthorized device control
-   Network compromise
-   Privacy loss

### Mitigation

-   Force password change during setup
-   Use unique device credentials
-   Support MFA for accounts
---
### Threat 3: Insecure Firmware

### Description

The device runs outdated or vulnerable firmware.

### Attack Scenario

An attacker exploits a known firmware vulnerability to execute malicious code.

### Impact

-   Complete device compromise
-   Malware installation
-   Botnet participation

### Mitigation

-   Regular security updates
-   Signed firmware
-   Vulnerability monitoring
---
### Threat 4: Unencrypted Communication

### Description

Data between the thermostat, cloud, and mobile app is sent without protection.

### Attack Scenario

An attacker connected to the same Wi-Fi intercepts traffic.

Example:

```
Thermostat ---- attacker ---- Cloud Server
```

### Impact

-   Data theft
-   Command manipulation
-   Privacy exposure

### Mitigation

-   TLS encryption
-   Certificate validation
-   Mutual authentication
---
### Threat 5: Malicious OTA Updates

### Description

An attacker installs fake firmware updates.

### Attack Scenario

The thermostat downloads a malicious firmware image believing it is legitimate.

### Impact

-   Permanent compromise
-   Device malfunction
-   Attacker gains control

### Mitigation

-   Code signing
-   Secure boot
-   Firmware verification
---
### Physical Access Attack Chain

**Scenario**

>An attacker obtains physical access to the thermostat.
---
### Step 1: Device Opening

The attacker removes the physical case.

Target:

-   circuit board
-   storage chip
-   debug interfaces

Impact:

Initial hardware access.

---
### Step 2: Debug Port Access

The attacker connects to:

-   UART
-   JTAG

Possible result:

Access to system shell or debugging features.

Impact:

Unauthorized control.

---
### Step 3: Firmware Extraction

The attacker copies firmware from device memory.

They analyze it looking for:

-   passwords
-   API keys
-   encryption keys
-   vulnerabilities

Impact:

Sensitive information disclosure.

---
## Step 4: Firmware Modification

The attacker changes the firmware.

Examples:

-   add backdoor
-   disable security checks
-   spy on users

Impact: 

Full device compromise.

---
### Step 5: Network Attack

The compromised thermostat is used to attack other devices.

Examples:

-   computers
-   phones
-   smart home devices

Impact:

Home network compromise.

---
Potential Impacts
| Impact Area| Consequence
|------------|-------------
|Confidentiality|Temperature patterns reveal when users are home or away.
|Integrity| Attacker changes thermostat settings or firmware.
|Availability| Device stops working or heating/cooling becomes unavailable.
|Privacy | User behavior information is exposed.
|Network Security | Device becomes an entry point into the home network.
---
 
### OTA Update Security Controls

OTA updates are critical because they allow remote modification of the device firmware.

**Requirement 1: Firmware Code Signing**

**Purpose**

Guarantee that updates come from the official manufacturer.

**How it works**

The manufacturer signs firmware using a private key.

The thermostat verifies using a public key before installing.

Prevents:

-   fake firmware installation
-   malware updates
---
### Requirement 2: Secure Boot

**Purpose**

Ensure the device only runs trusted firmware.

**Process**:

1.  Device powers on
2.  Bootloader checks firmware signature
3.  Valid firmware runs
4.  Invalid firmware is blocked

**Prevents**:

-   persistent malware
-   modified firmware
---
### Requirement 3: Encrypted Update Channel

**Purpose**

Protect firmware during download.

**Implementation**:

-   HTTPS/TLS
-   certificate validation

**Prevents**:

-   Man-in-the-Middle attacks
-   firmware interception
---
### Requirement 4: Rollback Protection

**Purpose**

Stop attackers from installing old vulnerable firmware.

**Attack example:**

```
Version 5.0 (secure)

attacker installs

Version 1.0 (vulnerable)
```

**Protection**:

-   Track firmware versions
-   Block downgrade attempts
---
### Requirement 5: Update Integrity Verification

**Purpose**

Confirm firmware was not modified.

**Controls**:

-   cryptographic hashes
-   digital signatures

**Prevents**:

-   corrupted updates
-   tampered firmware
---

### OTA Security Priority Order
|Priority| Control | Reason
|--------|---------|--------|
| 1 | Code signing| Ensures only trusted firmware installs
| 2 | Secure boot | Stops modified firmware from running
| 3 | TLS encryption | Protects updates during transfer
| 4 | Rollback protection | Blocks old vulnerable versions
| 5 | Integrity verification | Detects modified update files
---

### Conclusion
IoT security requires protecting both software and physical hardware.

The biggest risks are:

-   physical attacks
-   firmware compromise
-   weak credentials
-   insecure communication
-   malicious updates

A secure thermostat must protect confidentiality, integrity, and availability across the device, network, cloud, and mobile application.
