# 19. Remediation Map

## Finding 004 – CVE-2019-0708 (BlueKeep)

**Response Type:** Compensating Control

**Control Description:**
- Isolate the MRI workstation in a dedicated medical-device VLAN.
- Restrict RDP access to authorized radiology administrators only.
- Block all unnecessary inbound connections.
- Monitor the workstation for suspicious activity.

**Residual Risk:**
The Windows XP operating system remains unsupported and vulnerable to future exploits.

**Timeline:** Immediate (24–48 hours)

**Owner:** Security + Network Team + Clinical Engineering

**Cost Estimate:** $1K–10K

---

## Finding 031 – CVE-2020-1938 (Ghostcat)

**Response Type:** Patch

**Patch Source:**
Apache Tomcat official security updates:
https://tomcat.apache.org/security-9.html

**Prerequisites:**
- Backup Tomcat configuration.
- Backup application files.
- Test update in staging.
- Schedule maintenance outside clinical hours.

**Rollback Plan:**
Restore previous Tomcat installation and configuration from backup.

**Operational Risk:**
The EHR application may become unavailable during the restart.

**Timeline:** Immediate (24–48 hours)

**Owner:** IT Operations

**Cost Estimate:** $0–1K

---

## Finding 001 – CVE-2021-44790 (Apache mod_lua)

**Response Type:** Patch

**Patch Source:**
Apache HTTP Server official security updates:
https://httpd.apache.org/security/

**Prerequisites:**
- Full server backup.
- Verify application compatibility.
- Maintenance window.
- Notify billing users.

**Rollback Plan:**
Restore Apache packages and configuration from backup.

**Operational Risk:**
Temporary interruption of billing services.

**Timeline:** Immediate (24–48 hours)

**Owner:** Linux Server Team

**Cost Estimate:** $0–1K

---

## Finding 002 – Apache Privilege Escalation

**Response Type:** Patch

**Patch Source:**
Apache official security updates.

**Prerequisites:**
Patch together with Finding 001 because both vulnerabilities form one attack chain.

**Rollback Plan:**
Restore previous Apache version.

**Operational Risk:**
Unexpected application incompatibilities.

**Timeline:** Immediate (24–48 hours)

**Owner:** Linux Server Team

**Cost Estimate:** $0–1K

---

## Finding 010 – BD Alaris Infusion Pumps

**Response Type:** Configuration Change

**Change Description:**
- Change all default administrator credentials.
- Verify firmware with BD.
- Move pumps into a dedicated medical-device VLAN.
- Restrict management access.

**Impact Assessment:**
Changes require coordination with Biomedical Engineering and nursing staff to avoid disrupting patient treatment.

**Timeline:** 7 days

**Owner:** Clinical Engineering + Vendor

**Cost Estimate:** $1K–10K

---

## Finding 029 – Grafana Server

**Response Type:** Patch

**Patch Source:**
Grafana official security advisory:
https://grafana.com/security/

**Prerequisites:**
- Backup Grafana configuration.
- Backup dashboards.
- Snapshot virtual machine if applicable.

**Rollback Plan:**
Restore previous Grafana version from backup.

**Operational Risk:**
Temporary loss of monitoring dashboards.

**Timeline:** 7 days

**Owner:** IT Operations

**Cost Estimate:** $0–1K

---

## Finding 008 – PrintNightmare

**Response Type:** Patch

**Patch Source:**
Microsoft Security Update Catalog

https://www.catalog.update.microsoft.com/

**Prerequisites:**
- System backup.
- Maintenance window.
- Test printer functionality.

**Rollback Plan:**
Uninstall update if required and restore snapshot.

**Operational Risk:**
Printing services may be unavailable during maintenance.

**Timeline:** 7 days

**Owner:** Windows Server Team

**Cost Estimate:** $0–1K

---

## Finding 005 – Weak TLS Configuration

**Response Type:** Configuration Change

**Change Description:**
- Disable TLS 1.0 and TLS 1.1.
- Enable only TLS 1.2 and TLS 1.3.
- Enable HSTS.
- Replace weak cipher suites.

**Impact Assessment:**
Very old browsers or unsupported medical devices may lose connectivity.

**Timeline:** 30 days

**Owner:** Web Infrastructure Team

**Cost Estimate:** $0–1K

---

# Remediation Summary

| Finding | Response | Timeline | Owner |
|---------|----------|----------|-------|
| 004 | Compensating Control | Immediate | Security + Clinical Engineering |
| 031 | Patch | Immediate | IT Operations |
| 001 | Patch | Immediate | Linux Team |
| 002 | Patch | Immediate | Linux Team |
| 010 | Configuration Change | 7 days | Clinical Engineering + Vendor |
| 029 | Patch | 7 days | IT Operations |
| 008 | Patch | 7 days | Windows Team |
| 005 | Configuration Change | 30 days | Web Infrastructure |

# Overall Recommendation

MedDefense should first remediate vulnerabilities that provide remote code execution or direct access to critical clinical systems, particularly the EHR server, billing server and MRI workstation. Medical devices require special handling because firmware updates must follow vendor guidance and cannot always be applied immediately. Configuration changes such as network segmentation, disabling weak protocols and replacing default credentials should be implemented alongside patching to reduce the overall attack surface. Every remediation should be tested in a maintenance window, backed by verified backups and a documented rollback plan to minimize operational disruption.
