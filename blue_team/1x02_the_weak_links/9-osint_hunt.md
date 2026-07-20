# 9. The OSINT Hunt

## Purpose

This report supplements the automated vulnerability scan with manual open-source intelligence research. The scan explicitly excluded Microsoft 365/O365 cloud services and may not have assessed the FortiGate appliance firmware or authenticated Synology DSM configuration in sufficient depth.

The findings below should be treated as **potential MedDefense exposures until the exact product versions and configurations are verified**.

---

# Finding 1 — FortiGate FortiOS Authentication Bypass

## Source

- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-59718
- Fortinet PSIRT advisory: https://www.fortiguard.com/psirt/FG-IR-25-647
- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-59718

## CVE

**CVE-2025-59718**

## Affected Product

**MedDefense FortiGate 100F**, if it runs an affected FortiOS version and uses FortiCloud SSO for administrative login.

Affected FortiOS branches include:

- FortiOS 7.0.0 through 7.0.17
- FortiOS 7.2.0 through 7.2.11
- FortiOS 7.4.0 through 7.4.8
- FortiOS 7.6.0 through 7.6.3

The hardware model alone is not enough to confirm vulnerability. MedDefense must verify the exact FortiOS firmware version and whether FortiCloud SSO is enabled.

## Vulnerability Description

FortiOS incorrectly verifies the cryptographic signature of a crafted SAML authentication response. An unauthenticated attacker may use this weakness to bypass FortiCloud SSO authentication and access the administrative interface.

Fortinet classifies the issue as Critical and states that it has been exploited in the wild.

## Why the Scan Missed It

The scan targeted internal hosts and focused on services reachable during the scan window. It may have missed this issue because:

- the firewall's own firmware was not included in authenticated checks;
- the administrative interface may not have been reachable from the scanner;
- the OpenVAS plugin database may not yet have included the CVE;
- the weakness depends on FortiCloud SSO configuration, which may require authenticated or manual review;
- the CVE was disclosed after the original scan report was produced.

## CVSS / Severity

- **CVSS v3.1: 9.1**
- **Severity: Critical**
- Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- CISA KEV Date Added: 2025-12-16
- Federal remediation due date: 2025-12-23

## MedDefense Impact

The FortiGate is a perimeter security device. Successful exploitation could provide administrative control over:

- firewall rules;
- VPN access;
- network routes;
- security logging;
- traffic inspection;
- segmentation between clinical, workstation and server networks.

An attacker with firewall administration could create hidden access paths, weaken segmentation, intercept traffic or establish persistence. Because the scan already identified a flat internal network, compromise of the firewall would further increase the risk of lateral movement toward the EHR, billing systems and medical devices.

## Recommendation

1. Immediately identify the exact FortiOS version running on the FortiGate 100F.
2. Upgrade to a fixed FortiOS release listed in the Fortinet advisory.
3. Disable FortiCloud SSO administrative login if it is not required.
4. Restrict the management interface to dedicated administrative IP addresses.
5. Require MFA for all firewall administrators.
6. Review administrator accounts, configuration changes and login logs for suspicious activity.
7. Confirm that the management interface is not exposed directly to the internet.

---

# Finding 2 — Microsoft 365 / Entra ID Consent Phishing and AiTM

## Source

- Microsoft Learn — Consent phishing protection:
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/protect-against-consent-phishing
- Microsoft Security Blog — Evolving identity attack techniques:
  https://www.microsoft.com/en-us/security/blog/2025/05/29/defending-against-evolving-identity-attack-techniques/

## CVE

**Not applicable.**

Consent phishing and adversary-in-the-middle phishing are attack techniques rather than vulnerabilities in a specific software version.

## Affected Product

**MedDefense Microsoft Office 365 E3 / Microsoft Entra ID environment**, used across the organization.

## Vulnerability / Attack Description

### Consent phishing

An attacker creates a malicious OAuth application and tricks a user into approving permissions. The application may then access legitimate Microsoft 365 services and data without directly stealing the user's password.

Depending on the permissions granted, the attacker may access:

- email;
- contacts;
- files;
- SharePoint data;
- Teams information;
- user profile data.

### Adversary-in-the-middle phishing

AiTM phishing places attacker-controlled infrastructure between the user and the legitimate Microsoft sign-in page. The attacker captures credentials and session tokens during authentication.

Because the attacker steals an authenticated session token, traditional MFA may not be enough to prevent account takeover.

## Why the Scan Missed It

The scan methodology explicitly states that Microsoft 365/O365 cloud services were outside its scope.

A network vulnerability scanner would also miss these techniques because they depend on:

- identity configuration;
- OAuth application consent;
- Conditional Access policies;
- user behavior;
- session token theft;
- cloud audit logs;
- mailbox rules and application permissions.

These are logical and identity-security weaknesses, not open ports or vulnerable internal software versions.

## CVSS / Severity

- **CVSS: Not applicable**
- **MedDefense severity assessment: High**

There is no CVSS score because this is an attack technique rather than a product CVE. The practical risk is High because O365 is used organization-wide and may contain clinical, financial and operational information.

## MedDefense Impact

A successful attack could allow an attacker to:

- read employee email;
- access patient or billing-related documents;
- impersonate staff;
- create malicious mailbox forwarding rules;
- conduct Business Email Compromise;
- steal files from SharePoint or OneDrive;
- send phishing messages from trusted MedDefense accounts;
- maintain access through a malicious OAuth application;
- target privileged administrators.

Compromise of an Entra ID administrator could affect the entire cloud tenant and enable further access to hybrid systems.

## Recommendation

1. Restrict user consent for third-party applications.
2. Require administrator approval for high-risk OAuth permissions.
3. Configure the Entra admin consent workflow.
4. Review existing enterprise applications and remove unknown or unused applications.
5. Audit OAuth grants and application permissions regularly.
6. Use phishing-resistant MFA, such as FIDO2 security keys, passkeys or certificate-based authentication.
7. Apply Conditional Access policies for administrators and sensitive applications.
8. Disable legacy authentication.
9. Monitor for impossible travel, unusual consent events, new mailbox forwarding rules and anomalous sign-ins.
10. Train employees to inspect application permission requests rather than approving them automatically.

---

# Finding 3 — Synology DSM Missing Authorization

## Source

- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-1021
- Synology advisory:
  https://www.synology.com/en-global/security/advisory/Synology_SA_25_03

## CVE

**CVE-2025-1021**

## Affected Product

**MedDefense NAS-01**, which stores server backups and runs Synology DSM 7.

Affected versions include:

- DSM before 7.1.1-42962-8
- DSM 7.2.1 before 7.2.1-69057-7
- DSM 7.2.2 before 7.2.2-72806-3

The scan report identifies the product family but does not provide the exact DSM build number. Therefore, MedDefense must verify whether NAS-01 is running an affected version.

## Vulnerability Description

The `synocopy` component does not correctly enforce authorization. A remote unauthenticated attacker may be able to read arbitrary files from the NAS.

The vulnerability primarily affects confidentiality because it may expose files that the attacker should not be allowed to access.

## Why the Scan Missed It

The original scan detected that the DSM management interface was broadly accessible and that backups were unencrypted, but it did not report this CVE.

Possible reasons include:

- the exact DSM build was not identified;
- the scan may not have performed an authenticated DSM version check;
- the relevant OpenVAS plugin may not have been available;
- the CVE may have been published after the scanner plugin database was updated;
- the scanner focused on exposed ports and configuration rather than the vulnerable `synocopy` component.

## CVSS / Severity

- **CVSS v3.1: 7.5**
- **Severity: High**
- Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

## MedDefense Impact

NAS-01 stores all backup data for MedDefense servers, and the scan states that the backups are unencrypted.

If the NAS is vulnerable, an attacker may be able to read:

- server backups;
- application configuration files;
- database backups;
- credential files;
- patient-related information;
- billing records;
- system images.

Exposure of backup data could create a large-scale confidentiality breach. Backup files may also contain credentials that help an attacker compromise production systems.

This CVE is especially serious in combination with the existing scan findings:

- DSM management is accessible from the entire internal network;
- backup data is unencrypted;
- the network is relatively flat.

## Recommendation

1. Identify the exact DSM version and build on NAS-01.
2. Upgrade immediately to a fixed DSM release.
3. Restrict DSM management ports 5000 and 5001 to administrative IP addresses.
4. Use HTTPS only and disable unencrypted management access.
5. Encrypt backup data at rest.
6. Separate backup administration accounts from normal domain accounts.
7. Require MFA for DSM administrators.
8. Review DSM access logs and file-access logs.
9. Isolate the NAS in a dedicated backup network or VLAN.
10. Maintain offline or immutable backup copies that cannot be altered through the NAS management interface.

---

# Summary Table

| Technology | Vulnerability / Technique | CVE | Severity | Why the automated scan missed it |
|---|---|---|---|---|
| FortiGate 100F / FortiOS | FortiCloud SSO SAML authentication bypass | CVE-2025-59718 | Critical, CVSS 9.1 | Firewall firmware/configuration not fully assessed; CVE disclosed after the scan |
| Microsoft 365 / Entra ID | Consent phishing and AiTM session theft | N/A | High | O365 was explicitly out of scope and the weakness is identity/context based |
| Synology DSM 7 | Missing authorization allows arbitrary file read | CVE-2025-1021 | High, CVSS 7.5 | Exact DSM build/component not fingerprinted or plugin not available |

---

# Overall Assessment

The OSINT research shows that the automated scan does not represent MedDefense's complete vulnerability exposure. The firewall, cloud identity environment and backup platform all contain risks that were either out of scope or not detected.

The most urgent validation actions are:

1. Check and patch the FortiGate 100F firmware.
2. Review Entra ID OAuth consent and deploy phishing-resistant MFA.
3. Verify and patch the Synology DSM build.
4. Restrict management access to both the FortiGate and NAS.
5. Add cloud, firewall-firmware and backup-platform reviews to future vulnerability assessments.

The key lesson is that a vulnerability scanner reports only what it can reach, identify and test. Manual OSINT research is required to identify newly disclosed CVEs, cloud identity attacks and vulnerabilities in devices that were not fully authenticated during the scan.
