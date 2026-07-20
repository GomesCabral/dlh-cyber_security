# 23. Validation Plan

## Objective

The objective of this validation plan is to ensure that vulnerability remediation is correctly implemented, remains effective over time and is continuously monitored. Every remediation must be verified before a finding is considered closed.

---

# 1. Post-Patch Verification

## Finding 031 – Ghostcat (Tomcat AJP)

### Verification Steps

- Perform a targeted OpenVAS rescan of `ehr-srv-01`.
- Verify that TCP port 8009 (AJP) is disabled or restricted.
- Confirm the Apache Tomcat version matches the patched release.
- Attempt safe version detection to verify the vulnerability is no longer present.
- Review application logs for startup errors after the upgrade.

**Success Criteria**

- OpenVAS no longer reports CVE-2020-1938.
- AJP is disabled or restricted.
- The EHR application operates normally.

---

## Findings 001 & 002 – Apache Remote Code Execution

### Verification Steps

- Perform an authenticated vulnerability rescan.
- Verify the installed Apache version.
- Confirm the vulnerable `mod_lua` version has been removed.
- Review Apache service logs.
- Verify the billing application functions correctly.

**Success Criteria**

- Findings 001 and 002 no longer appear.
- Apache starts successfully.
- Billing services remain operational.

---

## Finding 004 – Windows XP MRI Workstation

### Verification Steps

Since Windows XP cannot be fully patched, validate compensating controls instead.

Verify:

- firewall rules;
- VLAN isolation;
- RDP restrictions;
- endpoint monitoring;
- access logging.

Attempt an authorized connection from a normal workstation to confirm the MRI workstation is no longer reachable.

**Success Criteria**

- Only approved systems can communicate with the MRI workstation.
- Unauthorized connections are blocked.
- Monitoring alerts function correctly.

---

# 2. Compensating Control Validation

## MRI Workstation

Validate:

- VLAN membership
- Firewall ACLs
- Approved administration paths
- Logging and alert generation
- Backup procedures
- Clinical downtime procedures

Residual risk should be reviewed every quarter.

---

## Medical IoT Devices

Validate:

- Default passwords have been replaced.
- Management interfaces are restricted.
- HL7 traffic only reaches approved servers.
- DICOM communication follows approved paths.
- Medical devices cannot be accessed from user workstations.
- Firmware versions match vendor documentation.

Periodic validation should be performed with Clinical Engineering.

---

# 3. Rescan Schedule

| Frequency | Activity |
|-----------|----------|
| Weekly | Targeted rescans of Critical findings until closed |
| Monthly | Authenticated vulnerability scan of all internal systems |
| Quarterly | Full enterprise vulnerability assessment |
| After every Critical Patch | Immediate verification scan |
| After major infrastructure changes | Full validation scan |

## Justification

Weekly scans ensure that critical vulnerabilities are verified quickly, while monthly authenticated scans provide regular visibility into the environment. Quarterly enterprise assessments confirm overall security posture, and additional scans after major changes ensure that new vulnerabilities are not introduced during maintenance.

---

# 4. Continuous Intelligence

MedDefense should integrate external threat intelligence into its vulnerability management program.

### CISA KEV

- Monitor new KEV entries weekly.
- Compare KEV updates against the asset inventory.
- Escalate any matching vulnerabilities immediately.

### Vendor Advisories

Monitor:

- Microsoft
- Ubuntu
- Apache
- PostgreSQL
- Grafana
- Synology
- BD
- Philips

Review vendor advisories every week.

### NVD

Review newly published CVEs affecting MedDefense technologies.

### Threat Intelligence Feeds

Monitor:

- CISA Alerts
- MS-ISAC
- CERT advisories
- Healthcare ISAC (H-ISAC)

Security Operations should review intelligence continuously and update remediation priorities when new exploitation evidence becomes available.

---

# 5. Continuous Vulnerability Management Lifecycle

```
Threat Intelligence
        │
        ▼
Scan
(OpenVAS / Lynis / OSINT)
        │
        ▼
Triage
(Security Analyst)
        │
        ▼
Prioritize
(Security Analyst + Management)
        │
        ▼
Remediate
(IT Operations / Network Team / Clinical Engineering / Vendor)
        │
        ▼
Validate
(Security Analyst)
        │
        ▼
Continuous Monitoring
(Security Operations)
        │
        ▼
Repeat
```

## Roles and Responsibilities

| Lifecycle Step | Primary Owner |
|----------------|---------------|
| Scan | Security Analyst |
| Triage | Security Analyst |
| Prioritize | Security Manager + IT Management |
| Remediate | IT Operations, Network Team, Clinical Engineering, Vendors |
| Validate | Security Analyst |
| Continuous Monitoring | Security Operations Center (SOC) |

---

# Conclusion

Vulnerability management is a continuous process rather than a one-time activity. Every remediation must be verified using technical validation, targeted rescanning and operational monitoring before a finding is closed. Continuous intelligence from CISA KEV, vendor advisories and threat feeds ensures that MedDefense can rapidly identify newly exploited vulnerabilities and adjust remediation priorities as the threat landscape evolves.
