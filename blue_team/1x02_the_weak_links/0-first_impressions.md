# First Impressions Summary — MedDefense Vulnerability Scan

## 1. Scan Metadata

| Item | Detail |
|---|---|
| Organization | MedDefense Health Systems |
| Scanner | OpenVAS 22.x — Greenbone Community Edition |
| Scan date | `[Current - 5 days]` — the report contains a relative placeholder rather than an exact date |
| Target | `10.10.0.0/16`, described as all internal subnets |
| Responsive hosts scanned | 47 |
| Scan policy | Full and Deep, authenticated where credentials were available |
| Requested by | James Chen, Deputy CISO |
| Executed by | SecurePoint Consulting, a third party |
| Scan window | 02:00–06:00, during off-peak hours |
| Authentication coverage | Linux servers through SSH and Windows systems through domain credentials where available |
| Medical-device coverage | Medical devices were scanned without authentication because credentials were not provided |
| Validation method | Version detection, configuration analysis and authenticated checks; no active exploitation was attempted |

### What was not scanned or not fully covered

- Microsoft 365/O365 cloud services.
- Mobile devices, including iPads.
- Assets that were offline or did not respond during the scan window.
- Authenticated configuration checks on medical devices.
- Exploitability proven through active exploitation, because exploitation was explicitly excluded.
- Every possible false positive: SecurePoint estimates a 5–10% false-positive rate and recommends manual validation of high-value findings.

The target range is much larger than the 47 responsive hosts. Therefore, the report describes only the systems reachable during the scan window, not necessarily the complete MedDefense environment.

## 2. Finding Distribution

| Severity | Count | Percentage of 31 findings |
|---|---:|---:|
| Critical | 4 | 12.9% |
| High | 7 | 22.6% |
| Medium | 11 | 35.5% |
| Low | 5 | 16.1% |
| Informational | 4 | 12.9% |
| **Total** | **31** | **100%** |

**Medium is the most common severity level**, with 11 of the 31 findings.

Critical and High findings together represent 11 of 31 findings, or approximately 35.5%. This is important, but the number alone does not establish business risk because the affected asset, exposure conditions and possible attack chains must also be considered.

## 3. Asset Heat Map

The counts below measure how many finding records explicitly name each host. A finding affecting a range of devices counts once for each named device in that range, because it represents one shared issue rather than several separate findings per device.

| Rank | Host | Finding count | Role |
|---:|---|---:|---|
| 1 | `10.10.2.15` — `billing-srv-01` | 6 | Billing application server; also hosts MySQL and financial/billing records |
| 2 | `10.10.2.10` — `ehr-srv-01` | 4 | Electronic Health Record application server |
| 2 | `10.10.2.50` — `web-srv-01` | 4 | Patient portal web server |
| 4 | `10.10.2.20` — `ad-dc-01` | 3 | Primary Active Directory domain controller and DNS server |
| 5 | `10.10.1.70` — `WS-RAD-01` | 1 | MRI scanner control workstation |

**Tie note:** There is no unique fifth-place host. Many systems appear in exactly one finding, including `ad-dc-02`, `print-srv-01`, `pacs-srv-01`, `backup-srv-01`, `NAS-01`, the two unknown Linux devices and each device included in the multi-host findings. `WS-RAD-01` is shown as a representative tied host because it is a clinically significant asset.

**Asset Registry cross-reference note:** The separate Asset Registry from `1x00 T7` was not included with this task. The roles above are taken only from the scan report. They should be checked against the registry before the final organizational assessment; inventing missing registry data would create an unsupported conclusion.

## 4. First Observations

### Critical findings are partly concentrated

The four Critical findings affect three systems:

- Two Critical findings are on `billing-srv-01`.
- One is on `ehr-db-01`, the patient database.
- One is on `WS-RAD-01`, the MRI workstation.

Therefore, half of the Critical findings are concentrated on the billing server, while the other half are spread across two clinically important systems.

### Several findings form related groups

1. **Billing server attack chain:** Findings 001 and 002 are explicitly linked. A remote attacker may first obtain code execution through the Apache issue and then escalate from the web-service account to root. Findings 011 and 026 indicate that the operating system and kernel are also outdated, while Findings 006 and 009 add unrestricted database exposure and password-based SSH authentication. The six findings on this host are more significant together than when viewed separately.

2. **EHR application and database exposure:** Finding 017 reveals the Tomcat version and recommends checking AJP. Finding 031 confirms that AJP is active and vulnerable. The report states that exploitation may expose database credentials. Finding 003 shows that the EHR database accepts connections from the entire internal network. These observations suggest a possible path from a compromised internal host to the application server and then toward patient data.

3. **Patient portal hardening weaknesses:** Findings 005, 012, 013 and 021 all affect `web-srv-01`. They concern outdated TLS support, missing HTTP security headers, an expiring certificate and the TRACE method. They are separate issues, but together show weak maintenance and web-security hardening on a public-facing business function.

4. **Medical-device exposure and network architecture:** The MRI workstation, infusion pumps and patient monitors have outdated software, default credentials or exposed management interfaces. Multiple findings mention a flat network or missing VLAN isolation. This means a compromise of one ordinary workstation may create a route to clinical devices.

5. **Identity infrastructure weaknesses:** The primary domain controller does not require LDAP signing, still has SMBv1 enabled, supports weak Kerberos encryption and allows unrestricted DNS zone transfers. These findings could assist relay attacks, credential attacks and internal reconnaissance.

### Important observations that should not be missed

- Severity labels do not always equal practical risk. Finding 020 has a CVSS score of 9.8 but is rated Medium because the required conditions may not exist and the scanner warns that it could be a false positive.
- Informational findings may still require urgent investigation. Findings 028 and 029 identify undocumented Linux devices. One exposes a Jupyter Notebook interface; the other runs an old Grafana version associated in the report with a publicly available path-traversal exploit. Their “Informational” label reflects discovery status, not proof that they are harmless.
- The same architectural weakness appears repeatedly: broad internal reachability and limited network segmentation. This increases the value of stolen credentials or a single compromised endpoint because it may permit lateral movement.
- The report contains evidence of asset-management gaps: undocumented devices, inactive endpoint-protection agents and systems outside normal support.
- The scan includes 31 findings, but some findings represent many affected assets. For example, the USB finding applies to approximately 280 workstations, the Philips issue to 13 monitors and the BD Alaris issue to seven pumps. Finding count is therefore not the same as affected-device count.

## 5. Scan Limitations

This scan does **not** establish that every listed vulnerability is exploitable in the MedDefense environment. It also does not establish that systems with no finding are secure.

Specific limitations are:

- Only 47 responsive hosts were scanned; offline or unreachable assets are absent.
- Cloud services and mobile devices are outside scope.
- Medical devices were scanned without credentials, limiting visibility into internal configuration, installed patches and security settings.
- No active exploitation was performed, so the report does not prove successful compromise or show the complete impact of an attack.
- Version-based detection can produce false positives when vendors backport patches without changing the visible version string.
- OpenVAS findings require manual validation, especially where the report itself identifies uncertain conditions.
- The report is mainly a network and host vulnerability assessment. It does not provide a complete application-security test of business logic, authorization flaws, session handling or custom application code.
- It does not evaluate user behavior, phishing susceptibility, insider activity or security-awareness effectiveness.
- It does not fully assess physical security, vendor governance, disaster-recovery performance, backup restoration success or incident-response readiness.
- It does not show whether existing monitoring controls detected the scan or would detect exploitation.
- It provides a point-in-time view from a four-hour window; configurations and asset availability may change afterward.
- It does not provide enough evidence to attribute any issue to a particular threat actor.

## 6. Reading Method Used

1. Read the title, scope, scanner, date, policy, requester and executor before reading findings.
2. Read the summary totals and verify that the severity counts add up to the stated total: `4 + 7 + 11 + 5 + 4 = 31`.
3. Read every finding once without researching any CVE.
4. Record the host named in each finding and count repeated hosts.
5. Mark findings that explicitly reference one another or describe the same asset, service or architectural weakness.
6. Read the methodology notes last and use them to limit every conclusion.
7. Separate scanner facts from analyst inference. For example, “AJP is active” is a verified report fact; “an attacker will successfully reach the database” is only a possible attack path that still requires validation.

## Conclusion

The first-pass picture is not simply “four Critical findings.” The scan shows a repeated concentration of weaknesses on the billing server, important exposure around the EHR environment, aging or weakly isolated medical technology, identity-control weaknesses and signs of incomplete asset management. The most important contextual pattern is the flat internal network, because it can connect otherwise separate findings into realistic lateral-movement paths. Before remediation decisions are made, the highest-value findings and all undocumented systems should be manually validated and cross-referenced with the Asset Registry.
