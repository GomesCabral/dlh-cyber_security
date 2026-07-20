# 11. The False Positives

## Scope and Important Distinction

A scanner result should not be labelled a false positive only because it has low business impact. Three different situations appear in the MedDefense report:

1. **Potential technical false positive:** the scanner may have matched a vulnerable version, but the required exploitation conditions may not exist.
2. **Benign or operational finding:** the observed condition is real, but it is not a security vulnerability.
3. **Transient or measurement noise:** the observation may have been temporary or caused by the scanner's own reference point.

The report provides one explicit false-positive candidate and two additional findings that require validation before remediation.

---

# Candidate 1 — Finding 020

## Finding ID

**020**

## Reported Vulnerability

OpenSSH 8.9p1 on `10.10.2.40` (`backup-srv-01`) was reported as affected by **CVE-2023-38408**, an OpenSSH PKCS#11 `ssh-agent` forwarding remote-code-execution vulnerability.

## Why It May Be a False Positive

The package version may be associated with the CVE, but version detection alone does not prove that the vulnerable execution path exists in MedDefense.

Exploitation requires several specific conditions:

- `ssh-agent` must be running;
- agent forwarding must be enabled;
- the agent must be forwarded to an attacker-controlled host;
- PKCS#11 support must be available;
- suitable libraries must exist on the client system;
- the attacker must be able to trigger a usable library-loading chain.

A backup server that does not use agent forwarding may have the vulnerable package version but may not be practically exploitable through this CVE.

SecurePoint explicitly noted that this finding **may be a false positive in this environment** and recommended manual verification.

## Validation Method

Check the SSH server configuration:

```bash
grep -Rni "AllowAgentForwarding" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
```

Check client-side SSH configurations:

```bash
grep -Rni "ForwardAgent" /etc/ssh/ssh_config /etc/ssh/ssh_config.d/ ~/.ssh/config
```

Check whether an SSH agent is active:

```bash
echo "$SSH_AUTH_SOCK"
ps aux | grep ssh-agent
```

Also confirm the exact OpenSSH package build and whether Ubuntu has backported the patch.

## Risk of Acting on This False Positive

MedDefense could schedule unnecessary emergency downtime, interrupt backup jobs, consume engineering time, create compatibility problems, and distract staff from confirmed critical findings.

## Risk of Not Validating

If agent forwarding is actually enabled, an attacker-controlled SSH host could potentially execute code through the forwarded agent. Because `backup-srv-01` is a high-value recovery asset, compromise could expose backup credentials and recovery processes.

**Conclusion:** Finding 020 is the strongest technical false-positive candidate, but it must be validated rather than ignored.

---

# Candidate 2 — Finding 030

## Finding ID

**030**

## Reported Vulnerability

The TLS certificate on `10.10.2.10` (`ehr-srv-01`) is issued to `ehr.meddefense.local`, but some clients access the server using `10.10.2.10`, creating a hostname mismatch warning.

## Why It Is Not an Actual Vulnerability in This Context

The scanner's observation is technically correct, but the report explicitly states that this is an **operational issue, not a security vulnerability**.

The certificate may validate correctly when users access the EHR through its proper hostname. The warning appears because some clients use the IP address instead of the certificate name.

This is therefore better classified as a configuration or usage problem rather than an exploitable TLS vulnerability.

## Validation Method

Inspect the certificate identity:

```bash
openssl s_client -connect 10.10.2.10:443 -servername ehr.meddefense.local \
2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Test both access methods:

```bash
curl -v https://ehr.meddefense.local
curl -v https://10.10.2.10
```

Confirm that DNS resolves correctly and that clients are configured to use the hostname.

## Risk of Acting on This False Positive

MedDefense could replace a valid certificate unnecessarily, create application downtime, waste certificate-administration effort, or distract from the confirmed Ghostcat vulnerability on the same server.

## Risk of Not Validating

Users may continue ignoring certificate warnings. That behavior could allow a genuine man-in-the-middle attack to go unnoticed.

**Conclusion:** Finding 030 is not a classic false positive because the mismatch exists. It is a **benign operational finding that should not be treated as a vulnerable service**.

---

# Candidate 3 — Finding 022

## Finding ID

**022**

## Reported Vulnerability

The system clock on `10.10.2.10` (`ehr-srv-01`) was reported as 47 seconds ahead of the scanner's NTP reference.

## Why It May Be a False Positive or Transient Finding

A single measurement does not prove a persistent time-synchronization problem.

Possible explanations include:

- the scanner's NTP reference was inaccurate;
- temporary network delay;
- the host was correcting its time during the scan;
- the scanner and server used different time sources;
- the condition was temporary.

The finding may therefore be measurement noise or a short-lived operational issue.

## Validation Method

Check current synchronization:

```bash
timedatectl status
timedatectl timesync-status
```

If Chrony is used:

```bash
chronyc tracking
chronyc sources -v
```

If traditional NTP is used:

```bash
ntpq -p
```

Repeat the measurement and compare the EHR server with the domain controllers, scanner, and authoritative NTP source.

## Risk of Acting on This False Positive

Changing a correct NTP configuration or forcing a time adjustment could disrupt Kerberos, invalidate sessions, and confuse logs.

## Risk of Not Validating

A real persistent skew could cause authentication failures, certificate problems, inaccurate incident timelines, poor SIEM correlation, and unreliable forensic evidence.

**Conclusion:** Finding 022 is not proven false from the report alone. It is a reasonable **transient/noise candidate** that requires repeated measurement.

---

# Summary Table

| Finding | Scanner Claim | Classification After Review | Required Action |
|---:|---|---|---|
| 020 | OpenSSH CVE-2023-38408 | Strong potential technical false positive because prerequisites may be absent | Verify agent forwarding, package patch level, and runtime conditions |
| 030 | TLS hostname mismatch | Real observation, but operational/benign rather than exploitable | Correct hostname usage and validate certificate SAN |
| 022 | 47-second clock skew | Possible transient measurement or operational noise | Repeat checks against trusted NTP sources |

---

# Expected False-Positive Rate

SecurePoint states that the expected false-positive rate for this OpenVAS configuration is approximately **5–10%**.

For 31 findings:

```text
31 × 0.05 = 1.55
31 × 0.10 = 3.1
```

A reasonable expectation is therefore **about 2 to 3 false positives or non-actionable findings**.

This is an estimate, not proof that exactly two or three findings are false.

---

# Why Manual Validation Is Essential

Manual validation is essential because automated scanners often rely on version matching, banners, remote behavior, and incomplete configuration visibility. They may not know whether a vendor has backported a patch, whether an exploit prerequisite is enabled, whether a condition is temporary, or whether an informational observation creates real security impact. Acting on every result without validation can waste maintenance windows, engineering time, and budget, and may even cause outages. Dismissing findings without validation is equally dangerous because a true positive may remain exposed. The correct process is to confirm the product version, configuration, reachability, exploit prerequisites, asset role, and business impact before committing remediation resources or formally accepting the risk.

---

# Analyst Lesson

A good analyst does not ask only:

> “Did the scanner detect it?”

The analyst asks:

1. Is the observed condition real?
2. Is the vulnerable code path present?
3. Are the exploitation prerequisites satisfied?
4. Is the service reachable by a realistic attacker?
5. Is this a security vulnerability, an operational issue, or temporary noise?
6. What is the cost of remediation?
7. What is the cost of being wrong?
