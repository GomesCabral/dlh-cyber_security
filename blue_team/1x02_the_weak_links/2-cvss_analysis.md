# CVSS Deconstruction — MedDefense

## NIST CVSS v3.1 Calculator

Calculator used:  
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

CVSS v3.1 calculates a Base Score from two main parts:

- **Exploitability:** how an attacker reaches and exploits the vulnerability.
- **Impact:** what happens to confidentiality, integrity and availability after successful exploitation.

Severity bands:

| Score | Severity |
|---:|---|
| 0.0 | None |
| 0.1–3.9 | Low |
| 4.0–6.9 | Medium |
| 7.0–8.9 | High |
| 9.0–10.0 | Critical |

---

# Exercise 1 — Deconstruction

## Original vector

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Calculated Base Score: 9.8 — Critical**

This vector describes a vulnerability that can be exploited remotely, is not complex to exploit, requires no privileges or user action, remains within the same security authority, and has a high impact on confidentiality, integrity and availability.

## Component-by-component analysis

### AV:N — Attack Vector: Network

**What the abbreviation means:**  
`AV` means **Attack Vector**.

**What the selected value means:**  
`N` means **Network**. The vulnerable component can be attacked remotely across a network. The attacker does not need local access to the server.

**Other possible values:**

| Value | Meaning | General score effect |
|---|---|---|
| `N` | Network | Highest exploitability weighting |
| `A` | Adjacent | Lower; attacker must be on an adjacent/shared network |
| `L` | Local | Lower; attacker needs local system access |
| `P` | Physical | Lowest; attacker needs physical interaction |

The more access the attacker needs, the lower the exploitability portion of the score.

**Why it was selected:**  
CVE-2021-44790 can be triggered using a specially crafted HTTP request sent to the Apache server. Because HTTP requests can reach the service over the network, `AV:N` is appropriate.

---

### AC:L — Attack Complexity: Low

**What the abbreviation means:**  
`AC` means **Attack Complexity**.

**What the selected value means:**  
`L` means **Low**. Exploitation does not depend on unusual conditions outside the attacker’s control.

**Other possible value:**

| Value | Meaning | General score effect |
|---|---|---|
| `L` | Low | Higher score |
| `H` | High | Lower score because special conditions are required |

**Why it was selected:**  
The attacker needs to send a crafted multipart request body. The scan report does not describe a race condition, special configuration sequence or another difficult prerequisite.

---

### PR:N — Privileges Required: None

**What the abbreviation means:**  
`PR` means **Privileges Required**.

**What the selected value means:**  
`N` means **None**. The attacker does not need to authenticate or already control an account.

**Other possible values:**

| Value | Meaning | General score effect |
|---|---|---|
| `N` | None | Highest score |
| `L` | Low | Lower score |
| `H` | High | Lowest exploitability weighting |

The exact numeric weight for Low and High privileges also depends on whether Scope is Changed or Unchanged.

**Why it was selected:**  
The crafted HTTP request can reach the vulnerable parser before authentication. The report explicitly describes remote code execution without authentication.

---

### UI:N — User Interaction: None

**What the abbreviation means:**  
`UI` means **User Interaction**.

**What the selected value means:**  
`N` means **None**. No user must open a file, click a link or approve an action.

**Other possible value:**

| Value | Meaning | General score effect |
|---|---|---|
| `N` | None | Higher score |
| `R` | Required | Lower score |

**Why it was selected:**  
The attacker interacts directly with the Apache service by sending the malicious request. A MedDefense employee does not need to perform an action.

---

### S:U — Scope: Unchanged

**What the abbreviation means:**  
`S` means **Scope**.

**What the selected value means:**  
`U` means **Unchanged**. The vulnerable component and the impacted component are controlled by the same security authority.

**Other possible value:**

| Value | Meaning | General score effect |
|---|---|---|
| `U` | Unchanged | Impact stays within the same security authority |
| `C` | Changed | Impact crosses into another security authority and can increase the score |

**Why it was selected:**  
The Apache process and the affected host belong to the same system security boundary. The vulnerability does not inherently cross into a separately managed security authority.

---

### C:H — Confidentiality Impact: High

**What the abbreviation means:**  
`C` means **Confidentiality Impact**.

**What the selected value means:**  
`H` means **High**. Successful exploitation could result in a total or serious loss of confidentiality.

**Other possible values:**

| Value | Meaning | General score effect |
|---|---|---|
| `N` | None | No confidentiality contribution |
| `L` | Low | Limited disclosure |
| `H` | High | Major or total disclosure |

**Why it was selected:**  
Remote code execution could allow the attacker to read sensitive files, application data, configuration data and billing information accessible to the compromised process.

---

### I:H — Integrity Impact: High

**What the abbreviation means:**  
`I` means **Integrity Impact**.

**What the selected value means:**  
`H` means **High**. The attacker could seriously or completely alter protected information or system components.

**Other possible values:**

| Value | Meaning | General score effect |
|---|---|---|
| `N` | None | No integrity contribution |
| `L` | Low | Limited unauthorized modification |
| `H` | High | Major or total modification |

**Why it was selected:**  
Code execution could permit changes to application files, billing records, configurations or other data accessible from the compromised service.

---

### A:H — Availability Impact: High

**What the abbreviation means:**  
`A` means **Availability Impact**.

**What the selected value means:**  
`H` means **High**. The vulnerable service or system could become completely unavailable.

**Other possible values:**

| Value | Meaning | General score effect |
|---|---|---|
| `N` | None | No availability contribution |
| `L` | Low | Reduced performance or intermittent interruption |
| `H` | High | Severe or complete interruption |

**Why it was selected:**  
The buffer overflow can crash Apache or allow an attacker to execute destructive commands, potentially stopping the billing application or the whole server.

---

## Changing Attack Vector from Network to Local

### Modified vector

`CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

### New score

**8.4 — High**

### Why the score changes

Only `AV` changes:

- Original: `AV:N`, reachable remotely over a network.
- Modified: `AV:L`, requiring local access or local execution.

The impact remains the same because confidentiality, integrity and availability are still all High. However, exploitability decreases substantially because an attacker must first obtain local access.

| Version | Exploitability sub-score | Impact sub-score | Base score |
|---|---:|---:|---:|
| Original `AV:N` | 3.887 | 5.873 | 9.8 |
| Modified `AV:L` | 2.515 | 5.873 | 8.4 |

The result falls from Critical to High because the attack is no longer directly reachable over the network.

---

# Exercise 2 — Construction

## Characteristics translated into metrics

| Characteristic | Metric choice | Reason |
|---|---|---|
| Exploitable only from the local network | `AV:A` | Adjacent means the attacker must be on the same local/shared network |
| Complex and requires specific conditions | `AC:H` | Exploitation depends on special prerequisites |
| Low-level privileges required | `PR:L` | The attacker needs a low-privileged account |
| No user interaction | `UI:N` | A user does not need to act |
| Only the target system is affected | `S:U` | Scope remains unchanged |
| Complete confidentiality compromise | `C:H` | Major or total disclosure |
| No integrity impact | `I:N` | Data cannot be altered through this vulnerability |
| No availability impact | `A:N` | The service is not disrupted |

## Constructed vector

`CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`

## Calculator result

**Base Score: 4.8 — Medium**

### Interpretation

The confidentiality impact is High, but the final score is moderated by three exploitability restrictions:

1. The attacker must already be on an adjacent network.
2. Exploitation requires complex conditions.
3. The attacker needs low-level privileges.

Integrity and availability contribute no impact. Therefore, the vulnerability is significant but not easy enough to exploit, nor broad enough in impact, to receive a High or Critical rating.

---

# Exercise 3 — Comparison

## Important dataset limitation

The scan report does **not** contain a finding with a documented CVSS score between **5.0 and 7.0**.

The explicit CVSS scores in the report are:

- 9.8
- 7.8
- 8.1
- 9.8
- 10.0
- 7.5
- 8.8
- 7.5
- 9.8
- 9.8

Therefore, a compliant comparison using an actual 5.0–7.0 finding is impossible without inventing data. The closest available scored finding is **7.5**, so it is used below and the deviation is documented.

## Finding selected above 9.0

### Finding 001 — CVE-2021-44790

Vector:

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

Score:

**9.8 — Critical**

## Closest available comparison finding

### Finding 005 — weak TLS protocols

Vector:

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

Score:

**7.5 — High**

## Side-by-side comparison

| Component | Finding 001 | Finding 005 | Effect |
|---|---|---|---|
| Attack Vector | `AV:N` | `AV:N` | Same: both are network reachable |
| Attack Complexity | `AC:L` | `AC:L` | Same: both are treated as low complexity |
| Privileges Required | `PR:N` | `PR:N` | Same: no prior privileges |
| User Interaction | `UI:N` | `UI:N` | Same: no user action |
| Scope | `S:U` | `S:U` | Same: scope unchanged |
| Confidentiality | `C:H` | `C:H` | Same: major confidentiality impact |
| Integrity | `I:H` | `I:N` | Finding 001 can alter data; Finding 005 cannot |
| Availability | `A:H` | `A:N` | Finding 001 can stop the service; Finding 005 cannot |

## What explains the score difference?

The exploitability metrics are identical. The entire difference comes from the Impact metrics:

- Finding 001 affects all three CIA properties: `C:H/I:H/A:H`.
- Finding 005 affects only confidentiality: `C:H/I:N/A:N`.

The calculated impact sub-scores illustrate this:

| Finding | Exploitability sub-score | Impact sub-score | Base score |
|---|---:|---:|---:|
| Finding 001 | 3.887 | 5.873 | 9.8 |
| Finding 005 | 3.887 | 3.595 | 7.5 |

## Which components have the biggest impact?

In this comparison, **Integrity and Availability have the biggest impact** because they are the only metrics that differ.

More generally:

- `AV:N`, `AC:L`, `PR:N` and `UI:N` maximize exploitability.
- Multiple High CIA impacts increase the Impact sub-score sharply.
- `S:C` can significantly affect the final formula because impact crosses a security boundary.
- Changing one CIA metric from None to High can be decisive, especially when the other exploitability metrics are already favorable to the attacker.

## Final lesson

Two vulnerabilities can be equally easy to exploit but receive very different scores because successful exploitation produces different consequences. CVSS must therefore be read as:

> **Ease of exploitation + technical impact**

It is not, by itself, a complete measure of organizational risk. Asset criticality, exposure, existing controls and business impact still need to be evaluated separately.
