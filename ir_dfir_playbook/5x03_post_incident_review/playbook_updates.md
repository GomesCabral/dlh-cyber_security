# IR Playbook Updates: IR-2026-0414-01

**Organization:** MedDefense  
**Target playbook:** `playbook_credential_exposure.yaml`  
**Sources:** `gap_analysis.md` (Task 2), `control_effectiveness.yaml` (Task 1), and `forensic_findings_summary.md` (5x02 hand-off).  
**Status:** Proposed amendments; validate against the current deployed playbook and approve through IR change control.

> **Source integrity:** The original `playbook_credential_exposure.yaml` was not supplied with this task. The **Before** snippets below are abbreviated descriptions from the assignment, **not verified verbatim quotations**. Section names are proposed insertion points. The forensic hand-off confirms a foreign-IP **Office 365** session, not a VPN login; confirms Kerberos-based lateral movement but not forged tickets; and confirms access to 14 PHI PDFs but not exfiltration.

### Change PB-UPD-001 — Trigger on anomalous VPN and identity sign-ins

**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `applies_to.triggers`  
**Gap closed:** GAP-002, GAP-003  
**Finding reference:** Task 1 phase 2; forensic summary, *Open investigative items* (Office 365 session at `2026-04-13T18:14:41Z`, IP `45.63.9.88`).

**Before (assignment's abbreviated description; not verified against original):**
```yaml
triggers:
  - "Alert: credential submitted to external domain"
```

**After (proposed playbook text):**
```yaml
triggers:
  - "Alert: credential submitted to external domain"
  - "Alert: successful VPN authentication from a country not observed for this identity in the preceding 30 days"
  - "Alert: impossible-travel sign-ins with geographically incompatible travel time within 2 hours (VPN or Entra ID)"
  - "Alert: high-risk Entra ID sign-in, including risk signals suppressed or bypassed by device-compliance policy"
triage_on_trigger:
  - "Record identity, UTC timestamps, source IPs, geolocation confidence, device ID and VPN/Entra correlation IDs"
  - "Correlate VPN concentrator logs with Entra ID sign-in logs; do not assume an Entra sign-in was VPN access"
  - "Check approved travel, corporate VPN egress, mobile carriers and proxy IPs before concluding compromise"
  - "If compromise is likely, revoke active sessions, preserve authentication evidence and initiate containment approval"
```

**Reason:** The known foreign-IP Office 365 session remained untraced, and conditional-access risk suppression needs review. A VPN-specific trigger closes the procedural blind spot **if VPN access is later verified**, rather than treating it as established fact.

**Validation:** Replay a synthetic new-country VPN sign-in and a separate foreign Entra sign-in; verify both initiate triage, retain distinct source types, and record analyst disposition.

---

### Change PB-UPD-002 — Expand scope when Kerberos lateral movement is detected

**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `response.scope_expansion` (new section)  
**Gap closed:** GAP-010, GAP-011  
**Finding reference:** ART-003-M01 (Kerberos logon from `WST-WS-031` to `WST-WS-017`); AD-LOG-01 (14 PDF reads on `LIS-WSIDE-01`).

**Before (assignment's abbreviated description; not verified against original):**
```yaml
response:
  containment:
    - "Reset compromised account password"
    # No explicit host-expansion checklist described in assignment.
```

**After (proposed playbook text):**
```yaml
response:
  scope_expansion:
    trigger: "Suspected or confirmed Pass-the-Ticket, anomalous Kerberos logon, or new remote execution host"
    steps:
      - "Preserve Kerberos events 4768/4769/4771/4776, logon events 4624/4648 and relevant EDR/Sysmon evidence with UTC times"
      - "Enumerate source host, target hosts, accounts, logon sessions, process trees and remote execution paths"
      - "Add every newly implicated endpoint and clinical share to the incident scope register"
      - "For WST-WS-031 -> WST-WS-017, investigate MSBuild execution and connections to 91.234.99.107:443"
      - "For LIS-WSIDE-01, preserve LIS_REPORTS$ file/share audit logs and review the 14 PDF accesses"
      - "Assess clinical impact with the care operations lead before isolating any patient-care system"
      - "Contain additional confirmed hosts using approved EDR/network isolation; preserve evidence first where safe"
      - "Reassess severity, update the incident timeline and notify IR commander and privacy/legal liaison"
```

**Reason:** Kerberos-based movement reached a second workstation, followed by access to PHI. The response must systematically identify and contain newly affected hosts rather than stopping at the initially compromised account.

**Validation:** Run a tabletop exercise where a second workstation and a clinical file share appear after initial triage; confirm the scope register, clinical approval, evidence preservation and containment decisions are recorded.

---

### Change PB-UPD-003 — Kerberos ticket response and conditional krbtgt double reset

**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `response.eradication.kerberos` (new section)  
**Gap closed:** GAP-008, GAP-009, GAP-010  
**Finding reference:** ART-002-M04 (NTLM material observed in LSASS); ART-003-M01 (Kerberos-based lateral movement); ATT&CK T1550.003 and T1558.003 listed in the forensic summary.

**Before (assignment's abbreviated description; not verified against original):**
```yaml
response:
  eradication:
    - "Reset compromised account password"
```

**After (proposed playbook text):**
```yaml
response:
  eradication:
    kerberos:
      - "Preserve domain-controller Kerberos and endpoint evidence; distinguish replayed/stolen tickets from forged tickets"
      - "Disable or reset compromised user/service credentials and revoke sessions; remove stolen tickets from affected hosts through approved session termination or restart"
      - "Investigate domain controller compromise, krbtgt secret exposure and evidence of forged Golden Tickets"
      - "If krbtgt compromise or Golden Ticket forging is confirmed, obtain AD/IR commander approval for a planned krbtgt password reset twice, with replication verified between resets and appropriate ticket-lifetime spacing"
      - "Coordinate both resets with AD operations to avoid replication, trust and authentication outages; record DC replication checks and post-change ticket validation"
      - "If only Pass-the-Ticket with an ordinary stolen ticket is confirmed, do not automatically reset krbtgt; document why a domain-wide reset is or is not warranted"
```

**Reason:** Resetting one user password is insufficient for all stolen-session or forged-ticket scenarios. **Technical correction to the assignment:** Pass-the-Ticket alone does *not* require a `krbtgt` double reset. That disruptive operation is warranted for `krbtgt` secret compromise or forged Golden Ticket risk, not merely a replayed ordinary Kerberos ticket. The case evidence does not establish `krbtgt` compromise.

**Validation:** In an authorized AD lab, confirm the decision branch: stolen user ticket leads to session/credential containment; simulated confirmed `krbtgt` compromise requires two approved rotations, verified replication and successful post-rotation authentication.

---

### Change PB-UPD-004 — HIPAA four-factor assessment for ePHI exposure

**Playbook:** `playbook_credential_exposure.yaml`  
**Section:** `decision_points.ephi_breach_assessment` (new section)  
**Gap closed:** GAP-011, GAP-012  
**Finding reference:** AD-LOG-01 (14 patient PDF reads on `LIS_REPORTS$`); forensic summary, *Scope* and *Open investigative items* (no confirmed exfiltration; DLP review outstanding).

**Before (assignment's abbreviated description; not verified against original):**
```yaml
response:
  decision_points:
    - "Determine whether credentials were compromised"
    # No ePHI-specific decision branch described in assignment.
```

**After (proposed playbook text):**
```yaml
response:
  decision_points:
    ephi_breach_assessment:
      trigger: "Any confirmed or suspected unauthorized access to ePHI systems, records or file shares"
      immediate_actions:
        - "Notify Privacy Officer and Legal Liaison; preserve access, DLP, proxy, EHR and file-share logs"
        - "Identify patients, records, user identities, access methods, timestamps and potential recipients"
        - "Do not equate absence of proven exfiltration with absence of a reportable breach"
      hipaa_four_factors:
        - "1. Nature and extent of PHI involved, including identifiers and likelihood of re-identification"
        - "2. Unauthorized person who used the PHI or to whom disclosure was made"
        - "3. Whether PHI was actually acquired or viewed (including evidence of the 14 PDF reads)"
        - "4. Extent to which the risk to PHI was mitigated"
      decision:
        - "Privacy/Legal documents the four-factor risk assessment and whether there is a low probability that PHI was compromised"
        - "Assess applicable notification obligations and deadlines under HIPAA; record rationale and decision authority"
        - "Keep DLP/exfiltration status OPEN until supporting evidence is reviewed; update findings when obtained"
```

**Reason:** The incident included confirmed access to 14 laboratory PDFs containing PHI. HIPAA risk analysis must be explicitly triggered even though transfer outside MedDefense is not confirmed.

**Validation:** Simulate unauthorized reads of 14 patient PDFs without confirmed exfiltration; verify a four-factor assessment, named Privacy/Legal decision maker, DLP follow-up and documented notification determination.

---

## Implementation and review checklist

| Change | Suggested owner | Acceptance evidence |
| --- | --- | --- |
| PB-UPD-001 | Identity/VPN engineering + SOC lead | Synthetic VPN and Entra alerts open distinct playbook cases |
| PB-UPD-002 | IR technical lead + clinical operations | Scope-expansion tabletop records all three implicated hosts and clinical sign-off |
| PB-UPD-003 | Active Directory lead + IR commander | Approved Kerberos response decision tree and lab validation; no unapproved production `krbtgt` resets |
| PB-UPD-004 | Privacy Officer + Legal Liaison | Completed four-factor assessment worksheet and tracked DLP review |

**Deployment gate:** Compare each proposed section with the actual version-controlled `playbook_credential_exposure.yaml`, obtain IR/clinical/privacy approvals, update the live YAML, run its schema/lint checks, and record a tabletop validation before publishing it as operational guidance.
