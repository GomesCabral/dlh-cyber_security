# IR Activation: IR-2026-0420-01

**Classification:** Internal — Incident Response / Exercise
**Record status:** Training simulation. Source observations are distinguished from proposed operational decisions and communications.

## Incident declaration

- **incident_id:** `IR-2026-0420-01`
- **declared_at:** `2026-04-20T19:52:00Z` (simulated declaration time; not recorded in the transcript)
- **declared_by:** Pedro Cabral, on-call Incident Response Analyst (simulated role)
- **initial_severity:** **SEV1 — Critical (proposed)**
- **reasoning:** The on-call nurse reported an unusually slow clinical workstation and apparently altered filenames on `CS-WS-101`. The scheduling server `SCHED-SVR-01` showed sustained CPU and disk pressure. SIEM rule `wz-edr-200214` identified suspicious service installations on three additional clinical workstations (`CS-WS-104`, `CS-WS-107`, `CS-WS-112`), using service `WinHealthSvc` and executable `C:\ProgramData\Microsoft\svchost32.exe`. The combined indicators suggest possible multi-host compromise and imminent disruption of clinical operations; ransomware execution, patient-data exposure and the full scope remain unconfirmed at declaration time. SEV1 is a conservative simulated judgment pending confirmation against the organization's approved severity matrix.
- **playbook_activated:** Major Security Incident / Suspected Malware and Ransomware Response, with Clinical Business Continuity escalation (proposed mapping; exact previously approved playbook title not provided).
- **playbook_reason:** Potential malware persistence on several clinical endpoints, suspicious file changes, and possible impact on scheduling require coordinated triage, evidence preservation, containment planning and clinical safety assessment.
- **incident_commander:** On-call IR Analyst, acting pending formal designation.
- **operational_priority:** Protect patient safety; preserve volatile evidence; coordinate containment with clinical and infrastructure leads; avoid unapproved shutdown of critical services.

## Source observations available at activation

1. At 19:43:22Z, Mike Torres relayed the nurse's report of a slow workstation and filenames that appeared changed. This was an unverified user report.
2. At 19:44:20Z, Torres reported SIEM rule `wz-edr-200214` on three clinical workstations; at 19:44:48Z he provided the suspicious service name and path. This is a reported alert, not yet independently validated.
3. Torres reported capturing `CS-WS-101` memory at 19:38Z. Handoff notes state it was written to `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem` at 19:41Z; no acquisition hash was computed. Preserve the original and calculate/record a cryptographic hash before analysis; document the initial integrity gap.

## Notifications within the first 15 minutes of simulated declaration

The entries below are a **proposed notification log**, not verified sends. All times are UTC; replace with actual send/acknowledgment evidence during a real exercise.

| Time (UTC) | Recipient / role | Channel and purpose | Status |
|---|---|---|---|
| 19:52Z | James Chen — SOC Lead | IR bridge: confirm SEV1, assign triage and detection scope | SIMULATED |
| 19:54Z | Sarah Park — IT Director | IR bridge: infrastructure coordination and safe containment planning | SIMULATED |
| 19:56Z | Dr. Patricia Morales — executive security sponsor | Restricted executive alert: critical clinical-system security incident | SIMULATED |
| 19:58Z | Robert Kim — Infrastructure Lead | IR bridge: endpoint/server dependencies and evidence preservation | SIMULATED |
| 20:00Z | Clinical Director representative | Clinical safety and scheduling continuity assessment | SIMULATED |
| 20:02Z | Helena Reyes — General Counsel | Privileged/legal channel: preservation, potential PHI exposure assessment | SIMULATED |
| 20:04Z | Marcus Webb — Communications Lead | Restricted coordination: prepare holding statement, no external disclosure without approval | SIMULATED |

## First communication — verbatim (simulated)

**Template:** Initial critical incident / executive status update (provisional; original organization communication template not supplied)  
**To:** Dr. Patricia Morales (executive security sponsor); restricted copy to Incident Commander and SOC Lead  
**Sent:** `2026-04-20T19:56:00Z` (SIMULATED; not evidenced by transcript)  
**Subject:** SEV1 IR-2026-0420-01 — Suspected Multi-Host Clinical System Compromise

> At 19:52 UTC, we declared SEV1 incident IR-2026-0420-01 following reports of abnormal behavior on clinical workstation CS-WS-101, severe resource utilization on scheduling server SCHED-SVR-01, and suspicious service-installation alerts affecting CS-WS-104, CS-WS-107, and CS-WS-112. The scope, root cause, presence of ransomware, and any patient-data impact are not yet confirmed. The SOC and infrastructure teams are being mobilized to preserve evidence, validate affected systems, and develop containment options in coordination with clinical leadership to protect patient care. Legal is being engaged for preservation and potential PHI implications. We will provide the next verified status update by 20:30 UTC or sooner if patient safety or service availability deteriorates.

## Immediate handoff / next actions (planned, not completed)

- Verify the SIEM events, service binary and host inventory; open a dedicated incident bridge and assign an incident commander.
- Record evidence custodian, acquisition times, storage path, SHA-256 hashes and chain of custody; do not imply the un-hashed memory image was verified at acquisition.
- Assess clinical operational risk before isolation or shutdown; seek documented authorization for containment of critical systems.
- Initiate targeted host and network scoping, while preserving original logs and avoiding unnecessary modifications to affected endpoints.
- Record all decisions and actual communications in `incident_timeline.md` as they occur.

## Sources and limitations

- Primary initial operational signal: `torres_call_transcript.md`, call at 2026-04-20T19:43:18Z and handoff notes at 19:52Z.
- The transcript contains a placeholder for the student's response at 19:47:40Z; it does **not** prove that declaration, notifications, or executive communication occurred.
- The exact approved severity matrix, playbook titles, distribution lists, and communication templates were not supplied. Names and notification roles are proposed for this training exercise and should be checked against the approved IR program.
