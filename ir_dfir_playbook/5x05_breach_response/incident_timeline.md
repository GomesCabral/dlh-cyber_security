# Incident Timeline — IR-2026-0420-01

**Classification:** Internal — Incident Response / Exercise  
**Status:** OPEN — append-only operational record  
**Time standard:** UTC (ISO 8601)  
**Recording rule:** Never overwrite or delete an existing event. Append corrections as new entries referring to the original event ID. Distinguish source-supported observations from simulated decisions and planned actions.  
**Certainty:** CONFIRMED (directly evidenced in the cited source), REPORTED (relayed but not independently verified), SIMULATED (exercise action not documented as actually occurring), INFERRED (analysis, not directly observed).

| Event ID | Timestamp (UTC) | Type | Actor | Description | Source | Certainty |
|---|---|---|---|---|---|---|
| EVT-001 | 2026-04-20T19:43:22Z | OBSERVATION | On-call nurse, relayed by Mike Torres | Nurse reports `CS-WS-101` is extremely slow and desktop filenames appear changed; Torres has not independently verified the changes. Torres also reports abnormal load on scheduling server `SCHED-SVR-01` at 19:43:50Z. | `torres_call_transcript.md`, 19:43:22–19:43:50Z | REPORTED |
| EVT-002 | 2026-04-20T19:44:20Z | OBSERVATION | Mike Torres, Network Engineer | Torres reports SIEM rule `wz-edr-200214` for suspicious service installations on `CS-WS-104`, `CS-WS-107`, and `CS-WS-112`. At 19:44:48Z he identifies service `WinHealthSvc` and executable `C:\ProgramData\Microsoft\svchost32.exe`. The underlying alert has not yet been independently validated by the IR analyst. | `torres_call_transcript.md`, 19:44:20–19:44:48Z | REPORTED |
| EVT-003 | 2026-04-20T19:52:00Z | DECISION | Pedro Cabral, acting on-call IR Analyst (simulation) | Formally declares `IR-2026-0420-01` as initial SEV1 due to suspected multi-host malware activity and potential clinical service impact. Activates major-incident/malware response coordination; exact approved playbook name and severity matrix require verification. This time is a simulated exercise choice, not a recorded transcript event. | `ir_activation.md`, Incident declaration (simulated) | SIMULATED |

## Append-only continuation instructions

Add future events **below the existing table** or append new rows without changing EVT-001 through EVT-003. Use a new sequential Event ID and preserve the source and certainty. The initial three rows are deliberately limited to the required opening: user report, SIEM alert, and incident declaration. Later forensic findings (including events that occurred earlier in time) must be appended with their original event timestamp and the time of discovery recorded in the description or a future extended schema.

**Important pending evidence note (not a fourth opening entry):** The transcript's 19:52Z handoff notes say Torres captured memory from `CS-WS-101` at 19:38Z, stored it at 19:41Z, and did not compute a hash at acquisition. Log this as an EVIDENCE entry when the evidence register is opened; document the missing initial hash rather than silently assuming integrity.
