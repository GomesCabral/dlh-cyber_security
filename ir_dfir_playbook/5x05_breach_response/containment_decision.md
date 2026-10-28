# Containment Decision — IR-2026-0420-01

**Classification:** Internal — IR exercise | **Decision time:** 2026-04-20T20:12:00Z (SIMULATED)  
**Decision owner:** Acting Incident Commander (Pedro Cabral); **authorization required:** Sarah Park (IT Director), with Clinical Director approval for FILE-SVR-01 disruption.  
**Scope:** CS-WS-101, CS-WS-104, CS-WS-107, CS-WS-112, FILE-SVR-01. `SCHED-SVR-01` requires separate urgent scoping; not assumed clean.

## Three strategies

| Strategy | Action | Attacker impact | Patient-care impact | Evidence preserved / lost | Estimated execution | Reversibility |
|---|---|---|---|---|---|---|
| A. Emergency power-off | Power down four workstations and file server | Abruptly stops active execution on powered-off hosts; no guarantee other footholds removed | High: clinical workstation and file-share outage; may disrupt ED workflow and access to clinical documents | Disk persists; RAM, live connections and encryption/process state lost | ~5–15 min after authorization | Hardware can restart, but volatile evidence irretrievable; malware may persist |
| **B. Coordinated network containment (chosen)** | Collect priority RAM and logs in parallel where safe; block C2 domain/IP at egress; EDR-isolate four workstations; restrict file-server network access with approved clinical exceptions; revoke exposed credentials | Disrupts C2 and lateral movement while preserving powered-on hosts; may miss alternative C2 paths | Moderate, managed: workstations unavailable; file-share access restricted with approved clinical continuity route | RAM and disk potentially preserved; isolation changes network state and terminates sessions; capture live sessions first | ~15–35 min to initial controls, plus validation | Firewall/EDR isolation reversible on approval; revoked credentials require controlled reissue |
| C. Observe without isolation | Continue telemetry collection; no immediate blocking | Preserves attacker behavior for observation, but leaves C2 and ransomware risk | Short-term services remain available; high potential future patient harm | More live telemetry; risk of attacker tampering or destruction | Immediate decision, indefinite risk window | Monitoring decision reversible; resulting harm may not be |

## Decision and trade-off rationale

**Choose B**, subject to documented clinical authorization. The four clinical workstations have indicators of beacon/persistence and ransomware staging; prolonged observation risks encryption and credential abuse. Immediate power-off would erase volatile malware and credential evidence and unnecessarily disrupt care. Parallel rapid memory acquisition followed by EDR isolation and centrally applied C2 egress controls balances forensic preservation with patient safety. `FILE-SVR-01` has suspicious access to clinical records and may itself have malicious process activity: preserve its audit trail and volatile state, then use narrowly approved clinical-access exceptions or a downtime workflow rather than assuming it is safe. Evidence collection must not delay containment if active encryption or imminent patient harm is detected. This is a **proposed exercise decision**, not a recorded authorization or execution.

**Rollback trigger:** Restore only specific network paths when Clinical Director confirms a patient-safety need **and** Incident Commander/SOC Lead verify the exception does not restore attacker C2/lateral access; document approver, scope, expiry and monitoring. Full restoration requires validated eradication, credential rotation and recovery authorization. **Emergency escalation:** active encryption, spreading compromise, or unsafe clinical disruption triggers immediate joint reassessment, potentially strategy A for a specific host.

**Evidence anchors:** `torres_call_transcript.md`; `sysmon_multihost.sample.jsonl`; `proxy_72h.sample.jsonl`; `fileserver_access.sample.json`. Times are exercise estimates, not observed execution durations.
