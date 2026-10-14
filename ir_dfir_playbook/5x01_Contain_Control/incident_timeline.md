# Incident Timeline: IR-2026-0414-01

## Header

- incident_id: IR-2026-0414-01
- declared_at: 2026-04-14T02:48:00Z
- declared_by: Pedro Cabral, on-call SOC (simulated analyst decision)
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: Pedro Cabral, on-call SOC

> **Simulation scope:** The incident declaration at `2026-04-14T02:48:00Z` is the analyst's chosen exercise decision time, not a timestamp recorded by the SIEM. Earlier observations retain their original event timestamps. The proxy export was produced at `2026-04-14T02:52:18Z`; its historical events are included retrospectively, not claimed to have been reviewed at declaration.

## Legend

- **OBSERVATION:** Raw fact from an alert, log, or artifact; not proof of malicious intent by itself.
- **DECISION:** Choice made by an authorized actor, with rationale.
- **ACTION:** Operation actually executed against an asset, with owner.
- **COMMUNICATION:** Message actually sent or received, with audience.
- **EVIDENCE:** Preserved artifact with SHA-256 hash and storage path (only once preservation is verified).

## Entries

Each entry uses the fields `timestamp | type | actor | description | source | certainty`, in that order. Times describe when the underlying event occurred; retrospective log observations are explicitly sourced.

- 2026-04-13T18:13:44Z | OBSERVATION | Proxy log / dmarsh | Browser requested an Outlook message URL before the suspicious web visit. | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-13T18:14:02Z | OBSERVATION | Proxy log / dmarsh | GET to ms0365-support.login-verification.click/auth returned HTTP 200; page resembles Microsoft sign-in. | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-13T18:14:41Z | OBSERVATION | Proxy log / dmarsh | POST to /auth/submit returned HTTP 302; submission contents and credential theft are not established by this log alone. | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-13T18:14:43Z | OBSERVATION | Proxy log / dmarsh | GET to /auth/drop/update.zip returned HTTP 200 (421004 bytes logged); execution of the download is not established. | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-14T02:46:41Z | OBSERVATION | WazuhEDR | powershell.exe (PID 7812) started under MEDDEFENSE\dmarsh with hidden window, execution-policy bypass and encoded command. | source=alert_A-20260414-9841.json:process_tree.parent | certainty=confirmed
- 2026-04-14T02:46:44Z | OBSERVATION | Proxy log / dmarsh | CONNECT attempt to 185.220.101.47:443 recorded; response/status absent in this line. | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-14T02:46:57Z | OBSERVATION | WazuhEDR | powershell.exe spawned MSBuild.exe (PID 8104) to process C:\Users\dmarsh\AppData\Local\Temp\update.xml. | source=alert_A-20260414-9841.json:process_tree.child | certainty=confirmed
- 2026-04-14T02:47:02Z | OBSERVATION | WazuhEDR | MSBuild.exe established outbound TCP connection from 10.42.118.31 to 185.220.101.47:443; destination tagged Tor exit relay by internal threat intelligence. | source=alert_A-20260414-9841.json:network_connection+enrichment | certainty=confirmed
- 2026-04-14T02:47:08Z | OBSERVATION | Proxy log / dmarsh | Additional CONNECT to 185.220.101.47:443 returned HTTP 200; destination intent and exfiltration remain unconfirmed. | source=proxy_24h_dmarsh.log | certainty=confirmed
- 2026-04-14T02:47:11Z | OBSERVATION | MedDefense-SOC-Splunk / WazuhEDR | Rule wz-edr-100041 fired for suspicious PowerShell-to-MSBuild process tree on clinical workstation WST-WS-031. | source=alert A-20260414-9841 | certainty=confirmed
- 2026-04-14T02:48:00Z | DECISION | Pedro Cabral, on-call SOC (simulated) | Declared incident IR-2026-0414-01 at initial SEV2: suspicious execution and outbound connection on high-criticality clinical workstation; clinical disruption and data exposure not confirmed. | source=alert A-20260414-9841 + severity_matrix.md; simulated analyst decision | certainty=confirmed
- 2026-04-14T02:48:00Z | DECISION | Pedro Cabral, on-call SOC (simulated) | Selected PB-CRED-001 Credential Exposure for credential-risk investigation as recommended by alert; preserve volatile evidence and assess clinical impact before disruptive containment. | source=alert_A-20260414-9841.json:recommended_playbook + PB-CRED-001; simulated analyst decision | certainty=confirmed

## Append-only continuation

Add subsequent OBSERVATION, DECISION, ACTION, COMMUNICATION, and EVIDENCE entries below this line as they occur. For EVIDENCE, include the verified artifact path and SHA-256. Do not record a planned action as completed, or a notification as sent, until verified. If an earlier interpretation changes, append a correction referencing the original timestamp rather than editing the prior entry.

- 2026-04-14T02:53:00Z | DECISION | Pedro Cabral, on-call SOC (simulated) | Selected quarantine-VLAN network isolation as the proposed containment strategy for WST-WS-031, conditional on volatile evidence preservation, James Chen's authorization and clinical continuity check; no containment executed yet. | source=containment_decision.md (Task 3; simulated decision timestamp) | certainty=confirmed

## Task 4 — Simulated containment execution (exercise-only, NOT evidence-validated)

- 2026-04-14T03:14:00Z | ACTION | Pedro Cabral / IR analyst (exercise simulation) | Close preservation checklist; review SHA-256 manifest and memory/process/network acquisition receipts; scenario result: checklist signed off; actual capture receipts and hashes were not supplied | source=containment_execution.md, simulated evidence_preservation.md; simulated checklist; no real execution log | certainty=possible
- 2026-04-14T03:15:00Z | ACTION | James Chen / IR Commander (exercise simulation) | Approve quarantine VLAN containment in incident change record; scenario result: approval granted; no actual approval message provided | source=containment_execution.md, simulated simulated approval record; no real execution log | certainty=possible
- 2026-04-14T03:16:04Z | ACTION | Network engineer (exercise simulation) | Switch console: set WST-WS-031 access port to quarantine VLAN 999; apply ACL deny all except IR jumpbox; scenario result: port reports VLAN 999 and quarantine ACL applied | source=containment_execution.md, simulated simulated switch audit; no real execution log | certainty=possible
- 2026-04-14T03:17:21Z | ACTION | Firewall administrator (exercise simulation) | Firewall console: add deny/log src=10.42.118.31 dst=185.220.101.47 tcp/443; commit above allow policies; scenario result: policy committed and test connection denied | source=containment_execution.md, simulated simulated firewall policy audit; no real execution log | certainty=possible
- 2026-04-14T03:18:30Z | ACTION | SOC network analyst (exercise simulation) | Query netflow/PCAP for WST-WS-031 -> 185.220.101.47:443 for 03:16:04–03:18:30Z; check capture coverage; scenario result: no successful egress flows after 03:16:04Z; collection coverage assumed | source=containment_execution.md, simulated simulated post-containment netflow; no real execution log | certainty=possible
- 2026-04-14T03:19:02Z | ACTION | EDR administrator (exercise simulation) | EDR console: enable device containment for WST-WS-031 with IR management exception; scenario result: device flagged contained and management exception enabled | source=containment_execution.md, simulated simulated EDR audit; no real execution log | certainty=possible
- 2026-04-14T03:22:04Z | ACTION | Network engineer / SOC analyst (exercise simulation) | From production user VLAN: TCP probe to 10.42.118.31 denied; from approved IR jumpbox: approved management port probe succeeds; scenario result: user-VLAN probe denied, jumpbox management probe allowed | source=containment_execution.md, simulated simulated connectivity tests; no real execution log | certainty=possible
- 2026-04-14T03:23:00Z | ACTION | West Campus lab lead (exercise simulation) | Confirm alternate clinical workflow after WST-WS-031 quarantine; scenario result: lab work continued via approved alternate workflow | source=containment_execution.md, simulated simulated clinical confirmation; no real execution log | certainty=possible

## Task 4 — Scenario reference clarification (appended, no historical entries overwritten)

The following entries reference the **assignment's example execution record** rather than independent device telemetry. They clarify the source of the scenario actions above; earlier simulated entries remain unchanged under the append-only rule.

- 2026-04-14T03:16:04Z | ACTION | Network Operations (lab scenario) | Reassign WST-WS-031 to quarantine VLAN 999; scenario reports user-VLAN timeout and IR jumpbox access. | source=containment_execution.md §1; Task 4 example | certainty=possible
- 2026-04-14T03:17:21Z | ACTION | Network Operations (lab scenario) | Configure firewall egress deny to 185.220.101.47; scenario reports zero outbound packets after enforcement. | source=containment_execution.md §2; Task 4 example | certainty=possible
- 2026-04-14T03:17:21Z | ACTION | Pedro Cabral / SOC Analyst (lab scenario) | Review NetFlow; scenario reports no subsequent packets to 185.220.101.47, without an independent capture. | source=containment_execution.md §3; Task 4 example | certainty=possible
- 2026-04-14T03:19:02Z | ACTION | Endpoint Security Analyst (lab scenario) | Set WST-WS-031 containment flag; scenario reports flag SET. | source=containment_execution.md §4; Task 4 example | certainty=possible
- 2026-04-14T03:22:04Z | ACTION | Pedro Cabral / SOC Analyst (lab scenario) | Test user-VLAN and IR jumpbox connectivity; scenario reports timeout from user VLAN and successful jumpbox ping. | source=containment_execution.md §5; Task 4 example | certainty=possible
