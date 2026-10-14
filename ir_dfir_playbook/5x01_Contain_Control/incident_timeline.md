# Incident Timeline: IR-2026-0414-01

## Header

- incident_id: IR-2026-0414-01
- declared_at: 2026-04-14T02:51:04Z
- declared_by: Pedro Cabral, on-call SOC (simulated analyst decision)
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: Pedro Cabral, on-call SOC

> **Exercise note:** `declared_at` (02:51:04Z) is the illustrative declaration time in the task example, **not** an event proved by the supplied logs. Replace it with the actual simulated declaration time you choose and keep all dependent entries consistent. Historical log events below are recorded at their original event timestamps; their presence in this timeline does not imply the analyst had reviewed the proxy export before its export at 02:52:18Z. Future changes must be appended, not edited.

## Legend

- **OBSERVATION:** Raw fact from an alert, log, or artifact; not proof of malicious intent by itself.
- **DECISION:** Choice made by an authorized actor, with rationale.
- **ACTION:** Operation actually executed against an asset, with owner.
- **COMMUNICATION:** Message actually sent or received, with audience.
- **EVIDENCE:** Preserved artifact with SHA-256 hash and storage path (only once preservation is verified).

## Entries

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
- 2026-04-14T02:51:04Z | DECISION | Pedro Cabral, on-call SOC (simulated) | Declared incident IR-2026-0414-01 at initial SEV2: suspicious execution and outbound connection on high-criticality clinical workstation; clinical disruption and data exposure not confirmed. | source=alert A-20260414-9841 + severity_matrix.md; simulated declaration | certainty=confirmed
- 2026-04-14T02:51:04Z | DECISION | Pedro Cabral, on-call SOC (simulated) | Selected PB-CRED-001 Credential Exposure for credential-risk investigation as recommended by alert; preserve volatile evidence and assess clinical impact before disruptive containment. | source=alert_A-20260414-9841.json:recommended_playbook + PB-CRED-001; simulated decision | certainty=confirmed

## Append-only continuation

Add subsequent OBSERVATION, DECISION, ACTION, COMMUNICATION, and EVIDENCE entries below this line as they occur. For EVIDENCE, include the verified artifact path and SHA-256. Do not record a planned action as completed, or a notification as sent, until verified. If an earlier interpretation changes, append a correction referencing the original timestamp rather than editing the prior entry.
