# Containment Execution Record — IR-2026-0420-01

**Classification:** Internal — IR exercise  
**Record mode:** Append-only; planned simulation entries, **not** executed commands or verified outcomes.  
**Time standard:** UTC, 2026-04-20. Times below are **proposed exercise timestamps**, not historical evidence.  
**Prerequisites:** authorization, evidence capture, patient safety coordination, controlled EDR/firewall access.

## Execution ledger

| Step | UTC timestamp | Actor | Action | Expected outcome | Observed outcome | Deviation notes |
|---|---|---|---|---|---|---|
| EX-01 | 2026-04-20T20:12:00Z (simulated) | Pedro Cabral / Sarah Park / Clinical Director | Request and record authorization for coordinated containment, including file-server clinical exception plan | Signed approval and patient-safe downtime plan | NOT OBSERVED — exercise authorization proposed | Approval artifact and exact clinical exception scope unavailable. |
| EX-02 | 2026-04-20T20:13:00Z (simulated) | Mike Torres / forensic acquisition team | Confirm CS-WS-101 existing RAM image hash and capture status of CS-WS-104, CS-WS-107, CS-WS-112 and FILE-SVR-01 in parallel | Volatile evidence captured, hashed and custody logged before disruptive actions where safe | NOT OBSERVED — only Torres CS-WS-101 memory capture is source-reported | Original acquisition hash absent; no new image/hash files supplied. |
| EX-03 | 2026-04-20T20:16:00Z (simulated) | Robert Kim / Network team | Export current DNS/proxy/firewall/EDR telemetry; stage egress deny for staging.office365-cdn.net and 45.152.66.114 TCP/443 at controlled boundary | Preserve pre-block evidence and prepare targeted C2 block | NOT OBSERVED — configuration and pre-change logs unavailable | Validate destination against threat intel and live telemetry; avoid wildcard Microsoft domain blocks. |
| EX-04 | 2026-04-20T20:18:00Z (simulated) | Robert Kim / Network team | Apply approved DNS/FQDN and IP egress denies to all affected segments, log rule ID/change ticket and test against legitimate traffic | Outbound C2 path denied without broader clinical outage | NOT OBSERVED — no firewall console or change confirmation provided | Domain/IP may change; DNS and alternate egress routes require validation. |
| EX-05 | 2026-04-20T20:20:00Z (simulated) | James Chen / EDR operator | EDR network-isolate CS-WS-104 after volatile capture or documented emergency override | Host loses lateral/C2 connectivity; management telemetry retained if supported | NOT OBSERVED — EDR isolation response unavailable | Verify isolation policy permits evidence retrieval and does not force reboot. |
| EX-06 | 2026-04-20T20:21:00Z (simulated) | James Chen / EDR operator | EDR network-isolate CS-WS-107 after volatile capture or documented override | Second lateral host isolated | NOT OBSERVED | No host-specific isolation confirmation. |
| EX-07 | 2026-04-20T20:22:00Z (simulated) | James Chen / EDR operator | EDR network-isolate CS-WS-112 after volatile capture or documented override | Third lateral host isolated | NOT OBSERVED | Historical activity does not establish present beacon state. |
| EX-08 | 2026-04-20T20:23:00Z (simulated) | James Chen / EDR operator | EDR network-isolate CS-WS-101; confirm nurse off console and clinical alternative available | Initial compromise workstation isolated without power-off | NOT OBSERVED — nurse stop-use instruction is reported, isolation is not | Preserve pre-isolation memory and disk acquisition status. |
| EX-09 | 2026-04-20T20:25:00Z (simulated) | Sarah Park / Robert Kim / Clinical Director | Restrict FILE-SVR-01 to approved IR management and essential clinical paths after preserving volatile state and Security 4663 logs; block workstation-origin lateral access | Protect patient documentation while keeping explicitly authorized clinical workflows | NOT OBSERVED — no ACL/firewall change evidence | Server may have suspicious process activity; do not claim no beacon without live checks. |
| EX-10 | 2026-04-20T20:27:00Z (simulated) | Helena Reyes / IAM lead / James Chen | Identify affected identities from 72h authentication evidence; disable MEDDEFENSE\jdoe interactive access, revoke active sessions/tokens and reset credentials through approved emergency process | Prevent reuse of suspected compromised identity | NOT OBSERVED — sample identifies jdoe but not full compromised account set | Preserve authentication logs and coordinate clinical access replacement. |
| EX-11 | 2026-04-20T20:30:00Z (simulated) | IAM lead / Infrastructure lead | Review service accounts, privileged sessions, cached tickets and accounts used on CS-WS-101/104/107/112 and FILE-SVR-01; revoke exposed tokens, rotate verified at-risk credentials in dependency order | Cut off attacker credential reuse without breaking critical services | NOT OBSERVED — full 72h auth inventory unavailable | Do not rotate every account indiscriminately; log affected account IDs, owners and validation. |
| EX-12 | 2026-04-20T20:34:00Z (simulated) | James Chen / Network team | Validate C2 disruption using firewall deny counters, DNS/proxy logs, EDR host-isolation status and new connection attempts from all four workstations; check for alternate C2 destinations | Positive block evidence and no successful C2 egress in defined observation window | NOT VERIFIED — historical samples only; no post-change telemetry | No proof of severed C2 available. Require post-control logs and a defined monitoring window. |
| EX-13 | 2026-04-20T20:40:00Z (simulated) | Pedro Cabral / SOC / Clinical Director | Reassess ransomware activity, file-server clinical availability, new alerts, and rollback conditions; issue status update | Documented containment effectiveness and clinical impact | PENDING — no operational response or clinical confirmation supplied | Keep incident open; do not declare containment complete. |

## Implementation references — examples only (NOT EXECUTED)

**Network egress block:** deploy a change-controlled FQDN/DNS deny for `staging.office365-cdn.net` and outbound TCP/443 deny to `45.152.66.114` on the relevant firewalls, with logging. The exact firewall platform is unknown; no vendor-specific command can be asserted as applied. Verify DNS resolution, proxy bypass paths and IPv6 routes. Avoid blocking legitimate `office365.com` services broadly.

**Windows/EDR:** use the organization’s approved EDR *isolate device* action for each workstation and verify returned host status. For the file server, apply reviewed segment ACLs allowing only explicitly approved clinical and IR management paths. Do not reboot or kill suspicious processes before volatile capture unless urgent patient safety requires it.

**IAM:** use approved identity-platform controls to revoke sessions, disable or reset at-risk user accounts, and rotate affected privileged/service secrets. Prioritize `MEDDEFENSE\jdoe` because the supplied file-server sample links this identity to abnormal access; investigate other accounts before naming them compromised.

## Verification required before claiming successful containment

1. Record firewall rule ID, activation timestamp, scope and deny-hit logs for the malicious FQDN/IP.
2. Record EDR isolation acknowledgment for **each** of `CS-WS-101`, `CS-WS-104`, `CS-WS-107`, `CS-WS-112`.
3. Confirm `FILE-SVR-01` cannot accept unauthorized lateral connections while essential clinical access remains functional.
4. Compare proxy/SIEM/Sysmon/EDR events **after** enforcement with the pre-change beacon baseline, across a stated observation interval; look for successful connections, alternate domains/IPs, DNS bypass and new hosts.
5. Confirm IAM revocation in identity audit logs and failed reuse of exposed sessions, without testing with attacker credentials.
6. Record the clinical director’s sign-off on patient-safety impact. **Current result: C2 severance NOT VERIFIED.**

## Timeline synchronization

The planned steps above are mirrored below as `ACTION` rows in `incident_timeline.md`, marked `SIMULATED / NOT VERIFIED`. They must not be relabeled completed until actual evidence (change logs, EDR results, hashes, and clinical acknowledgment) is attached.

## Sources

- `torres_call_transcript.md` — initial reports and pre-call memory capture.
- `proxy_72h.sample.jsonl` — historical C2 domain/IP indicators.
- `sysmon_multihost.sample.jsonl` — suspicious process and network activity.
- `fileserver_access.sample.json` — suspicious clinical file access.
- `containment_decision.md` — selected strategy and rollback policy.
