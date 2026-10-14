# Containment Execution: IR-2026-0414-01

> **EXERCISE SIMULATION — NOT LIVE EXECUTION.** The lab supplied only the assignment text, not switch/firewall/EDR consoles, packet captures, post-change logs, actual approval, or collection receipts. All times and observed results below are **invented exercise assumptions**, not evidence-validated facts. Replace them with actual records if the lab later supplies execution data. Never submit these as real-world forensic proof.

- Endpoint: `WST-WS-031` (`10.42.118.31`); user `MEDDEFENSE\dmarsh`
- Initial alert: `A-20260414-9841` at `2026-04-14T02:47:11Z`
- Chosen strategy: A — quarantine VLAN with IR jumpbox access (`containment_decision.md`)
- Simulation VLAN: `999` (example, not verified switch configuration)
- Execution classification: **simulated / not independently verified**

## Execution window

- Simulated evidence-preservation completion: `2026-04-14T03:14:00Z` (no acquisition outputs supplied)
- Simulated authorization: `2026-04-14T03:15:00Z`, James Chen, IR Commander
- Simulated containment start: `2026-04-14T03:16:04Z`
- Gap between preservation completion and containment: **2 min 4 sec** (simulation only)

## Execution records

Each record includes all six required fields. `observed result` means **scenario-assumed result**, not an independently validated observation.

### Step 1 — 2026-04-14T03:14:00Z
- **timestamp (UTC):** `2026-04-14T03:14:00Z`
- **actor:** Pedro Cabral / IR analyst
- **command or console action:** Close preservation checklist; review SHA-256 manifest and memory/process/network acquisition receipts
- **expected result:** Volatile evidence secured before isolation
- **observed result:** SIMULATED: checklist signed off; actual capture receipts and hashes were not supplied
- **deviation notes:** Precondition assumed for exercise; cannot independently verify
- **source:** evidence_preservation.md; simulated checklist (exercise assumption; no authentic execution artifact supplied)

### Step 2 — 2026-04-14T03:15:00Z
- **timestamp (UTC):** `2026-04-14T03:15:00Z`
- **actor:** James Chen / IR Commander
- **command or console action:** Approve quarantine VLAN containment in incident change record
- **expected result:** Authorized isolation after clinical coordination
- **observed result:** SIMULATED: approval granted; no actual approval message provided
- **deviation notes:** Approval assumed only in scenario
- **source:** simulated approval record (exercise assumption; no authentic execution artifact supplied)

### Step 3 — 2026-04-14T03:16:04Z
- **timestamp (UTC):** `2026-04-14T03:16:04Z`
- **actor:** Network engineer
- **command or console action:** Switch console: set WST-WS-031 access port to quarantine VLAN 999; apply ACL deny all except IR jumpbox
- **expected result:** Production and internet access denied; forensic jumpbox allowed
- **observed result:** SIMULATED: port reports VLAN 999 and quarantine ACL applied
- **deviation notes:** Switchport and jumpbox IP unspecified in supplied materials; do not execute blindly
- **source:** simulated switch audit (exercise assumption; no authentic execution artifact supplied)

### Step 4 — 2026-04-14T03:17:21Z
- **timestamp (UTC):** `2026-04-14T03:17:21Z`
- **actor:** Firewall administrator
- **command or console action:** Firewall console: add deny/log src=10.42.118.31 dst=185.220.101.47 tcp/443; commit above allow policies
- **expected result:** New C2 sessions denied
- **observed result:** SIMULATED: policy committed and test connection denied
- **deviation notes:** VLAN change could alter source IP; verify endpoint identity and rule scope
- **source:** simulated firewall policy audit (exercise assumption; no authentic execution artifact supplied)

### Step 5 — 2026-04-14T03:18:30Z
- **timestamp (UTC):** `2026-04-14T03:18:30Z`
- **actor:** SOC network analyst
- **command or console action:** Query netflow/PCAP for WST-WS-031 -> 185.220.101.47:443 for 03:16:04–03:18:30Z; check capture coverage
- **expected result:** No successful post-isolation C2 sessions; denied attempts may appear
- **observed result:** SIMULATED: no successful egress flows after 03:16:04Z; collection coverage assumed
- **deviation notes:** Absence of flows alone is not proof unless sensor visibility verified
- **source:** simulated post-containment netflow (exercise assumption; no authentic execution artifact supplied)

### Step 6 — 2026-04-14T03:19:02Z
- **timestamp (UTC):** `2026-04-14T03:19:02Z`
- **actor:** EDR administrator
- **command or console action:** EDR console: enable device containment for WST-WS-031 with IR management exception
- **expected result:** Containment flag active; forensic access retained
- **observed result:** SIMULATED: device flagged contained and management exception enabled
- **deviation notes:** Only valid if platform supports isolation and does not override jumpbox access
- **source:** simulated EDR audit (exercise assumption; no authentic execution artifact supplied)

### Step 7 — 2026-04-14T03:22:04Z
- **timestamp (UTC):** `2026-04-14T03:22:04Z`
- **actor:** Network engineer / SOC analyst
- **command or console action:** From production user VLAN: TCP probe to 10.42.118.31 denied; from approved IR jumpbox: approved management port probe succeeds
- **expected result:** Only jumpbox permitted; normal workstation access blocked
- **observed result:** SIMULATED: user-VLAN probe denied, jumpbox management probe allowed
- **deviation notes:** ICMP ping alone is insufficient; use approved service and firewall logs
- **source:** simulated connectivity tests (exercise assumption; no authentic execution artifact supplied)

### Step 8 — 2026-04-14T03:23:00Z
- **timestamp (UTC):** `2026-04-14T03:23:00Z`
- **actor:** West Campus lab lead
- **command or console action:** Confirm alternate clinical workflow after WST-WS-031 quarantine
- **expected result:** No unmitigated clinical service interruption
- **observed result:** SIMULATED: lab work continued via approved alternate workflow
- **deviation notes:** No real clinical confirmation or spare workstation inventory supplied
- **source:** simulated clinical confirmation (exercise assumption; no authentic execution artifact supplied)

## Evidence validation and limitations

The original alert confirms pre-containment traffic to `185.220.101.47:443`, but **cannot establish that containment succeeded**. In an instrumented lab, retain switch port audit, firewall rule audit, EDR state-change event, post-change netflow/PCAP with sensor coverage, and two-origin jumpbox connectivity test. Store them under `/evidence/IR-2026-0414-01/network/` or `/endpoint_telemetry/`, calculate SHA-256, and reference hashes in `IR-2026-0414-01-hashes.txt`. No such artifacts or hashes were supplied; none are asserted as collected.

## Rollback

If quarantine disrupts critical clinical care, escalate to James Chen and clinical lead. Prefer approved alternate workstation or downtime procedure. Only with explicit authorization, restore the original switchport VLAN and ACL configuration while maintaining a narrower egress block and EDR monitoring; verify and document connectivity and new risks. Do not automatically reconnect a potentially compromised endpoint.

## Timeline integration

The following `ACTION` records are **simulated scenario entries**, not verified operational actions. They are appended to `incident_timeline.md` without changing earlier entries.
