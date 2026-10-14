# Containment Execution: IR-2026-0414-01

## Status and evidence boundary

- **Incident:** `IR-2026-0414-01` — SEV2
- **Endpoint:** `WST-WS-031` (`10.42.118.31`), `MEDDEFENSE\dmarsh`
- **Observed C2 destination:** `185.220.101.47:443` (alert `A-20260414-9841`)
- **Chosen strategy:** A — quarantine VLAN with access from the IR jumpbox only (`containment_decision.md`)
- **Execution status:** **NOT VERIFIED / PENDING**. The supplied materials establish suspicious activity, not completed containment. No switch, firewall, EDR console, netflow-after-change, packet capture, approval record, or live execution transcript was provided. **Do not treat any planned step below as an executed ACTION.**
- **Approval:** James Chen, IR Commander — **PENDING confirmation**.
- **Clinical impact check:** West Campus lab lead — **PENDING confirmation**.
- **Evidence preservation completion:** **PENDING verification** under `evidence_preservation.md`.
- **Timing:** All execution timestamps below must be the **actual UTC timestamps** recorded during a live or instrumented lab simulation. Do not reuse the illustrative 03:16–03:22 times from the task example as observations.

## Preconditions and operator handoff

1. Confirm approval by James Chen and clinical continuity arrangement; record approval evidence and UTC time.
2. Confirm that Task 2 volatile RAM, processes, and active connections were captured and hashed, or record why urgent patient-safety containment overrides acquisition.
3. Resolve the actual switch/interface for `WST-WS-031`, current VLAN, quarantine VLAN ID, IR jumpbox address, and EDR platform capabilities. **VLAN 999 is an exercise example, not a discovered configuration.**
4. Start change ticket and capture pre-change switch port/VLAN, ACL, firewall, EDR state, and network flow baseline. Use approved administrative consoles; never execute the example syntax against an unverified device.
5. Use one record per attempted step, including failed steps. Fill the actual timestamp, operator, exact console action/command, expected result, observed result, evidence path and deviation.

## Execution records — fill after each action, in order

### Step 1 — Network isolation: VLAN reassignment

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — authorized network engineer`
- **command or console action:** `PENDING — actual switch vendor, interface, and approved change command`. Illustrative *Cisco IOS-style* sequence **only after validating the device and interface**:

  ```text
  show interfaces status
  show interfaces switchport
  configure terminal
  interface <VERIFIED_WORKSTATION_PORT>
   switchport mode access
   switchport access vlan <APPROVED_QUARANTINE_VLAN>
  end
  show interfaces <VERIFIED_WORKSTATION_PORT> switchport
  ```

  Apply/verify quarantine ACL permitting only explicitly approved IR jumpbox forensic management traffic; deny other inbound and outbound paths. VLAN membership alone is **not** proof of isolation.
- **expected result:** Workstation has no production or internet connectivity; permitted forensic traffic from the IR jumpbox remains possible.
- **observed result:** `NOT OBSERVED — pending switch configuration/audit output and network tests`.
- **deviation notes:** `PENDING`; preserve original VLAN and ACL settings for controlled rollback.
- **execution evidence:** switch change/audit export to `/evidence/IR-2026-0414-01/network/` (create this subdirectory if absent), with SHA-256 in canonical manifest.

### Step 2 — Firewall egress block for observed destination

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — authorized firewall administrator`
- **command or console action:** `PENDING — actual firewall vendor and policy object`. In the approved firewall console, create/enable a **deny** rule matching `source=10.42.118.31`, `destination=185.220.101.47`, `service=TCP/443`, log denied traffic; ensure rule priority precedes permissive rules and deploy/commit policy. If endpoint source address changes in quarantine, use a host identity or both known IPs as appropriate. Preserve policy ID and change ticket.
- **expected result:** No allowed new egress sessions from this endpoint to `185.220.101.47:443`; denied attempts logged if they occur.
- **observed result:** `NOT OBSERVED — pending firewall policy/audit output`.
- **deviation notes:** `PENDING`; a deny rule is defense-in-depth and must not replace quarantine ACL validation.
- **execution evidence:** exported firewall rule/policy and audit log in `/evidence/IR-2026-0414-01/network/`, hashed.

### Step 3 — Verify that the observed outbound connection is severed

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — network/SOC analyst`
- **command or console action:** Export timestamped firewall sessions and network flow/packet capture for `10.42.118.31` (and the actual quarantine address, if changed) ↔ `185.220.101.47:443` covering **before and after** the policy change. Example analysis of an already captured pcap:

  ```bash
  tshark -r /evidence/IR-2026-0414-01/network/wst-ws-031_postcontainment.pcapng \
    -Y 'ip.addr==185.220.101.47 && tcp.port==443' \
    -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.flags
  ```

  Query firewall/session logs for `action=allow` and `action=deny` after the change, using the actual deployment time as the boundary. Collect from a trusted network sensor, **not** a newly established session from the compromised host.
- **expected result:** No new **allowed** flows/packets to the destination after the effective policy time; optionally logged deny events. Existing TCP sessions closed or expired.
- **observed result:** `NOT OBSERVED — no post-change pcap, netflow, or firewall logs supplied`.
- **deviation notes:** `PENDING`; a quiet pcap is not proof unless sensor placement, time range and visibility are validated. Record coverage gaps and any surviving sessions.
- **execution evidence:** timestamped pre/post flow logs, sensor metadata and pcap in `/evidence/IR-2026-0414-01/network/`, hashed.

### Step 4 — Endpoint containment flag (if supported)

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — authorized EDR analyst`
- **command or console action:** In the **actual** EDR console, select device `WST-WS-031`, use `Isolate device` / `Network contain` **only if the platform supports it and the action is approved**, then export the action/audit record. **Wazuh alerting alone does not establish an endpoint isolation feature**; if unsupported, record `NOT SUPPORTED` and rely on validated network controls.
- **expected result:** Device reports containment active, with permitted IR management path documented; no normal external traffic.
- **observed result:** `NOT OBSERVED — endpoint platform capability and console state unverified`.
- **deviation notes:** `PENDING`; avoid a second containment method that unexpectedly blocks the IR jumpbox.
- **execution evidence:** EDR device-state and audit export in `/evidence/IR-2026-0414-01/endpoint_telemetry/`, hashed.

### Step 5 — Verify jumpbox-only reachability

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — network/SOC analyst`
- **command or console action:** From the **approved IR jumpbox**, test the explicitly allowed management service on `WST-WS-031` (e.g. TCP/5986 only if WinRM HTTPS is enabled and authorized). From a separate **user VLAN test host**, attempt the *same* service. From a trusted network management sensor, check other inbound and outbound paths and ACL hit counters. Illustrative Linux test:

  ```bash
  nc -vz -w 3 <VERIFIED_WST_WS_031_IP> <APPROVED_IR_PORT>
  ```

  Run the command from both sources and retain the console outputs with UTC timestamps. A failed ping alone does not prove isolation because ICMP may already be blocked.
- **expected result:** Approved jumpbox service succeeds; identical test from user VLAN fails; all non-approved traffic denied.
- **observed result:** `NOT OBSERVED — no source-separated connectivity tests provided`.
- **deviation notes:** `PENDING`; if jumpbox access fails, assess the quarantine ACL without reconnecting the workstation to production by default.
- **execution evidence:** jumpbox and user-VLAN test transcripts, source addresses, ACL counters, and timestamps in `/evidence/IR-2026-0414-01/network/`, hashed.

### Step 6 — Clinical impact and containment handoff

- **timestamp (UTC):** `PENDING`
- **actor:** `PENDING — IR Commander / West Campus lab lead`
- **command or console action:** Confirm with the lab lead that LIS/patient workflows have a safe alternative, record any disruption, and hand over the quarantine status and rollback trigger to the IR Commander.
- **expected result:** Clinical continuity assessed and containment ownership confirmed.
- **observed result:** `NOT OBSERVED — no clinical confirmation or communication transcript supplied`.
- **deviation notes:** `PENDING`; escalate any patient-safety impact immediately.
- **execution evidence:** change ticket/communication record, with actual UTC time.

## Evidence integrity and audit checks

After collection, hash **each actual execution artifact** from the Linux evidence store; do not hash absent files or invent digest values. Example for a verified capture:

```bash
ROOT=/evidence/IR-2026-0414-01
MANIFEST="$ROOT/IR-2026-0414-01-hashes.txt"
mkdir -p "$ROOT/network"
# Run only after the actual capture exists and is closed:
(cd "$ROOT" && sha256sum network/wst-ws-031_postcontainment.pcapng) >> "$MANIFEST"
(cd "$ROOT" && sha256sum -c "$MANIFEST")
```

Record actual acquisition time, source, collector, tool, size, path, SHA-256, and transfer/custody details in `incident_timeline.md` once verified. A post-containment netflow gap must be supported by sensor visibility and a clear pre/post time boundary; absence of data by itself is not proof of containment.

## Incident timeline append-only integration

**Current status:** No Task 4 `ACTION` entries are appended yet because no executed actions or results were supplied. The Task 3 decision remains a **decision**, not an action. When each action is executed, append the corresponding entry below the existing timeline entries, using actual UTC timestamps and the verified evidence source:

```text
- <ACTUAL_UTC_TIMESTAMP> | ACTION | <NETWORK_ENGINEER> | Reassigned WST-WS-031 switchport <PORT> from VLAN <OLD> to quarantine VLAN <ID>; observed <VERIFIED_RESULT>. | source=containment_execution.md step 1 + <SWITCH_AUDIT_PATH> | certainty=confirmed
- <ACTUAL_UTC_TIMESTAMP> | ACTION | <FIREWALL_ADMIN> | Applied deny rule <RULE_ID> for WST-WS-031 -> 185.220.101.47:443; observed <VERIFIED_RESULT>. | source=containment_execution.md step 2 + <FIREWALL_AUDIT_PATH> | certainty=confirmed
- <ACTUAL_UTC_TIMESTAMP> | ACTION | <SOC_ANALYST> | Verified no allowed C2 flows in monitored window <START>–<END>; visibility <SENSOR_SCOPE>. | source=containment_execution.md step 3 + <FLOW_OR_PCAP_PATH> | certainty=confirmed
- <ACTUAL_UTC_TIMESTAMP> | ACTION | <EDR_ANALYST> | <EDR_CONTAINMENT_ACTION_OR_NOT_SUPPORTED>; observed <VERIFIED_RESULT>. | source=containment_execution.md step 4 + <EDR_AUDIT_PATH> | certainty=confirmed
- <ACTUAL_UTC_TIMESTAMP> | ACTION | <SOC_ANALYST> | Verified approved IR jumpbox access and denied user-VLAN access using <SERVICE_PORT>; observed <RESULTS>. | source=containment_execution.md step 5 + <TEST_TRANSCRIPTS> | certainty=confirmed
```

If a step fails, record the **attempt and failure**, not a successful result. Do not append the EDR entry if no action was performed; instead record unsupported capability as an `OBSERVATION` once verified. If any earlier timeline interpretation changes, append a new corrective entry referencing the old entry; never rewrite the original.

## Completion gate

Containment is **CONFIRMED** only when approval, switch/ACL change, firewall rule, network flow verification, permitted jumpbox access, denied user-VLAN access, and clinical handoff are documented with actual UTC times and supporting evidence. EDR containment flag is required only if the platform supports it and it is authorized. Until then, report **PENDING / NOT VERIFIED**, not `CONTAINED`.
