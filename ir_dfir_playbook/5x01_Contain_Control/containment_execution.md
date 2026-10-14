# Containment Execution: IR-2026-0414-01

**Endpoint:** WST-WS-031 (`10.42.118.31`)  
**Account:** `MEDDEFENSE\dmarsh`  
**Strategy:** A — Quarantine VLAN 999, IR jumpbox access only  
**Authority:** James Chen, IR Commander  
**Record type:** Lab scenario containment execution (based on the assignment's example)

## Execution Record

### 1. VLAN Reassignment

- **Timestamp (UTC):** 2026-04-14T03:16:04Z
- **Actor:** Network Operations
- **Command or console action:** Reassign the switchport serving WST-WS-031 to quarantine VLAN 999; apply isolation policy allowing authorized IR jumpbox access only.
- **Expected result:** Workstation isolated from production networks, while forensic access from the IR jumpbox remains available.
- **Observed result:** The assignment scenario reports successful connectivity from the IR jumpbox and timeout from the production user VLAN.
- **Deviation notes:** None reported in the scenario.

### 2. Firewall Egress Block

- **Timestamp (UTC):** 2026-04-14T03:17:21Z
- **Actor:** Network Operations
- **Command or console action:** Configure and enable a firewall deny rule for outbound traffic from WST-WS-031 to `185.220.101.47` (TCP/443), with deny logging.
- **Expected result:** Prevent further outbound communication with the identified C2 destination.
- **Observed result:** The assignment scenario reports zero outbound packets to `185.220.101.47` after 03:17:21Z.
- **Deviation notes:** None reported in the scenario.

### 3. C2 Communication Verification

- **Timestamp (UTC):** 2026-04-14T03:17:21Z
- **Actor:** SOC Analyst — Pedro Cabral
- **Command or console action:** Review post-block NetFlow for WST-WS-031 (`10.42.118.31`) to `185.220.101.47:443`, comparing the period before and after firewall enforcement.
- **Expected result:** No successful outbound C2 communication following the block.
- **Observed result:** The assignment scenario describes a NetFlow gap starting at 03:17:21Z, with zero subsequent packets to the destination.
- **Deviation notes:** No separate NetFlow export or packet-capture identifier was supplied.

### 4. Endpoint Containment Flag

- **Timestamp (UTC):** 2026-04-14T03:19:02Z
- **Actor:** Endpoint Security Analyst
- **Command or console action:** Set the WST-WS-031 device containment flag to `SET` in the endpoint security console, preserving authorized IR access.
- **Expected result:** Restrict endpoint communication to approved analyst tooling.
- **Observed result:** The assignment scenario reports containment flag `SET` in the endpoint console.
- **Deviation notes:** None reported in the scenario.

### 5. Isolation Verification

- **Timestamp (UTC):** 2026-04-14T03:22:04Z
- **Actor:** SOC Analyst — Pedro Cabral
- **Command or console action:** Test connectivity to WST-WS-031 from both the production user VLAN and the approved IR jumpbox.
- **Expected result:** Production user VLAN connectivity fails; IR jumpbox connectivity succeeds.
- **Observed result:** The assignment scenario reports timeout from the user VLAN and successful ping from the IR jumpbox.
- **Deviation notes:** None reported in the scenario.

## Containment Outcome

Within the **assignment's example execution scenario**, the workstation is placed in quarantine VLAN 999, outbound communication to `185.220.101.47` is blocked, post-change NetFlow reports no further C2 packets, the endpoint containment flag is set, and connectivity is limited to the IR jumpbox. These outcomes meet the intended containment checks in the lab narrative.

**Evidence limitation:** The timestamps and reported outcomes above originate from the example in the task instructions. Independent switch, firewall, EDR, NetFlow, and jumpbox test artifacts were not provided. This is a *lab scenario record*, not evidence that these operations were performed against a live MedDefense endpoint. Actual verification would require the relevant console audit exports, packet/flow records, and operator logs.

**Timeline:** The five scenario actions are cross-referenced in `incident_timeline.md`. Earlier entries are retained under the append-only rule.
