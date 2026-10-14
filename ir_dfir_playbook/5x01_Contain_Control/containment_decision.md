# Containment Decision: IR-2026-0414-01

## Incident context

- Incident: `IR-2026-0414-01` (SEV2)
- Affected asset: `WST-WS-031`, high-criticality clinical workstation, account `MEDDEFENSE\dmarsh`
- Trigger: alert `A-20260414-9841`, `2026-04-14T02:47:11Z`, rule `wz-edr-100041`
- Observed: `powershell.exe` (PID 7812) spawned `msbuild.exe` (PID 8104), which established TCP/443 to `185.220.101.47` (enriched as a Tor exit relay).
- Confidence boundary: suspicious execution and network connection are observed; data exfiltration, persistence and wider compromise are **not** established by this alert alone.
- Decision status: **SIMULATED selection / PENDING operational authorization and execution**. No real isolation, power-off, process kill or clinical failover is asserted.

## Candidate strategies

### A. Network isolation — quarantine VLAN (preferred)

- **Action:** Following preservation of volatile evidence when clinically safe, move `WST-WS-031` to an approved quarantine VLAN (illustrative VLAN `999`); deny normal inbound/outbound traffic, permitting only explicitly approved forensic access from the IR jumpbox. Verify policy from the jumpbox and network logs. Quarantine VLAN number and ACLs require validation with network operations.
- **Effect on attacker:** Cuts off the observed external C2 path and most lateral movement, though malicious processes may continue running locally; isolation is not eradication.
- **Effect on evidence:** RAM, process state and on-disk artifacts remain available; the move alters live connection state, so capture memory, process tree and net connections first if feasible. Preserve network-device change logs.
- **Effect on patient care:** Normal LIS/network access from this workstation is interrupted; coordinate with the West Campus lab lead and verify an alternative workstation or downtime workflow. The exercise example mentions four spare workstations, but availability is **not confirmed** in the supplied evidence.
- **Time to execute:** Approximately 5 minutes after authorization and network readiness (estimate, not measured).
- **Reversibility:** High: restore approved VLAN/ACL configuration after explicit authorization; does not reverse any missed volatile evidence.

### B. Host power-off

- **Action:** Shut down or forcibly power off `WST-WS-031` through an authorized local or remote administrative channel.
- **Effect on attacker:** Stops currently running code and external connections immediately; does not eliminate disk-based persistence or stolen credentials.
- **Effect on evidence:** Destructive to volatile memory, live processes and connections; a graceful shutdown may modify disk state. Use only for imminent harm or when less destructive containment is impossible.
- **Effect on patient care:** Workstation becomes unusable; lab workflow must transfer to an alternative or approved downtime procedure.
- **Time to execute:** Approximately 1–2 minutes (estimate, depends on access).
- **Reversibility:** Power can be restored, but lost RAM/live state cannot be recovered.

### C. Selective process termination + firewall egress block

- **Action:** After capturing volatile evidence, block `185.220.101.47:443` and other confirmed malicious destinations through managed host/network firewall policy; terminate the verified malicious `msbuild.exe` and parent `powershell.exe` process tree under change control. Validate that blocking does not affect clinical applications.
- **Effect on attacker:** Interrupts the known connection and processes, but other payloads, alternate destinations, credentials or persistence may remain active.
- **Effect on evidence:** Killed processes lose their volatile memory and handles; capture memory, process metadata and network connections first. Firewall rule changes alter network observations.
- **Effect on patient care:** Potentially less disruptive than full isolation; however, ending the wrong process or blocking a shared destination may disrupt clinical workflows.
- **Time to execute:** Approximately 3–10 minutes including validation (estimate).
- **Reversibility:** Firewall rules can be removed; terminated process state cannot be restored.

## Chosen strategy: A — Network isolation (quarantine VLAN)

**Rationale:** Quarantine offers the strongest balance between interrupting the observed outbound connection and retaining the workstation's RAM, running processes and disk artifacts for subsequent forensic analysis, while remaining reversible if lab operations are disrupted. Option B is faster but irreversibly destroys volatile evidence; Option C is less disruptive initially but risks missing other malicious processes or persistence and also destroys process state when terminating processes. Because this is a clinical workstation, execute Option A only after confirming the operational impact and a safe clinical workaround with the lab lead, and after prioritized volatile acquisition unless patient-safety urgency requires immediate isolation.

## Execution window — Task 2 to Task 4

- **Evidence preservation completion (Task 2):** `PENDING — actual UTC time not supplied`; Task 2 is a runbook, not proof of completed acquisitions.
- **Containment execution start (Task 4):** `PENDING — record actual UTC time after approval and execution`.
- **Elapsed window:** `PENDING = containment_start_utc - preservation_end_utc`; do not invent a measured interval.
- **Target operational handoff:** Begin containment immediately after essential volatile capture and clinical approval; minimize the gap, monitor the alert and destination during any delay, and escalate if active harm requires faster containment.
- **Evidence to capture before the change, if safe:** memory image, process tree/PIDs/command lines, active network connections, EDR and SIEM export; hash and record acquisitions per `evidence_preservation.md`.
- **Execution proof required:** change ticket, approving authority/time, switch/EDR policy audit log, isolation verification, clinical impact check and actual UTC timestamps.

## Approval

- **Approving authority:** **James Chen, IR Commander (SOC Lead)**, subject to clinical operational coordination and local authorization policy.
- **Approval status:** `PENDING`; no approval timestamp or authorization message is present in the supplied evidence.
- **Clinical coordination:** West Campus lab lead / clinical operations must confirm workstation role and contingency arrangements before the network change when feasible.
- **Executor:** Authorized network/endpoint operations engineer; record name, change ticket and execution time in `incident_timeline.md`.

## Rollback plan

1. **Trigger:** Quarantine causes unacceptable clinical impact, and approved alternatives or downtime procedures are inadequate.
2. **Escalate:** Inform James Chen and the clinical lead; obtain explicit approval to change containment. Do **not** automatically reconnect a potentially compromised workstation to the production network.
3. **Preferred mitigation:** Move clinical work to a verified clean spare workstation or approved downtime process while retaining quarantine.
4. **Controlled fallback, only if approved:** Apply Option C's narrowly scoped egress blocks and enhanced EDR monitoring, verify coverage, then restore the original VLAN/ACL configuration through network operations. Do not remove containment before the alternative control is active.
5. **Validate and document:** Test clinical functionality, confirm the malicious destination remains blocked, retain network change logs, and append `DECISION`, `ACTION` and `COMMUNICATION` entries with actual UTC times and evidence. Any reconnection risk must be explicitly accepted by the IR Commander and clinical authority.
- **Rollback target:** Restore approved network configuration within approximately 5 minutes *after authorization* if technically feasible; this is a planning target, not a guaranteed time.

## Sources and certainty

- `alert_A-20260414-9841.json`: observed process tree, endpoint criticality, network connection and alert time.
- `incident_timeline.md`: simulated declaration and previous decisions.
- `evidence_preservation.md`: planned acquisition sequence; **not** evidence of completed preservation.
- Task 3 instructions: candidate strategies and illustrative VLAN, timings and spare-workstation example. These are **planning assumptions**, not verified operational facts.

**Next action:** Task 4 must record the real/simulated execution event separately, with authorization and timestamps; do not represent this selection as a completed containment action.
