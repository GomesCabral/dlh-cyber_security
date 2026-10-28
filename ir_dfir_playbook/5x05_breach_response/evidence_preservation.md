# Evidence Preservation: IR-2026-0420-01

**Classification:** Internal — Incident Response / Exercise  
**Prepared by:** Pedro Cabral, acting on-call IR Analyst (simulation)  
**Incident declared:** 2026-04-20T19:52:00Z (simulated; see `ir_activation.md`)  
**Record status:** Acquisition plan plus one source-reported acquisition. No new captures, hashes, transfers, or verification steps are represented as completed.

## 1. Scope, operating rules, and source limitations

Five systems are in scope: `CS-WS-101`, `CS-WS-104`, `CS-WS-107`, `CS-WS-112`, and `FILE-SVR-01`. The assignment's reference to “four hosts” is superseded by its explicit five-host list. The first memory acquisition has already been reported by Mike Torres; the **remaining four hosts** require new volatile captures. `SCHED-SVR-01` is an additional potentially affected scheduling server reported by Torres but is **not one of the five mandated systems**; request separate scoping and preservation authorization rather than silently excluding its telemetry.

**Preserve before destructive containment wherever patient safety permits.** Coordinate multiple acquisition operators in parallel; the sequence below is a *priority order for scarce capture resources*, not an instruction to wait for one host to finish before beginning the next. If active encryption or immediate clinical harm makes delay unsafe, authorize proportionate containment immediately, record the decision, and explicitly record which volatile evidence could be lost. Do not execute suspicious binaries, disable security controls, or log on interactively to affected endpoints unless authorized and documented. Use a trusted incident-response collection medium or isolated acquisition channel; record tool versions, operator, start/end time (UTC), destination, SHA-256, and handoffs.

**Evidence status:** The transcript supports the `CS-WS-101` memory capture at 19:38Z and its write to the evidence share at 19:41Z, but explicitly states **no acquisition hash was computed**. The Sysmon and file-server files supplied are *condensed samples*, not full raw forensic acquisitions. The provided data cannot substantiate the current beacon state of every host at 19:52Z; investigate live telemetry before treating a host as quiet.

## 2. Priority order and parallel acquisition rationale

| Order | Host | Acquisition priority and reason | Initial capture focus |
|---|---|---|---|
| Existing / P0 | `CS-WS-101` (`WS-101`) | Initial compromised clinical coordinator workstation; Torres captured volatile memory at **19:38Z**, before the call. Potential credential material, running payload and staged ransomware make its memory highly time-sensitive; **verify existing image first**. | Preserve and hash existing RAM image; acquire disk before disruptive remediation where safe. |
| P1 | `CS-WS-104` (`WS-104`) | Sysmon sample shows `WinHealthSvc` creation and outbound connection to `45.152.66.114:443`. Active process state and credentials may disappear on isolation. | RAM, network/process state, EDR/Sysmon exports; disk second. |
| P1 (parallel) | `CS-WS-107` (`WS-107`) | Sysmon sample shows outbound traffic from suspicious `svchost32.exe`; same volatile C2 and credential risks as WS-104. | RAM, network/process state, EDR/Sysmon exports; disk second. |
| P2 (parallel if staff available) | `FILE-SVR-01` | Patient documentation access is high-impact; preserve audit logs and file metadata immediately. **Important:** the Sysmon sample also shows suspicious `svchost32.exe` process creation on this server, so it must **not** be assumed clean or without an active implant. Prioritize its RAM capture alongside P1 if live telemetry confirms ongoing activity. | RAM if process active; Windows Security logs, access logs, file metadata, disk/snapshot. |
| P3 (start in parallel if possible) | `CS-WS-112` (`WS-112`) | Lateral compromise indicators and historical outbound connection exist. Lower *provisional* priority only because current active beaconing is unconfirmed, **not** because the host is known inactive. Reprioritize immediately if live activity or encryption is seen. | RAM, network/process state, service configuration, logs; disk. |

**Basis:** `torres_call_transcript.md` (19:43–19:52Z handoff), `sysmon_multihost.sample.jsonl` (historical service/network events), and `fileserver_access.sample.json` (file-server access window). Historical Sysmon connections on WS-112 are present; a claim of “no current beacon” is not established by these samples.

## 3. Acquisition workflow (authorized, trusted responder workstation)

Perform the following on **each system**, adjusting host-specific paths and artifact IDs. Commands below are reproducible examples; they are **not execution evidence**. Collect memory *before* running broad live-response commands where feasible. The exact WinPmem executable and flags depend on the installed version; verify `winpmem.exe --help` and record the version before running.

### A. Memory capture — volatile evidence

From an approved administrator console on the target, using a trusted collection drive (`E:` is an example):

```powershell
# Run from an elevated, approved IR session; adapt binary syntax to installed version.
& 'E:\IRTools\winpmem.exe' --help
# Example for versions supporting this syntax:
& 'E:\IRTools\winpmem.exe' -o 'E:\Evidence\<HOST>.raw'

# Record hash immediately after the file has been closed:
Get-FileHash -Algorithm SHA256 'E:\Evidence\<HOST>.raw' |
  Format-List Algorithm,Hash,Path
```

If the installed WinPmem version uses a different output flag or produces AFF4 rather than raw memory, use its documented syntax and record the resulting format. Do not overwrite Torres's `cs-ws-101.mem` or re-label a new capture as the original. If capture could jeopardize patient care, escalate the trade-off to the incident commander and clinical lead.

### B. Live state and event logs — collect promptly after RAM

```powershell
$h = $env:COMPUTERNAME
$dest = "E:\Evidence\$h"
New-Item -ItemType Directory -Force $dest | Out-Null
Get-Date -Format o | Out-File "$dest\collection_time.txt"
Get-Process | Select-Object Id,ProcessName,Path,StartTime -ErrorAction SilentlyContinue |
  Export-Csv "$dest\processes.csv" -NoTypeInformation
Get-NetTCPConnection | Export-Csv "$dest\tcp_connections.csv" -NoTypeInformation
Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName |
  Export-Csv "$dest\services.csv" -NoTypeInformation
wevtutil epl Security "$dest\Security.evtx"
wevtutil epl System "$dest\System.evtx"
wevtutil epl 'Microsoft-Windows-Sysmon/Operational' "$dest\Sysmon.evtx"
```

If a log is absent, inaccessible, or collection fails, record the error; do not imply success. Collect SIEM/EDR exports separately with query, time window, export timestamp, and source identifiers. These commands can change host state; record that footprint in the acquisition log.

### C. Non-volatile disk / filesystem preservation

Use **FTK Imager** (or an approved equivalent) from a trusted IR workstation to acquire a **physical disk image** where feasible: select the correct source disk, use E01 or raw (`.dd`), enable acquisition verification, and record source disk serial/size, sector count, image segments, destination, start/end UTC, operator, and tool version. Capture to controlled evidence storage with sufficient space; use a hardware write blocker when acquiring removed media. If live imaging is necessary, document that the disk can change during collection and record any VSS/snapshot identifier. Never mistake an ordinary file copy for a forensic disk image.

Hash the completed acquisition and re-hash after transfer:

```powershell
Get-FileHash -Algorithm SHA256 'E:\Evidence\<HOST>.dd' | Format-List
Get-FileHash -Algorithm SHA256 '\\evidence\share\IR-2026-0420-01\<HOST>.dd' | Format-List
# Record both complete digests; PASS only when values match exactly.
```

For segmented E01, use the forensic tool's image verification report and hash manifest for all segments rather than claiming a single `.dd` exists. Store evidence read-only with restricted access, preserve original filenames, and perform analysis on verified working copies.

## 4. Host-specific acquisition instructions

### ART-001 — `cs-ws-101.mem` (`CS-WS-101`, pre-existing)

- **Acquired by:** Mike Torres, Network Engineer (reported).
- **Captured at:** `2026-04-20T19:38:00Z` (reported approximate minute); **written at:** `2026-04-20T19:41:00Z` (handoff note).
- **Tool:** WinPmem (exact version and flags not recorded).
- **Original location:** `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem`.
- **Acquisition hash:** **NOT RECORDED**. This is an evidence-handling deficiency; a later hash cannot retroactively prove integrity at acquisition.
- **Analyst verification (pending):** At first controlled access, calculate `Get-FileHash -Algorithm SHA256` on the original and on the analysis copy, record exact UTC times, identities and values, and compare. Record any access/transfer logs. Do **not** invent a digest or mark integrity verified before computation.
- **Timing note:** 19:38Z capture to 19:41Z write = **3 minutes**; 19:38Z capture to 19:43:18Z call start = **5 min 18 sec**; capture to simulated 19:52Z declaration = **14 minutes**. These are different intervals and must not be conflated.
- **Custody:** Torres → controlled evidence share (reported, 19:41Z) → analyst access **pending**; obtain Torres's acquisition metadata and access-control logs. The transcript was reviewed and signed off by Torres at 21:10Z, but that does not supply the missing acquisition hash.

**Integrity command (run on authorized evidence storage):**

```powershell
Get-FileHash -Algorithm SHA256 '\\evidence\share\IR-2026-0420-01\cs-ws-101.mem' |
  Format-List Algorithm,Hash,Path
```

### ART-002 — `cs-ws-101.dd` (`CS-WS-101`, planned)

- **Priority:** P0 for disk after verifying ART-001; coordinate with clinical team because the endpoint is at the emergency-department charge desk.
- **Capture:** FTK Imager physical disk image from trusted acquisition environment, ideally before isolation if clinically safe; record whether live or offline, tool version, disk identifiers, and imaging start/end.
- **Hash/verification:** Tool's source/image verification plus SHA-256 of image after acquisition and after transfer; values **PENDING**.
- **Custody:** operator and exact time **PENDING**; restricted evidence repository; working copy only for analysis.

### ART-003 — `cs-ws-104.mem` and ART-004 — `cs-ws-104.dd` (`CS-WS-104`, planned)

- **Priority:** P1. Historical Sysmon sample shows suspicious service creation and outbound connection (`45.152.66.114:443`); capture RAM first to retain process/network/credential state.
- **Capture:** WinPmem with version-verified syntax; process, TCP, service and Sysmon exports; FTK Imager disk image after volatile capture.
- **Hash/verification:** SHA-256 at capture completion and after transfer, separately for RAM and disk; values **PENDING**.
- **Custody:** named operator, start/end UTC, source/target path, hash and handoff **PENDING**.

### ART-005 — `cs-ws-107.mem` and ART-006 — `cs-ws-107.dd` (`CS-WS-107`, planned)

- **Priority:** P1, in parallel with WS-104. Historical Sysmon sample shows `svchost32.exe` connecting to `45.152.66.114:443`.
- **Capture:** WinPmem RAM; live process/network/service state; Sysmon and Windows logs; FTK Imager disk image.
- **Hash/verification:** SHA-256 after acquisition and transfer for each artifact; values **PENDING**.
- **Custody:** operator/times/handoffs **PENDING**.

### ART-007 — `file-svr-01.mem`, ART-008 — `file-svr-01.dd`, ART-009 — `file-svr-01-security.evtx` (`FILE-SVR-01`, planned)

- **Priority:** P2, **escalate to P1** if suspicious process still running or encryption active. Patient documentation is sensitive and historical sample shows `svchost32.exe` on the server; do not treat the server as merely a passive log source.
- **Capture:** WinPmem RAM where safe; export original Security.evtx (`wevtutil epl Security ...`) and Sysmon logs, file metadata and storage snapshot; FTK Imager/snapshot-based disk acquisition with consistency limitations recorded. Coordinate with clinical and infrastructure owners before any action affecting file access.
- **Specific records:** Preserve Event ID 4663 object-access logs, associated Event ID 4624 logon and 4634 logoff records, `MEDDEFENSE\jdoe`, logon ID `0xAF12C4B8`, and relevant access window `2026-04-19T02:14:01Z`–`02:41:12Z`. The condensed sample reports **1,847 read events**, not proof of exfiltration or necessarily 1,847 unique patients.
- **Hash/verification:** SHA-256 of original exported EVTX, memory and disk artifacts; verify copies after transfer; **PENDING**.
- **Custody:** operator/times/handoffs **PENDING**. Sample JSON is supporting lead material, **not** a substitute for original EVTX.

### ART-010 — `cs-ws-112.mem` and ART-011 — `cs-ws-112.dd` (`CS-WS-112`, planned)

- **Priority:** P3 provisional; start in parallel if operators available. Sysmon sample contains historical outbound connection from suspicious executable; absence of *current* beacon activity is not established.
- **Capture:** WinPmem RAM; process/network/service state; Windows/Sysmon exports; FTK Imager disk image.
- **Hash/verification:** SHA-256 after acquisition and transfer, **PENDING**.
- **Custody:** operator/times/handoffs **PENDING**.

## 5. Integrity, handling, and chain-of-custody policy

1. Assign unique artifact IDs and label source host, evidence type, collection tool/version, collector, UTC start/end, path, and original media ID.
2. Calculate SHA-256 immediately on the completed artifact and record the **actual 64-character digest**. Hash the transferred copy independently; compare byte-for-byte digest values and record PASS/FAIL. Do not label missing hashes as PASS.
3. Log every transfer/access (from, to, UTC time, reason, method, storage location, integrity check); protect originals from modification and analyze verified copies.
4. If integrity cannot be established back to acquisition (as with ART-001), state that limitation and corroborate with tool logs, transfer logs, and other telemetry. Do not conceal the chain-of-custody gap.
5. Append real collection events to `incident_timeline.md` with `EVIDENCE` type and accurate `CONFIRMED`/`REPORTED`/`SIMULATED` certainty. **Do not backdate simulated events as completed actions.**

## 6. Chain of custody — all five hosts

`PENDING` means an acquisition or verification has **not** been demonstrated by supplied evidence. Planned evidence IDs are reserved, not proof of creation.

| Host | Artifact ID(s) | Evidence | Collector | Acquisition / transfer UTC | Original / destination | SHA-256 at acquisition | Verification / custody status |
|---|---|---|---|---|---|---|---|
| `CS-WS-101` | ART-001 | `cs-ws-101.mem` | Mike Torres (reported) | Captured **19:38Z**; written **19:41Z**, 2026-04-20 | `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem` | **NOT RECORDED** | First analyst hash/copy comparison **PENDING**; original-acquisition integrity gap documented |
| `CS-WS-101` | ART-002 | Disk image | Assigned forensic collector (TBD) | PENDING | Restricted evidence store (TBD) | PENDING | Not yet acquired |
| `CS-WS-104` | ART-003 / ART-004 | RAM / disk | Assigned collector (TBD) | PENDING | Restricted evidence store (TBD) | PENDING | Not yet acquired |
| `CS-WS-107` | ART-005 / ART-006 | RAM / disk | Assigned collector (TBD) | PENDING | Restricted evidence store (TBD) | PENDING | Not yet acquired |
| `FILE-SVR-01` | ART-007 / ART-008 / ART-009 | RAM / disk / Security EVTX | Assigned collector (TBD) | PENDING | Restricted evidence store (TBD) | PENDING | Not yet acquired; preserve original EVTX |
| `CS-WS-112` | ART-010 / ART-011 | RAM / disk | Assigned collector (TBD) | PENDING | Restricted evidence store (TBD) | PENDING | Not yet acquired |

## 7. Source references

- `torres_call_transcript.md`: 19:43:18–19:47:40Z call and 19:52Z handoff; memory acquisition 19:38Z, write 19:41Z, no initial hash.
- `sysmon_multihost.sample.jsonl`: historical malicious service, process and network indicators on workstations and file server; sample is not live-state verification.
- `fileserver_access.sample.json`: condensed Windows Security Event 4663 access summary and associated logon events; original EVTX remains to be collected.
- `ir_activation.md` and `incident_timeline.md`: simulated incident declaration at 19:52Z and first three timeline entries.
