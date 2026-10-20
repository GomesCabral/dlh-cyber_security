# Memory Analysis: ART-002 (`wst-ws-031.mem`) and ART-003 (`wst-ws-017.mem`)

**Case:** LH-2026-0414-01  
**Incident:** IR-2026-0414-01  
**Status:** **PENDING — memory images not supplied; no Volatility commands have been executed on evidence**  
**Investigator:** Pedro Cabral (confirm operator identity before recording access)  
**Method:** Volatility 3, read-only forensic examination; all times UTC.

> **Evidence classification:** Entries labelled **SOC lead** originate from `siem_alert_export.json` and are NOT memory-confirmed. **Expected/illustrative** text describes what to look for, not observed output. Never promote a SOC lead to a confirmed memory finding without an actual plugin result.

## 1. Artifact verification and custody

| Artifact | Filename | Acquisition (UTC) | Tool | Acquisition hash | Baseline / verification | CoC |
|---|---|---|---|---|---|---|
| ART-002 | `wst-ws-031.mem` | 2026-04-14 03:02Z | WinPmem v3.3-rc3 | Not recorded | PENDING — image unavailable | PENDING |
| ART-003 | `wst-ws-017.mem` | 2026-04-14 03:38Z | WinPmem (version not independently recorded for this host) | Not recorded | PENDING — image unavailable | PENDING |

Acquisition notes indicate that ART-002 was taken while the host was live and beaconing; ART-003 was captured before isolation. No acquisition-time SHA-256 hashes were taken, and the original custody trail has gaps. A first-access baseline cannot establish integrity retrospectively back to acquisition.

**Before each session:** execute `./verify_artifacts.sh` with `EVIDENCE_DIR` set to the real evidence location. Proceed **only** if all three artifacts pass and the script exits `0`. Record the exact SHA-256, UTC timestamp, actor, verification log reference, source path, and action in `chain_of_custody.md`. Do not claim verification if any image is missing. Analyze copies where feasible, keep originals access-controlled, and never commit raw memory or credential material to GitHub.

```bash
# Replace this example directory with the real evidence directory.
EVIDENCE_DIR='/path/to/evidence' ACTOR="$(id -un)" ./verify_artifacts.sh
printf 'Verifier exit code: %s\n' "$?"
# Run Volatility only if exit code is 0 and custody entry has been recorded.
```

**Verified SHA-256 ART-002:** PENDING  
**Verified SHA-256 ART-003:** PENDING  
**CoC entries updated:** NO — no actual access/verification performed.

## 2. Analysis setup

From the directory containing verified evidence files, confirm Volatility 3 availability and record its version:

```bash
vol --help
vol -f wst-ws-031.mem windows.info.Info
vol -f wst-ws-017.mem windows.info.Info
```

`windows.info.Info` is a preparatory validation command. Record Windows version, kernel and symbol resolution errors. On some installations the executable is `vol.py` or `python3 vol.py`, not `vol`. Keep complete raw output in an access-controlled working directory; place only relevant excerpts and hashes of exported evidence in this report.

## 3. ART-002 — `wst-ws-031.mem`

### ART-002-M01 — Process inventory (`PsList`)

**Exact command:**
```bash
vol -f wst-ws-031.mem windows.pslist.PsList
```
**Relevant output:** PENDING. Capture `PID`, `PPID`, image name, create/exit times for `powershell.exe`, `MSBuild.exe`, `lsass.exe` and relevant parent processes.  
**SOC lead:** `powershell.exe` PID **7812**, `MSBuild.exe` PID **8104**, reported around 02:46Z.  
**Interpretation:** A matching Volatility process record would support process presence in the acquisition snapshot; process names alone do not establish maliciousness. Processes that terminated before capture might not appear in PsList.  
**Certainty:** possible (SOC-only). **ATT&CK candidate:** T1059.001 (PowerShell), T1127.001 (MSBuild), pending validation.

### ART-002-M02 — Parent-child relationship (`PsTree`)

**Exact command:**
```bash
vol -f wst-ws-031.mem windows.pstree.PsTree
```
**Relevant output:** PENDING. Find PID 7812 as parent of PID 8104, check process creation timestamps and whether the parent is still present.  
**SOC lead:** EDR reports `MSBuild.exe` PPID 7812.  
**Interpretation:** A matching tree corroborates the reported chain; a missing parent may reflect termination, memory acquisition timing or incomplete recovery, not necessarily a false alert.  
**Certainty:** possible (SOC-only). **ATT&CK candidate:** T1127.001.

### ART-002-M03 — Process command lines (`CmdLine`)

**Exact command:**
```bash
vol -f wst-ws-031.mem windows.cmdline.CmdLine
```
**Relevant output:** PENDING. Extract exact arguments for PIDs 7812 and 8104.  
**SOC lead:** PowerShell with `-ep bypass -w hidden -enc ...`; MSBuild references `C:\Users\dmarsh\AppData\Local\Temp\update.xml`. The SIEM's encoded string is truncated; do not infer a decoded payload.  
**Interpretation:** Recovered command lines could corroborate staging and execution context; command-line strings alone do not prove the XML contents or payload behavior.  
**Certainty:** possible (SOC-only). **ATT&CK candidate:** T1059.001 / T1127.001.

### ART-002-M04 — Network sockets (`NetScan`)

**Exact command:**
```bash
vol -f wst-ws-031.mem windows.netscan.NetScan
```
**Relevant output:** PENDING. Record protocol, local and remote addresses/ports, socket state, owning PID and timestamps.  
**SOC lead:** remote `185.220.101.47:443`, TCP ESTABLISHED; **owning PID and local endpoint not independently established**.  
**Interpretation:** If Volatility associates this remote endpoint with PID 8104, it strengthens the correlation; a socket alone cannot prove command-and-control or application-layer protocol. NetScan can recover closed/stale sockets as well.  
**Certainty:** possible (SOC-only). **ATT&CK candidate:** T1071.001 only if HTTP(S) use is established, otherwise network communication under investigation.

### ART-002-M05 — DLL inventory for MSBuild (`DllList`)

**Exact command (PID must be verified first):**
```bash
vol -f wst-ws-031.mem windows.dlllist.DllList --pid 8104
```
**Relevant output:** PENDING. Record DLL paths, bases and suspicious modules; compare with expected MSBuild/.NET modules.  
**Interpretation:** An unusual module can be a lead for side-loading or malicious code loading, but is not by itself proof.  
**Certainty:** possible (no observed finding). **ATT&CK:** unassigned pending evidence.

### ART-002-M06 — Suspicious executable regions (`Malfind`)

**Exact command:**
```bash
vol -f wst-ws-031.mem windows.malfind.Malfind
```
**Relevant output:** PENDING. Inspect results for PID 8104 and others; record start/end addresses, VAD protection, hex/ascii excerpts, and dump suspicious regions for offline analysis if warranted.  
**Interpretation:** Executable private memory, RWX permissions or an MZ header are indicators requiring validation; they do **not**, alone, confirm code injection. Correlate with VAD details, PE parsing, threads and other artifacts.  
**Certainty:** possible (no observed finding). **ATT&CK candidate:** T1055 only if supported by corroborating evidence.

### ART-002-M07 — LSASS handles (`Handles`)

**Exact command (replace PID with value from PsList):**
```bash
vol -f wst-ws-031.mem windows.handles.Handles --pid <lsass_pid>
```
**Relevant output:** PENDING. Record `lsass.exe` PID and relevant handle type, name, granted access when available.  
**Interpretation:** Handles **held by LSASS** do not by themselves show another process accessing LSASS. For suspected credential dumping, examine handles **to LSASS from other processes**, process access telemetry and related memory artifacts.  
**Certainty:** possible (no observed finding). **ATT&CK candidate:** T1003.001 only with supporting evidence.

### ART-002-M08 — Local credential hashes (`Hashdump`)

**Exact command:**
```bash
vol -f wst-ws-031.mem windows.hashdump.Hashdump
```
**Relevant output:** PENDING. Record whether extraction succeeded, relevant account names/identifiers, and **redacted** evidence references only. Store full output in a restricted evidence location, never in a public repository.  
**Interpretation:** Recovered local SAM NT hashes demonstrate recoverable credential material, **not** that an attacker accessed or stole it. `hashdump` is not a general LSA-secrets dump. Failure to extract is not proof credentials were absent.  
**Certainty:** possible (no observed finding). **ATT&CK candidate:** T1003.002 (SAM) only when attacker dumping activity is corroborated.

## 4. ART-003 — `wst-ws-017.mem`

### ART-003-M01 — Process list
```bash
vol -f wst-ws-017.mem windows.pslist.PsList
```
**Relevant output:** PENDING. Investigate anomalous processes, creation times and suspicious process relationships.  
**Interpretation:** Establish processes present at 03:38Z; compare against expected workstation baseline.  
**Certainty:** possible. **ATT&CK:** unassigned.

### ART-003-M02 — Network connections
```bash
vol -f wst-ws-017.mem windows.netscan.NetScan
```
**Relevant output:** PENDING. Search for connections to/from `WST-WS-031` and unusual external destinations; record owning PIDs.  
**Interpretation:** Correlate with AD logon events; network connectivity alone is not proof of lateral movement.  
**Certainty:** possible. **ATT&CK candidate:** T1021 only with corroborated remote-service activity.

### ART-003-M03 — Command lines
```bash
vol -f wst-ws-017.mem windows.cmdline.CmdLine
```
**Relevant output:** PENDING. Look for remote execution tools, PowerShell, unusual commands and service launch arguments.  
**Interpretation:** A suspicious command can support lateral movement or follow-on execution when combined with authentication and process evidence.  
**Certainty:** possible. **ATT&CK:** unassigned pending findings.

**Related lead outside memory:** AD authentication records should be correlated with this host, but those records are not Volatility output and cannot be used to label the memory findings confirmed.

## 5. Evidence handling and analyst worksheet

For **every** plugin, record:

| Artifact | Finding ID | Command | UTC execution time | Relevant verbatim output | PID/PPID | Interpretation | Certainty | ATT&CK | Raw-output reference |
|---|---|---|---|---|---|---|---|---|---|
| ART-002 | M01–M08 | See above | PENDING | PENDING | PENDING | PENDING | possible | provisional | PENDING |
| ART-003 | M01–M03 | See above | PENDING | PENDING | PENDING | PENDING | possible | provisional | PENDING |

Use **confirmed** only for a directly observed, correctly interpreted fact in the memory artifact; **probable** for strongly supported but incomplete conclusions; **possible** for leads needing corroboration. Distinguish *fact confirmed* (e.g. socket observed) from *malicious interpretation* (e.g. C2), which may remain probable.

Suggested safe capture workflow (after verification and CoC update):

```bash
mkdir -p memory_output
vol -f wst-ws-031.mem windows.pslist.PsList > memory_output/art002_pslist.txt 2>&1
vol -f wst-ws-031.mem windows.pstree.PsTree > memory_output/art002_pstree.txt 2>&1
vol -f wst-ws-031.mem windows.cmdline.CmdLine > memory_output/art002_cmdline.txt 2>&1
vol -f wst-ws-031.mem windows.netscan.NetScan > memory_output/art002_netscan.txt 2>&1
vol -f wst-ws-031.mem windows.dlllist.DllList --pid 8104 > memory_output/art002_dlllist_8104.txt 2>&1
vol -f wst-ws-031.mem windows.malfind.Malfind > memory_output/art002_malfind.txt 2>&1
# Replace <lsass_pid> after examining the actual process list.
vol -f wst-ws-031.mem windows.handles.Handles --pid <lsass_pid> > memory_output/art002_lsass_handles.txt 2>&1
vol -f wst-ws-031.mem windows.hashdump.Hashdump > memory_output/art002_hashdump_RESTRICTED.txt 2>&1
vol -f wst-ws-017.mem windows.pslist.PsList > memory_output/art003_pslist.txt 2>&1
vol -f wst-ws-017.mem windows.netscan.NetScan > memory_output/art003_netscan.txt 2>&1
vol -f wst-ws-017.mem windows.cmdline.CmdLine > memory_output/art003_cmdline.txt 2>&1
```

**Do not execute the entire block blindly:** `<lsass_pid>` is a placeholder; verify PID 8104 is truly MSBuild in memory before filtering; command availability and plugin options vary by Volatility version. Outputs, particularly hashdump and cmdline, may contain secrets. Keep restricted outputs out of Git (`.gitignore` and access controls). Hash and register exported evidence and record each analysis action in the append-only CoC.

## 6. Preliminary synthesis and outstanding questions

- **SOC lead:** PowerShell PID 7812 reportedly launched MSBuild PID 8104 and `update.xml`. **Memory confirmation: pending.**
- **SOC lead:** Network connection to `185.220.101.47:443`. **Process ownership and C2 classification: pending.**
- **Code injection:** no Volatility output available; **not confirmed**.
- **Credential access/theft:** no Volatility output available; **not confirmed**.
- **WST-WS-017 lateral movement:** investigate process/network evidence alongside AD authentication; **not confirmed from memory**.

**Next steps:** obtain the two original memory images from an authorized evidence store, verify all artifact hashes, log custody, run the listed plugins, preserve verbatim outputs, then replace PENDING sections with evidence-backed findings and justified certainty ratings.
