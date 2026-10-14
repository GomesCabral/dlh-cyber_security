# Evidence Preservation Runbook: IR-2026-0414-01

**Incident:** `IR-2026-0414-01`  
**Host:** `WST-WS-031` (`10.42.118.31`), clinical workstation, West Campus  
**Account:** `MEDDEFENSE\dmarsh`  
**Alert:** `A-20260414-9841`, fired `2026-04-14T02:47:11Z`  
**Evidence store:** `/evidence/IR-2026-0414-01/` (Linux collection host)  
**Hash algorithm:** SHA-256  
**Canonical manifest:** `/evidence/IR-2026-0414-01/IR-2026-0414-01-hashes.txt`  
**Responsible analyst:** on-call SOC analyst; record actual name, acquisition timestamps and authorizations in `incident_timeline.md`.

> **Status:** This is an executable *plan*, not proof that live acquisitions were performed. The provided lab exports are available, but no actual RAM image, live process/network snapshot, DNS export, or verified collection output was supplied. Do not record these as preserved until acquisition and hashing succeed. All timestamps in collection notes must be actual UTC timestamps, not simulated.

## 0. Preconditions and secure evidence store

1. Confirm incident authorization and assess patient-safety risk with the IR Commander/clinical lead. Do not delay urgent containment if active clinical harm is suspected; document any evidence that could not be collected.
2. Use a trusted Linux collection host and restricted evidence share, not the compromised workstation's local disk. Provision a dedicated, access-controlled SMB share mapped to `Z:` on `WST-WS-031`, with the share root corresponding to `/evidence/IR-2026-0414-01/`. **Share provisioning, credentials, winpmem installation, remote-access permissions and disk capacity are prerequisites; the lab does not provide them.** Never expose `/evidence` as a broadly writable share.
3. On the Linux collector, from the directory containing the supplied script:

```bash
bash evidence_store_init.sh
ROOT=/evidence/IR-2026-0414-01
cd "$ROOT" || exit 1
# The initializer creates hashes.txt; retain its custody header in the requested canonical manifest.
cp -n hashes.txt IR-2026-0414-01-hashes.txt
chmod 640 IR-2026-0414-01-hashes.txt
```

`evidence_store_init.sh` refuses to reinitialize an existing incident directory. If the directory already exists, **do not rerun or overwrite it**; inspect the existing manifest and continue under the incident custodian's direction. Its `hashes.txt` is an initializer artifact, not the requested per-artifact hash manifest. Retain both files, but add evidence hashes only to the canonical `IR-2026-0414-01-hashes.txt`.

4. Use this helper **from the Linux collector** after each artifact has fully arrived and is closed. Paths passed to it must be relative to `$ROOT` and must not contain newlines:

```bash
ROOT=/evidence/IR-2026-0414-01
MANIFEST="$ROOT/IR-2026-0414-01-hashes.txt"
record_hash() {
  local rel="$1"
  test -f "$ROOT/$rel" || { echo "Missing: $rel" >&2; return 1; }
  (cd "$ROOT" && sha256sum -- "$rel") >> "$MANIFEST"
}
```

Record in the timeline the UTC acquisition time, collector identity, source host, collection method, artifact path, SHA-256 and any errors. Never hash a partially transferred file. Keep originals read-only after capture; work on verified copies.

## 1. Volatile physical memory — FIRST live acquisition

- **What:** full RAM of `WST-WS-031`, including process memory, potential injected code and in-memory session artifacts.
- **How:** from an **elevated** trusted Windows shell on the host, with approved WinPmem binary already staged and `Z:` mapped to the secure evidence share:

```powershell
& 'C:\IRTools\winpmem_3.3.rc3.exe' -o 'Z:\memory\WST-WS-031_20260414.mem'
```

Confirm the installed WinPmem version supports this syntax (`--help`) before the incident; if it differs, use the documented equivalent. Do not claim success until the tool exits successfully and the destination file is complete. Capture console output and actual start/end times in the timeline. **Memory may contain PHI or secrets; restrict access.**
- **Where:** `/evidence/IR-2026-0414-01/memory/WST-WS-031_20260414.mem`.
- **Hash:** on Linux, `record_hash 'memory/WST-WS-031_20260414.mem'`. Windows cross-check if required: `certutil -hashfile Z:\memory\WST-WS-031_20260414.mem SHA256`.
- **Ordering:** before termination, reboot, shutdown or containment that would sever remote acquisition; RAM contents and volatile execution context can be lost. If clinical safety requires immediate isolation, document the deviation and use approved out-of-band/local collection where feasible.

## 2. Live processes with PID, PPID and command line

- **What:** running process snapshot including process name, PID, parent PID and command line. Specifically inspect `update.exe` (PID 7204), `powershell.exe` (PID 7812) and `MSBuild.exe` (PID 8104), as identified in the provided EDR history; do not assume these PIDs are still active.
- **How:** elevated PowerShell on `WST-WS-031`:

```powershell
Get-CimInstance Win32_Process |
  Select-Object Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath,CreationDate |
  ConvertTo-Json -Depth 4 |
  Set-Content -Encoding UTF8 'Z:\process_tree\WST-WS-031_processes.json'
```

- **Where:** `/evidence/IR-2026-0414-01/process_tree/WST-WS-031_processes.json`.
- **Hash:** `record_hash 'process_tree/WST-WS-031_processes.json'`.
- **Ordering:** before killing processes, logging off the user or rebooting; active process state and parent-child relationships may disappear. The command captures a snapshot, not the complete historical tree; preserve EDR separately.

## 3. Live network connections

- **What:** active TCP connections with local/remote addresses, ports, state and owning PID, plus UDP endpoints. Look for `185.220.101.47:443` without assuming every connection is malicious.
- **How:** elevated PowerShell on `WST-WS-031`:

```powershell
$network = [pscustomobject]@{
  captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
  tcp = @(Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess)
  udp = @(Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess)
}
$network | ConvertTo-Json -Depth 6 |
  Set-Content -Encoding UTF8 'Z:\network\WST-WS-031_connections.json'
```

- **Where:** `/evidence/IR-2026-0414-01/network/WST-WS-031_connections.json`.
- **Hash:** `record_hash 'network/WST-WS-031_connections.json'`.
- **Ordering:** before host isolation, firewall changes, connection termination or process kill; connections may disappear immediately. This snapshot does not capture packet payloads.

## 4. Full 24-hour endpoint telemetry

- **What:** original Wazuh EDR export for `WST-WS-031` over `[2026-04-13T02:47:11Z, 2026-04-14T02:47:11Z]`, including process, file, persistence and network events. Preserve the raw export without filtering or editing.
- **How (provided lab export, Linux collector):**

```bash
cp -- edr_wst_ws_031_24h.jsonl "$ROOT/endpoint_telemetry/WST-WS-031_edr_24h.jsonl"
record_hash 'endpoint_telemetry/WST-WS-031_edr_24h.jsonl'
```

Run the `cp` command from the directory holding the lab file (and after defining `ROOT` and `record_hash`). For a live environment, export the same UTC window through the authorized Wazuh/SIEM export interface; API URL, token and credentials are **not supplied**, so no working API invocation can be asserted.
- **Where:** `/evidence/IR-2026-0414-01/endpoint_telemetry/WST-WS-031_edr_24h.jsonl`.
- **Hash:** `record_hash 'endpoint_telemetry/WST-WS-031_edr_24h.jsonl'`.
- **Ordering:** after volatile snapshots but before EDR retention, cleanup, agent disconnection or log rotation. This log includes scheduled-task persistence, `update.exe`, PowerShell, MSBuild and an executable writable memory region.

## 5. Original SIEM/EDR alert

- **What:** complete JSON alert `A-20260414-9841`, including detection metadata, process tree, connection and enrichment.
- **How (provided lab export):**

```bash
cp -- alert_A-20260414-9841.json "$ROOT/siem/A-20260414-9841.json"
record_hash 'siem/A-20260414-9841.json'
```

- **Where:** `/evidence/IR-2026-0414-01/siem/A-20260414-9841.json`.
- **Hash:** `record_hash 'siem/A-20260414-9841.json'`.
- **Ordering:** preserve the raw detection before tuning rules, changing alert status or SIEM retention; avoid changing the source export.

## 6. Proxy and DNS history — 24 hours

- **What:** HTTP(S) proxy requests and DNS queries for `dmarsh` / `WST-WS-031` / `10.42.118.31` for `[2026-04-13T02:47:11Z, 2026-04-14T02:47:11Z]`.
- **How (provided proxy export):**

```bash
cp -- proxy_24h_dmarsh.log "$ROOT/proxy_dns/proxy_24h_dmarsh.log"
record_hash 'proxy_dns/proxy_24h_dmarsh.log'
```

- **How (DNS):** request a raw export from the organization's DNS logging platform using the same UTC window and identifiers; save it as `dns_24h_dmarsh.jsonl` **without transforming the source records**. A DNS file or DNS export API is **not provided** in the lab materials; therefore DNS capture is **PENDING**, not completed. After obtaining the export:

```bash
record_hash 'proxy_dns/dns_24h_dmarsh.jsonl'
```

- **Where:** `/evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log` and `/evidence/IR-2026-0414-01/proxy_dns/dns_24h_dmarsh.jsonl` (pending).
- **Hash:** SHA-256 using the commands above.
- **Ordering:** preserve before proxy/DNS retention rollover or account/session remediation; these records help trace the suspected phishing site, `update.zip` download and external connection. The provided proxy export was produced at `02:52:18Z`; do not backdate collection.

## 7. Authentication history — AD and Azure AD, 24 hours

- **What:** account sign-ins and domain authentication for `MEDDEFENSE\dmarsh` / `dmarsh@meddefense.local`, including AD DC01/DC02 and Azure AD, over `[2026-04-13T02:47:11Z, 2026-04-14T02:47:11Z]`.
- **How (provided combined export):**

```bash
cp -- auth_24h_dmarsh.json "$ROOT/authentication/auth_24h_dmarsh.json"
record_hash 'authentication/auth_24h_dmarsh.json'
```

- **Where:** `/evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json`.
- **Hash:** `record_hash 'authentication/auth_24h_dmarsh.json'`.
- **Ordering:** before credential resets, token/session revocation and retention expiry. Existing logs survive a reset, but preserving the pre-remediation view is important for investigating account misuse. The provided export includes both AD and Azure AD events; do not label it as two independent exports.

## 8. Verification, chain of custody and handoff

On the Linux collector, after **all available captures are complete**:

```bash
ROOT=/evidence/IR-2026-0414-01
cd "$ROOT" || exit 1
sha256sum -c IR-2026-0414-01-hashes.txt
```

Expected: every recorded artifact reports `OK`; command exits with code `0`. The manifest includes comment lines beginning with `#`, which `sha256sum -c` ignores. The manifest **must not contain its own hash**, because that would be self-referential.

To check which files were collected but omitted from the manifest:

```bash
find memory process_tree network endpoint_telemetry siem proxy_dns authentication \
  -type f -printf '%P\n' | sort
```

Compare this inventory with the manifest entries (taking directory prefixes into account). Record all missing expected artifacts, failed acquisitions, incomplete transfers and hash mismatches in `incident_timeline.md` as `OBSERVATION` entries; do not silently replace or overwrite originals. If an artifact changes, quarantine it, preserve the original manifest and open a chain-of-custody exception. Record collector, acquisition time, source system, tool/version, destination, access restrictions, SHA-256 and transfer details for every item.

**Containment gate:** confirm RAM and live snapshots are complete or explicitly waived by the authorized IR Commander; verify available evidence hashes; then execute the approved containment step. Never let this gate delay an urgent patient-safety action. The runbook itself does not authorize isolation, password reset, process termination or network blocking.

### Source and scope notes

- `evidence_store_init.sh` creates `memory/`, `disk/`, `process_tree/`, `network/`, `endpoint_telemetry/`, `siem/`, `proxy_dns/`, `authentication/`, `malware/`, `correlation/` and an initial `hashes.txt`.
- `alert_A-20260414-9841.json` records a high-criticality clinical endpoint, PowerShell PID 7812 spawning MSBuild PID 8104, and an established TCP connection to `185.220.101.47:443`.
- `edr_wst_ws_031_24h.jsonl` additionally records `update.zip`, `update.xml`, a scheduled task, `update.exe` PID 7204 and a suspicious MSBuild memory region. These are historical events, not live captures.
- `proxy_24h_dmarsh.log` records the suspicious sign-in page, POST and ZIP download; `auth_24h_dmarsh.json` contains AD and Azure AD events.
- No provided artifact proves that live memory, live process/network snapshots or DNS export have already been collected.
