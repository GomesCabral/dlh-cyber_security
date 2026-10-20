# Correlated Incident Timeline: LH-2026-0414-01

**Incident:** `IR-2026-0414-01`  
**Case:** `LH-2026-0414-01`  
**Time standard:** UTC, ISO 8601 (`Z`)  
**Status:** **PARTIAL CORRELATION — supplementary logs reviewed; disk and memory images unavailable.**  
**Analyst:** Pedro Cabral (training exercise; appointment/actual custody not verified)

## Methodology and evidentiary boundaries

This timeline correlates `proxy_log.jsonl`, `ad_auth_log.jsonl`, and `siem_alert_export.json` with the **pending** findings registers in `filesystem_analysis.md` (Task 3), `persistence_analysis.md` (Task 4), and `memory_analysis.md` (Task 5). Those prior reports document investigation plans and leads, **not completed examinations** of `wst-ws-031.dd`, `wst-ws-031.mem`, or `wst-ws-017.mem`. No Volatility/TSK result, hash, Run-key, scheduled task, memory injection, or LSASS compromise is established here.

- **confirmed** = the cited source explicitly records the *narrowly described* event (e.g., a successful logon or proxy request), **not** a confirmed malicious attribution.
- **probable** = supported interpretation of correlated records, not yet independently proven.
- **possible** = hypothesis or missing artifact-based verification. Where no timestamp exists, use `unknown` rather than invent a time.
- **Evidence references:** `PROXY-Lnn` = 1-based physical line of `proxy_log.jsonl`; `AUTH-Lnn` = 1-based physical line of `ad_auth_log.jsonl`; `SIEM-Lnn` = physical line of `siem_alert_export.json`. `ART-001-Fxx`, `ART-001-Rxx`, `ART-001-Exx`, `ART-002-Mxx`, `ART-003-Mxx` are **pending finding IDs**, not verified proof. Log-source IDs are local analytical identifiers, not original evidence acquisition IDs.
- **ATT&CK mappings** are hypotheses/classifications and do not independently establish malicious intent.

## Correlated timeline

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
|---|---|---|---|---|---|
| 2026-04-13T18:13:44Z | Proxy | `dmarsh` session requests an Outlook message; context preceding suspicious redirect. | — | confirmed | `PROXY-L06` |
| 2026-04-13T18:14:02Z | Proxy | Browser requests typosquat `/auth` URL with Outlook message as referer; phishing-link navigation. | T1566.002 | confirmed | `PROXY-L07`; `SIEM-L36` |
| 2026-04-13T18:14:41Z | Proxy | POST to typosquat `/auth/submit` with `form_submission=true`; **contents of form, including credentials, not visible**. | T1056.003 (hypothesis) | confirmed | `PROXY-L10` |
| 2026-04-13T18:14:41Z | Azure AD | Successful Office 365 sign-in from `45.63.9.88`, flagged `impossibleTravel`, MFA reported complete; attacker attribution not proven. | T1078 (hypothesis) | confirmed | `AUTH-L03` |
| 2026-04-13T18:14:43Z | Proxy | `update.zip` requested with HTTP 200 and `download=true`; payload content and actual disk placement unverified. | T1105 (hypothesis) | confirmed | `PROXY-L11`; pending `ART-001-F02` |
| 2026-04-14T02:44:02Z | AD | Successful Kerberos AS request on `WST-WS-031`, unusual hour for user. | T1078 (hypothesis) | confirmed | `AUTH-L05` |
| 2026-04-14T02:44:03Z | AD | Interactive logon type 2 for `dmarsh` on `WST-WS-031`. | T1078 (hypothesis) | confirmed | `AUTH-L06` |
| 2026-04-14T02:44:17Z | VPN | Successful VPN logon for `dmarsh` from `45.63.9.88`, MFA reported complete; unauthorized operator not independently identified. | T1133 / T1078 (hypotheses) | confirmed | `AUTH-L07` |
| 2026-04-14T02:46:41Z | SIEM/EDR export | `powershell.exe` PID 7812 created with `-ep bypass -w hidden -enc` in command line; full encoded argument truncated in export. | T1059.001 | confirmed | `SIEM-L29`, `SIEM-L37`; pending `ART-002-M01` |
| 2026-04-14T02:46:57Z | SIEM/EDR export | `MSBuild.exe` PID 8104 spawned with PPID 7812 and `Temp\update.xml` command-line argument; disk contents and memory process tree not verified. | T1127.001 | confirmed | `SIEM-L30`, `SIEM-L38`; pending `ART-001-F01`, `ART-002-M01` |
| 2026-04-14T02:46:58Z | Proxy | First recorded CONNECT from `WST-WS-031`/PID 8104 to `185.220.101.47:443`; **C2 interpretation probable**, traffic contents unknown. | T1071.001 (hypothesis) | confirmed | `PROXY-L12`; `SIEM-L32-L33`; pending `ART-002-M02` |
| 2026-04-14T02:47:02Z | Proxy | Repeated CONNECT to same remote endpoint, attributed to `MSBuild.exe` PID 8104. | T1071.001 (hypothesis) | confirmed | `PROXY-L13` |
| 2026-04-14T02:47:11Z | SIEM | High-severity alert `A-20260414-9841` fired on PowerShell → MSBuild chain. | T1059.001 / T1127.001 | confirmed | `SIEM-L07-L14` |
| 2026-04-14T02:47:30Z | Proxy | Further CONNECT to same endpoint; recurring network activity consistent with possible beaconing, not packet-level proof. | T1071.001 (hypothesis) | confirmed | `PROXY-L14` |
| 2026-04-14T03:22:47Z | AD | Successful Kerberos TGS request for `cifs/WST-WS-017` from `WST-WS-031`. | T1021.002 (hypothesis) | confirmed | `AUTH-L08` |
| 2026-04-14T03:22:48Z | AD | Successful TGS request for `host/WST-WS-017` from `WST-WS-031`. | T1021 (hypothesis) | confirmed | `AUTH-L09` |
| 2026-04-14T03:23:01Z | AD | Successful Kerberos network logon (type 3) on `WST-WS-017` from `10.42.118.31`; malicious lateral movement remains probable, not independently proven. | T1021.002 (hypothesis) | confirmed | `AUTH-L10`; pending `ART-003-M01` |
| 2026-04-14T03:27:13Z | Proxy | First recorded CONNECT from `WST-WS-017`/`MSBuild.exe` PID 5108 to `91.234.99.107:443`, reputation `c2_infrastructure`; second suspected beacon. | T1071.001 (hypothesis) | confirmed | `PROXY-L15`; pending `ART-003-M02` |
| 2026-04-14T03:27:45Z | Proxy | Second CONNECT from `WST-WS-017` to same remote endpoint. | T1071.001 (hypothesis) | confirmed | `PROXY-L16` |
| 2026-04-14T03:40:18Z | AD | Successful TGS request for `cifs/LIS-WSIDE-01` from `WST-WS-017`. | T1021.002 (hypothesis) | confirmed | `AUTH-L11` |
| 2026-04-14T03:41:52Z | AD | Repeated TGS request for same service, note `second_request_with_ticket_reuse`; does **not** prove ticket theft. | T1021.002 (hypothesis) | confirmed | `AUTH-L12` |
| 2026-04-14T03:42:08Z | AD | Successful network logon type 3 to `LIS-WSIDE-01` from `WST-WS-017`. | T1021.002 (hypothesis) | confirmed | `AUTH-L13` |
| 2026-04-14T03:43:30Z | File-server audit | Event 4663 records successful access to 14 PDF files in `LIS_REPORTS$`, path `C:\LIS\reports\daily\*.pdf`; **no evidence here of exfiltration or contents read in full**. | T1005 / T1039 (hypotheses) | confirmed | `AUTH-L14` |
| unknown | Disk image (not examined) | `update.xml` and possible second-stage payload physically dropped in `AppData\Local\Temp`: **unverified**, no MAC times or SHA-256. | T1105 (hypothesis) | possible | pending `ART-001-F01`, `ART-001-F02` |
| unknown | Registry / disk (not examined) | Scheduled-task and Run-key persistence installed: **not established**, no keys, task XML or last-write times. | T1053.005 / T1547.001 (hypotheses) | possible | pending `ART-001-F03`, `ART-001-R01`, `ART-001-R03` |
| unknown | Memory (not examined) | NTLM hashes or Kerberos ticket material accessible in `lsass.exe`: **not established**; a dump or handle alone would not prove attacker access. | T1003.001 / T1558 (hypotheses) | possible | pending `ART-002-M04` (placeholder only) |

## Coverage of the 14 mandatory scenario events

| # | Requested event | Evidence-based status |
|---|---|---|
| 1 | Credential phishing link clicked | **Confirmed navigation** at 2026-04-13T18:14:02Z (`PROXY-L07`); a physical mouse click is inferred from referer, not directly recorded. |
| 2 | Credentials submitted | **Form POST confirmed** at 18:14:41Z (`PROXY-L10`); exact credential fields and values **not confirmed**. |
| 3 | Attacker VPN access | **VPN logon confirmed** at 2026-04-14T02:44:17Z (`AUTH-L07`); attacker identity/authorization **unverified**. |
| 4 | Encoded PowerShell | **SIEM/EDR-recorded** at 02:46:41Z (`SIEM-L29`, `SIEM-L37`); memory corroboration pending. |
| 5 | MSBuild child / C2 starts | **Child process reported** 02:46:57Z; **first proxy CONNECT** 02:46:58Z (`SIEM-L30`, `SIEM-L38`, `PROXY-L12`); C2 attribution probable. |
| 6 | Files dropped in Temp | **Not established by disk**; `update.zip` download request and `update.xml` process argument are leads only (`PROXY-L11`, `SIEM-L30`). |
| 7 | Scheduled task and Run key | **Not established**; Task 4 has no actual hive or task XML findings. |
| 8 | NTLM and Kerberos material in LSASS | **Not established**; no memory results or observed credential-access behavior. |
| 9 | TGS for `cifs/WST-WS-017` | **Confirmed log record**, 03:22:47Z (`AUTH-L08`). |
| 10 | Logon to `WST-WS-017` | **Confirmed log record**, 03:23:01Z (`AUTH-L10`); malicious lateral movement probable. |
| 11 | Second C2 beacon | **Proxy connections confirmed**, 03:27:13Z and 03:27:45Z (`PROXY-L15-L16`); C2 attribution probable. |
| 12 | TGS for `cifs/LIS-WSIDE-01` | **Confirmed log record**, 03:40:18Z (`AUTH-L11`), repeat 03:41:52Z (`AUTH-L12`). |
| 13 | Logon to `LIS-WSIDE-01` | **Confirmed log record**, 03:42:08Z (`AUTH-L13`). |
| 14 | 14 patient lab PDFs read | **File access event confirmed**, 03:43:30Z (`AUTH-L14`), `files_opened=14`; patient identity and exfiltration not established. |

## Interpretation and working hypothesis

The records support a plausible sequence of phishing-page navigation and form submission, suspicious cloud/VPN authentication, PowerShell→MSBuild execution, network connections to reputation-tagged infrastructure, Kerberos service requests and network logons across `WST-WS-031` → `WST-WS-017` → `LIS-WSIDE-01`, followed by audited access to 14 laboratory report PDFs. **This is a correlated investigative hypothesis, not an end-to-end proof of one operator or of all requested persistence/credential-theft mechanisms.** The Azure AD sign-in and proxy POST share a timestamp but have distinct log origins and no shared transaction ID.

### Source acquisition caveat

`siem_alert_export.json` reports an export time of `2026-04-14T02:58:04Z`, which is **earlier than** the `wst-ws-031.mem` acquisition at 03:02Z; the memory image cannot be inferred from that SIEM export. The `wst-ws-017.mem` acquisition at 03:38Z precedes the later `LIS-WSIDE-01` activity at 03:40–03:43Z, so this memory snapshot cannot itself contain those later events. Preserve the temporal boundaries of each source.

## Outstanding forensic actions

1. Obtain `wst-ws-031.dd`, `wst-ws-031.mem`, `wst-ws-017.mem`; establish and verify SHA-256 baselines, document actual custody and access.
2. **Task 3:** inspect `Temp\update.xml`, any downloaded/dropped payloads and NTFS MACB times; replace pending `ART-001-Fxx` IDs only with actual findings.
3. **Task 4:** inspect `NTUSER.DAT` Run/RunOnce, task XML, UserAssist, ShimCache, Amcache and LNK; record precise values, hashes and timestamps. Do not presume persistence.
4. **Task 5:** run `pslist`, `pstree`, `cmdline`, `netscan`, `malfind`, `dlllist`, `handles`, `hashdump` as appropriate, preserving full output; confirm process and socket associations and evaluate possible credential access without publishing recovered secrets.
5. Validate log clock synchronization and identify the raw authentication/session records; review the phishing POST payload if legally available, audit trail for 14 files, SMB/file server events, and any exfiltration indicators.
6. When verified findings are available, insert actual artifact IDs, finding IDs and acquisition-consistent timestamps; retain original rows and add dated corrections rather than silently rewriting historical evidence.

## Reproducible commands for supplementary logs

```bash
# Inspect the source data without changing it.
jq -c 'select(.url? | strings | contains("login-verification.click"))' proxy_log.jsonl
jq -c 'select(.event == "vpn_logon" or .event == "kerberos_tgs_req" or .event == "logon_network" or .event == "object_access")' ad_auth_log.jsonl
jq '.alert | {fired_at, process_tree, network, correlated_events}' siem_alert_export.json

# Chronological raw-log view (preserves original file separately).
{ jq -c '{ts, source:"proxy", data:.}' proxy_log.jsonl; \
  jq -c '{ts, source:(.source // "auth"), data:.}' ad_auth_log.jsonl; } \
  | jq -sc 'sort_by(.ts) | .[]'
```

## Audit note

This report was authored from the provided supplementary logs and pre-existing Task 3–5 draft reports. No `.dd` or `.mem` image was available for execution; no new image-access event or hash-verification success is claimed. The investigator must append real access events to `chain_of_custody.md` when the artifacts are obtained.
