# Filesystem Analysis: ART-001 (`wst-ws-031.dd`)

## Case and evidence scope

- **Case:** `LH-2026-0414-01` · **Incident:** `IR-2026-0414-01`
- **Examiner:** Pedro Cabral (exercise; appointment to be confirmed)
- **Source:** `wst-ws-031.dd`, acquired by Mike Torres using FTK Imager, 2026-04-14 04:51–06:14 UTC, after VLAN 999 isolation.
- **Status:** **PENDING DISK EXAMINATION.** The `.dd` image has not been provided here. Commands and expected fields below are an executable investigation plan, **not fabricated outputs**.
- **Acquisition limitations:** no acquisition-time SHA-256; incomplete chain of custody; source filesystem accessed read-write before imaging. See `acquisition_notes.md` and `chain_of_custody.md`.

## Artifact verification and custody

| Check | Status / evidence |
|---|---|
| SHA-256 at analysis start | **PENDING** — copy the full 64-character verified value from `hashes.txt` and `verification_log.txt` |
| Hash matched baseline? | **NOT TESTED** — do not proceed until `verify_artifacts.sh` returns exit code 0 |
| Mounted read-only? | **NOT MOUNTED** — pending access to image; prefer TSK direct reads, optionally mount NTFS read-only |
| Chain of custody updated? | **PENDING** — append actual UTC time, actor, artifact, action, tool and hash verification to `chain_of_custody.md` |

**Pre-analysis procedure (Kali):**

```bash
cd /path/to/ir_dfir_playbook/5x02_evidence_trail
EVIDENCE_DIR=/absolute/path/to/evidence ACTOR="Pedro Cabral" ./verify_artifacts.sh
status=$?
if [ "$status" -ne 0 ]; then echo "STOP: evidence not verified (exit $status)"; exit 1; fi
# Record timestamp and verification in chain_of_custody.md before next access.
IMG=/absolute/path/to/evidence/wst-ws-031.dd
mkdir -p analysis_output exports
```

If the script creates `hashes.txt` for the first time, it returns `2` (`BASELINE_SET`). Run it again and require exit `0` before examining the image. Keep evidence immutable; write all outputs to a separate analysis directory.

## Original SOC detection context — not independently verified

The supplied `siem_alert_export.json` reports alert `A-20260414-9841` (fired `2026-04-14T02:47:11Z`), account `MEDDEFENSE\\dmarsh`, PowerShell PID 7812 at `02:46:41Z`, child `MSBuild.exe` PID 8104 at `02:46:57Z`, and command line `msbuild.exe C:\\Users\\dmarsh\\AppData\\Local\\Temp\\update.xml`. It also reports TCP/443 to `185.220.101.47`. **These are SIEM claims only.** The acquisition notes report that Mike Torres saw `update.xml` on the source filesystem, but did not independently preserve/hash that file. Disk findings must confirm or refute its presence and contents.

## Partition layout

```bash
mmls "$IMG" | tee analysis_output/mmls_output.txt
```

**Actual `mmls` output:** PENDING. Identify the main NTFS partition by partition type, sector start and length. **Do not assume offset `2048`:** that number in the task is illustrative.

| Partition | Start sector | End sector | Length (sectors) | Type | Notes |
|---|---|---|---|---|---|
| PENDING | PENDING | PENDING | PENDING | PENDING | Main NTFS volume to be identified |

**NTFS sector offset used:** `PENDING` (sector count, not byte offset). For mounting, byte offset = start sector × sector size shown by `mmls`/disk geometry (commonly 512, verify).

## Read-only mounting

TSK commands (`mmls`, `fsstat`, `fls`, `icat`) operate directly on the image **without a mount**, reducing unnecessary writes. The task also requires a read-only mount. Once the NTFS start sector and logical sector size are confirmed, perform the following on a **working copy** using the appropriate NTFS driver:

```bash
sudo mkdir -p /mnt/wst-ws-031-ro
# Set these only after reviewing mmls and disk geometry:
OFFSET_SECTORS=<actual_ntfs_start_sector>
SECTOR_BYTES=<actual_sector_size>
BYTE_OFFSET=$((OFFSET_SECTORS * SECTOR_BYTES))
sudo mount -t ntfs-3g -o ro,loop,offset="$BYTE_OFFSET" "$IMG" /mnt/wst-ws-031-ro
findmnt /mnt/wst-ws-031-ro -o SOURCE,FSTYPE,OPTIONS
# When finished:
sudo umount /mnt/wst-ws-031-ro
```

**Mount result / UTC timestamp:** PENDING. Confirm `ro` in `findmnt`, document any errors, and append the actual access to CoC. If mounting fails, stop and document; do not retry read-write. `ntfs-3g` and loop-mount support must be installed. Do not execute the placeholder assignments literally.

## Filesystem metadata

```bash
fsstat -o "$OFFSET_SECTORS" "$IMG" | tee analysis_output/fsstat_output.txt
```

**Actual `fsstat` output:** PENDING.

| Field | Observed value |
|---|---|
| Filesystem type | PENDING |
| Volume serial number | PENDING |
| Sector size / cluster size | PENDING |
| MFT details | PENDING |
| Last mount time (if available) | PENDING / not necessarily exposed by `fsstat` |

**Caution:** `fsstat` output varies by filesystem and TSK version. If last mount time is not shown, record **not available in fsstat**, not an invented value.

## Recursive file listing and MAC timeline

```bash
# File listing with inode / metadata references and flags (not a mactime body file):
fls -r -o "$OFFSET_SECTORS" "$IMG" > analysis_output/fls_output.txt

# Proper mactime body-file format: -m prefixes paths; -r includes deleted entries where possible.
fls -r -m C:/ -o "$OFFSET_SECTORS" "$IMG" > analysis_output/fls_body.txt

# CSV MAC timeline, UTC. Set TZ to UTC explicitly.
TZ=UTC mactime -b analysis_output/fls_body.txt -d > analysis_output/mac_timeline.csv

# Optional: focus on relevant files and Windows directories.
grep -Ei 'update\.xml|AppData/Local/Temp|Windows/System32/Tasks|Windows/Recent|Windows/History' analysis_output/fls_output.txt > analysis_output/target_paths.txt
```

**Outputs:** PENDING. **Critical correction:** `fls -r ... > fls_output.txt` produces a listing, **not** the body-file format that `mactime -b` expects. Run `fls -r -m C:/ ...` to generate `fls_body.txt` for `mactime`. Verify the resulting timeline and timestamp convention before interpreting it.

**MACB interpretation:** `M` content modified; `A` accessed; `C` metadata changed (not created); `B` born/created. NTFS `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps may differ; timestamps can be altered, delayed, or unreliable. A file's timestamps do not independently prove execution.

## Paths to examine

| Windows path | Purpose | Examination status |
|---|---|---|
| `C:\\Users\\dmarsh\\AppData\\Local\\Temp\\` | Staging files, `update.xml`, dropped payloads | PENDING |
| `C:\\Windows\\System32\\Tasks\\` | Scheduled-task definitions and persistence | PENDING |
| `C:\\Users\\dmarsh\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\` | `.lnk` shortcuts and recently accessed targets | PENDING |
| `C:\\Users\\dmarsh\\AppData\\Local\\Microsoft\\Windows\\History\\` | Legacy history artifacts, if present | PENDING |

Modern browser histories may instead be found in browser-specific SQLite databases (e.g. Edge/Chrome `User Data/.../History`). Absence of the legacy History directory does not imply no browsing.

For every suspicious path: identify the inode/MFT entry from `fls_output.txt`, inspect metadata, export content and hash the **exported file**, documenting the association with its source inode:

```bash
# Replace the placeholder with the exact metadata address reported by fls.
INODE=<actual_inode>
istat -o "$OFFSET_SECTORS" "$IMG" "$INODE" | tee "analysis_output/istat_${INODE}.txt"
icat -o "$OFFSET_SECTORS" "$IMG" "$INODE" > "exports/artifact_${INODE}.bin"
wc -c < "exports/artifact_${INODE}.bin"
sha256sum "exports/artifact_${INODE}.bin"
file "exports/artifact_${INODE}.bin"
```

Record export path, original NTFS path, inode, size, SHA-256, MACB timestamps and CoC access event. Treat suspicious files as untrusted; **do not execute** exported payloads. For deleted files, `icat -r` may be appropriate if recovery is supported; distinguish recovered bytes from a complete verified file.

## Key findings (evidence-controlled)

### ART-001-F01 — Suspected MSBuild staging file `update.xml`

- **Claim/source:** SIEM process tree points to `C:\\Users\\dmarsh\\AppData\\Local\\Temp\\update.xml`; acquisition notes say Torres observed the filename before imaging.
- **Disk confirmation:** PENDING.
- **MFT inode:** PENDING.
- **Created / Modified / Accessed / Metadata changed (UTC):** PENDING.
- **Size (bytes):** PENDING.
- **Extracted-file SHA-256:** PENDING.
- **Content / forensic significance:** PENDING. An MSBuild project can execute inline tasks, but **Base64-encoded C# shellcode is not established** by the supplied evidence. Inspect the actual XML before making that claim.
- **Correlation target:** SIEM `MSBuild.exe` event at `2026-04-14T02:46:57Z`; execution requires independent corroboration from memory or other execution artifacts.

### ART-001-F02 — Possible second-stage dropped payload

- **Path / inode / timestamps / size / SHA-256:** PENDING; no confirmed disk evidence supplied.
- **Forensic significance:** Investigate new executables, scripts and suspicious writes near the incident window. Do not assert a dropped payload until found.

### ART-001-F03 — Possible scheduled-task persistence

- **Path / inode / timestamps / size / SHA-256:** PENDING; no confirmed disk evidence supplied.
- **Forensic significance:** Inspect task XML, action commands, triggers and creation times; correlate with registry and event logs. Do not assert persistence without evidence.

### ART-001-F04 — Recent items / browser history

- **Path / inode / timestamps / size / SHA-256:** PENDING.
- **Forensic significance:** Extract and parse LNK files and browser databases with suitable parsers, recording their provenance. Do not equate a shortcut's existence with a user deliberately opening a malicious file.

## Working evidence table — complete after examination

| Finding ID | Full NTFS path | Inode | Created UTC | Modified UTC | Accessed UTC | Metadata changed UTC | Size (bytes) | SHA-256 | Significance / corroboration |
|---|---|---|---|---|---|---|---|---|---|
| ART-001-F01 | `C:\\Users\\dmarsh\\AppData\\Local\\Temp\\update.xml` (SIEM-reported) | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | Unverified staging candidate |
| ART-001-F02 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | Potential second-stage payload |
| ART-001-F03 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | Potential scheduled-task persistence |
| ART-001-F04 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | LNK / browser history candidate |

## Timeline correlation and limitations

| UTC time | Source | Event | Evidentiary status |
|---|---|---|---|
| 2026-04-13 18:14:02 | SIEM correlated proxy event | Reported visit to phishing-lookalike URL | SOC context only |
| 2026-04-14 02:46:41 | SIEM EDR event | `powershell.exe` PID 7812 created | SOC context only |
| 2026-04-14 02:46:57 | SIEM EDR event | `MSBuild.exe` PID 8104 created | SOC context only |
| 2026-04-14 02:47:11 | SIEM alert | Alert fired | SOC context only |
| 2026-04-14 04:51–06:14 | Acquisition notes | Disk image acquired | Documented in notes, no acquisition hash |
| PENDING | NTFS/MFT timeline | File creation/modification/access evidence | Not yet examined |

**Assessment:** no disk-based attack reconstruction can be concluded until the image is verified and examined. The pre-imaging read-write source mount may affect timestamps; document this caveat in any final chronology.

## Audit trail / append-only follow-up

Append each actual image read, mount, `mmls`, `fsstat`, `fls`, `icat`, export and hash operation to `chain_of_custody.md` with UTC time, actor, artifact ID, action, tool, verification status and notes. Preserve command output files and their SHA-256 hashes. Never retroactively claim an unperformed command was executed.

## References

- `acquisition_notes.md` — Mike Torres, 2026-04-14.
- `siem_alert_export.json` — SOC alert export, 2026-04-14T02:58:04Z.
- `chain_of_custody.md` — case evidence register.
- `hashes.txt` and `verification_log.txt` — **pending** local verification.
