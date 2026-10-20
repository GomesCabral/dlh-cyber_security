# Persistence Artifact Analysis: ART-001 (`wst-ws-031.dd`)

**Case:** LH-2026-0414-01  
**Incident:** IR-2026-0414-01  
**Lead investigator:** Pedro Cabral (training scenario; confirm actual assignment)  
**Host:** WST-WS-031 (Windows 10 Pro 22H2)  
**Evidence status:** **NOT EXAMINED — DISK IMAGE UNAVAILABLE**  
**Scope:** Offline Windows Registry, scheduled tasks, UserAssist, ShimCache, Amcache, and LNK artifacts.  

> **Evidence boundary:** The disk image `wst-ws-031.dd` was not supplied. No disk-derived persistence, registry value, hash, inode, last-write time, or execution timestamp has been verified. Any examples in the training appendix are **SIMULATED**, not findings. The SIEM export is a lead, not independent proof.

## 1. Artifact verification and chain of custody

| Requirement | Status / value |
|---|---|
| Artifact ID | ART-001 |
| Source image | `wst-ws-031.dd` |
| Acquisition | Mike Torres; FTK Imager; 2026-04-14 04:51–06:14 UTC |
| SHA-256 at acquisition | **Not calculated** |
| Baseline SHA-256 | **PENDING — image unavailable** |
| Hash at analysis start | **PENDING** |
| Baseline matches | **NOT VERIFIED** |
| Mounted read-only | **NO — no image available or mounted** |
| Chain-of-custody analysis entry | **NOT ADDED — no actual access occurred** |
| Litigation hold | LH-2026-0414-01, effective approximately 2026-04-14 07:30 UTC |

**Acquisition limitation:** The source filesystem was mounted read-write by the acquirer before imaging. Acquisition hashes and the original chain-of-custody record are absent. These issues must be preserved as deviations, not silently repaired.

**Before any real examination:**

```bash
# Execute from the evidence project directory, with EVIDENCE_DIR pointing to the actual image directory.
EVIDENCE_DIR=/path/to/evidence ACTOR='Pedro Cabral' ./verify_artifacts.sh
# First run establishes a baseline only; rerun to obtain PASS for all three.
EVIDENCE_DIR=/path/to/evidence ACTOR='Pedro Cabral' ./verify_artifacts.sh
# Do not proceed unless verification succeeds (exit status 0).
```

Record the actual UTC start time, operator, hash, read-only access method, tool, and any exported sections in `chain_of_custody.md`. Preserve the original image; analyze extracted working copies. A read-only TSK inspection can avoid mounting the image altogether. If mounting is required, use an appropriate read-only mechanism after identifying the NTFS partition and document it; do not assume a Linux ext4 `noload` option applies to NTFS.

## 2. Initial SOC context (not confirmed by disk)

`siem_alert_export.json` reports:

- Alert `A-20260414-9841`, fired **2026-04-14 02:47:11 UTC** on WST-WS-031.
- Parent `powershell.exe`, PID 7812, created **02:46:41 UTC**, with hidden/encoded command-line arguments.
- Child `MSBuild.exe`, PID 8104, created **02:46:57 UTC**, command line `msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml`.
- Remote connection indicator `185.220.101.47:443`.

**Working hypothesis:** Inspect `update.xml` and any associated executable, task, or Run key for persistence. **Do not claim persistence from this alert alone.**

## 3. Reproducible TSK extraction workflow (PENDING)

The commands below are a procedure to run when the actual image becomes available, **not a record of completed commands**.

```bash
IMG=/path/to/evidence/wst-ws-031.dd
mkdir -p extracted/{registry,tasks,lnk} outputs
mmls "$IMG" | tee outputs/mmls.txt
# Set the real start sector of the main NTFS partition from mmls.
OFFSET=<ACTUAL_NTFS_START_SECTOR>
fsstat -o "$OFFSET" "$IMG" | tee outputs/fsstat.txt
fls -r -p -o "$OFFSET" "$IMG" > outputs/fls_paths.txt
fls -r -m C:/ -o "$OFFSET" "$IMG" > outputs/fls_body.txt
TZ=UTC mactime -b outputs/fls_body.txt -d > outputs/mac_timeline.csv
```

`fls -r -p` includes paths in its listing; the `-m C:/` form generates a **body file** for `mactime`. Do not feed the ordinary listing to `mactime`.

Search for target files:

```bash
grep -Ei 'Users/dmarsh/NTUSER\.DAT|Windows/System32/config/SYSTEM|Windows/AppCompat/Programs/Amcache\.hve|Windows/System32/Tasks/|Users/dmarsh/AppData/Roaming/Microsoft/Windows/Recent/' outputs/fls_paths.txt
```

For each identified inode, inspect metadata and export bytes **without writing to the source image**:

```bash
istat -o "$OFFSET" "$IMG" <INODE> | tee outputs/istat_<ID>.txt
icat -o "$OFFSET" "$IMG" <INODE> > extracted/registry/<FILE_NAME>
sha256sum extracted/registry/<FILE_NAME> | tee -a outputs/extracted_sha256.txt
stat -c '%n %s bytes' extracted/registry/<FILE_NAME>
```

Repeat the `icat` export for scheduled-task XML files and `.lnk` files into their corresponding directories. Document each original full path, inode, extracted path, SHA-256, and actual extraction time in the chain of custody. Use `istat` for MACB timestamps, and distinguish the NTFS `$STANDARD_INFORMATION` and `$FILE_NAME` timestamp sources where relevant.

## 4. Registry persistence: Run and RunOnce

**User hive:** `C:\Users\dmarsh\NTUSER.DAT`  
**Keys:**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

For an offline hive, `HKCU` refers to the **dmarsh user hive**, not the current analyst's registry.

Example inspection using RegRipper, if installed:

```bash
rip.pl -r extracted/registry/NTUSER.DAT -p run
rip.pl -r extracted/registry/NTUSER.DAT -p runonce
```

Plugin names and availability vary by RegRipper version; confirm with its plugin list. A registry viewer such as `reglookup` can also be used to inspect the offline hive.

**Record for each value:** key path, value name, value data, data type, key last-write timestamp (UTC), linked executable/script, associated inode, hash, analyst assessment, and evidence ID. A key's last-write timestamp does **not** necessarily equal the creation time of an individual value.

### ART-001-R01 — HKCU Run key

- **Status:** NOT VERIFIED
- **Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value name / data:** Unknown
- **Last write:** Unknown
- **Significance:** Determine whether a logon autorun launches a suspicious binary, script, or LOLBin.
- **Evidence:** Pending offline `NTUSER.DAT` extraction and examination.

### ART-001-R02 — HKCU RunOnce key

- **Status:** NOT VERIFIED
- **Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- **Value name / data:** Unknown
- **Last write:** Unknown
- **Significance:** Determine whether a one-time logon command is configured; an absent value does not exclude previously consumed RunOnce entries.
- **Evidence:** Pending.

## 5. Scheduled task persistence

**Path:** `C:\Windows\System32\Tasks\` (including subdirectories). Search for task definitions whose actions execute PowerShell, MSBuild, scripts, or binaries in user-writable locations.

Inspect extracted task XML safely as data, never execute it:

```bash
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
for path in sorted(Path('extracted/tasks').rglob('*')):
    if not path.is_file():
        continue
    try:
        root = ET.parse(path).getroot()
        def vals(tag):
            return [e.text for e in root.iter() if e.tag.rsplit('}',1)[-1] == tag and e.text]
        print('FILE:', path)
        for tag in ('Command', 'Arguments', 'UserId', 'LogonType', 'RunLevel', 'StartBoundary', 'Enabled'):
            print(f'  {tag}: {vals(tag)}')
        print('  Trigger types:', [e.tag.rsplit('}',1)[-1] for e in root.iter() if e.tag.rsplit('}',1)[-1].endswith('Trigger')])
    except (ET.ParseError, OSError) as exc:
        print('PARSE ERROR:', path, exc)
PY
```

Also compare task files with the offline `SOFTWARE` hive TaskCache registry keys, if available, because on-disk XML and registered tasks can diverge.

### ART-001-R03 — Scheduled tasks

- **Status:** NOT VERIFIED
- **Task path / XML:** Unknown
- **Trigger / action / arguments / principal:** Unknown
- **Last write / SHA-256:** Unknown
- **Significance:** Assess task-based persistence, ATT&CK T1053.005.
- **Evidence:** Pending extraction and parsing.

## 6. Execution and activity artifacts (not automatically persistence)

### ART-001-E01 — UserAssist

- **Source:** `NTUSER.DAT`
- **Key:** `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`
- **Status:** NOT VERIFIED
- **Method:** Use a forensic parser supporting ROT13-decoded value names, run counts, and FILETIME last-run timestamps; record parser name/version. Example with RegRipper, if its `userassist` plugin is available:

```bash
rip.pl -r extracted/registry/NTUSER.DAT -p userassist
```

- **Interpretation:** UserAssist typically reflects Explorer-mediated user interaction. Absence of `MSBuild.exe` does not refute execution launched by PowerShell. Record decoded path, run count, last run (UTC), and the original registry value/key last write.

### ART-001-E02 — AppCompatCache / ShimCache

- **Source:** `C:\Windows\System32\config\SYSTEM`
- **Registry location:** `ControlSet00X\Control\Session Manager\AppCompatCache\AppCompatCache` (identify the relevant control set; inspect `Select`).
- **Status:** NOT VERIFIED
- **Method:** Use a Windows 10-compatible ShimCache parser and preserve original record order, file path, available timestamps, and parser/version. Some RegRipper installations include an `appcompatcache` plugin:

```bash
rip.pl -r extracted/registry/SYSTEM -p appcompatcache
```

- **Interpretation:** On Windows 10, ShimCache is **not reliable standalone proof of execution**. Timestamps often reflect file modification, not execution, and record order is not a trustworthy execution timeline. Correlate with Prefetch, Amcache, UserAssist, SRUM, event logs, and memory.

### ART-001-E03 — Amcache

- **Source:** `C:\Windows\AppCompat\Programs\Amcache.hve`
- **Status:** NOT VERIFIED
- **Method:** Parse with a version-appropriate Amcache tool (for example, AmcacheParser), preserving file path, program metadata, timestamps, and any SHA-1-derived value. Document tool/version and field semantics.
- **Interpretation:** Amcache may indicate file presence or program inventory. It does **not universally provide a first-execution timestamp**, and its hash fields may be partial or derived differently from a full-file SHA-1. Never label a timestamp 'first execution' without verifying its meaning for this OS and parser.

### ART-001-E04 — Recent LNK files

- **Source:** `C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\`
- **Status:** NOT VERIFIED
- **Method:** Extract `.lnk` files with `icat` and parse using a Shell Link-aware forensic tool (for example, LECmd or liblnk). Record target path, embedded target timestamps, volume metadata, LNK filesystem MACB times, and parser/version.
- **Interpretation:** A shortcut can indicate interaction with a target file, but is not standalone proof that a target executable ran.

## 7. Findings matrix (real evidence only)

| Evidence ID | Source key/path | Value name | Value data / target | Last write (UTC) | SHA-256 | Significance | Status |
|---|---|---|---|---|---|---|---|
| ART-001-R01 | dmarsh NTUSER.DAT / Run | Pending | Pending | Pending | N/A | Logon persistence candidate | Not examined |
| ART-001-R02 | dmarsh NTUSER.DAT / RunOnce | Pending | Pending | Pending | N/A | One-time autorun candidate | Not examined |
| ART-001-R03 | System32/Tasks | Pending | Pending | Pending | Pending | Scheduled-task persistence candidate | Not examined |
| ART-001-E01 | NTUSER.DAT / UserAssist | Pending | Pending | Pending | N/A | User interaction evidence | Not examined |
| ART-001-E02 | SYSTEM / AppCompatCache | Pending | Pending | Pending | N/A | File observation evidence | Not examined |
| ART-001-E03 | Amcache.hve | Pending | Pending | Pending | Pending | Application/file metadata | Not examined |
| ART-001-E04 | dmarsh / Recent / *.lnk | Pending | Pending | Pending | Pending | Recent-item evidence | Not examined |

## 8. Correlation and eradication checklist

No persistence mechanism is currently confirmed. Once artifacts become available:

1. Compare suspicious Run/RunOnce value data and scheduled-task actions with `update.xml` and any extracted binaries.
2. Correlate candidate creation/change timestamps with the SIEM's 02:46–02:47 UTC process sequence; check clock/timezone and timestamp provenance.
3. Search other users' hives, machine-wide Run keys (`SOFTWARE`), services (`SYSTEM`), Startup folders, WMI permanent event subscriptions, and other autoruns if scope permits. The six required sources are **not an exhaustive persistence inventory**.
4. Cross-check executable execution claims against independent sources such as Prefetch, event logs, memory, and EDR.
5. For every **confirmed** persistence item, record its exact removal procedure, dependencies, ownership/authorization, validation evidence after reboot, and monitoring plan; preserve evidence before remediation.
6. Re-verify source-image hashes and append actual access/export events to the chain of custody.

## 9. Training-only example (NOT EVIDENCE)

**SIMULATED ART-001-R01:** Suppose a parsed Run key contains `WindowsUpdateSvc` pointing to `C:\Users\dmarsh\AppData\Roaming\updater.exe`. This would be suspicious because a user-profile executable is configured for automatic logon execution. It would **not** be sufficient to conclude malicious persistence without examining the executable, signature, provenance, timeline, and authorization.

**SIMULATED ART-001-R03:** Suppose a scheduled task `SystemUpdater` triggers at user logon and runs `powershell.exe` with an encoded argument. This would be a persistence hypothesis to investigate, not an actual finding in MedDefense.

## 10. Conclusion

**Persistence status: UNDETERMINED.** The SIEM supports a lead involving PowerShell and MSBuild, but no Registry hive, task XML, UserAssist record, ShimCache entry, Amcache record, or LNK file has been independently examined. This report is a reproducible investigation plan, not a completed forensic examination. Do not claim eradication completeness until persistence is scoped and validated.
