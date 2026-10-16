# Chain of Custody: `LH-2026-0414-01`

## Case Header

- **Case number:** `LH-2026-0414-01`
- **Incident ID:** `IR-2026-0414-01`
- **Lead investigator:** Pedro Cabral (assigned for this exercise; confirm formal appointment)
- **Date opened:** 2026-10-16 (document created for exercise; original investigation commenced 2026-04-14)
- **Litigation hold reference:** Memo from Helena Reyes, 2026-04-14T07:30Z (time approximate per acquisition notes)
- **Acquisition notes:** `acquisition_notes.md`, signed by Mike Torres, 2026-04-14T07:42Z
- **Log policy:** Append-only. Never overwrite or delete existing rows; corrections must be appended as dated amendments.
- **Evidence status:** Acquisition-time hashes unavailable; first-access baselines pending. No original custody log exists for the interval before handoff.

## Artifact Registry

| Artifact ID | Artifact Name | Format | Acquired By | Acquisition Timestamp (UTC) | Acquisition Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| ART-001 | `wst-ws-031.dd` | RAW/dd disk image | Mike Torres | 2026-04-14 04:51Z–06:14Z | FTK Imager | **NOT COMPUTED** | `\\evidence\share\IR-2026-0414-01\` (reported destination; exact path unverified) | Not documented at acquisition; enforce read-only, IR team only; verify permissions |
| ART-002 | `wst-ws-031.mem` | RAW memory dump | Mike Torres | 2026-04-14 03:02Z | WinPmem v3.3-rc3 | **NOT COMPUTED** | `\\evidence\share\IR-2026-0414-01\` (reported destination; exact path unverified) | Not documented at acquisition; enforce read-only, IR team only; verify permissions |
| ART-003 | `wst-ws-017.mem` | RAW memory dump | Mike Torres | 2026-04-14 03:38Z | WinPmem (version not separately recorded; same workflow as ART-002) | **NOT COMPUTED** | `\\evidence\share\IR-2026-0414-01\` (reported destination; exact path unverified) | Not documented at acquisition; enforce read-only, IR team only; verify permissions |

## First-Access SHA-256 Baselines

Acquisition-time hashes **cannot be reconstructed**. Before any forensic analysis of each binary artifact, calculate SHA-256 on the preserved source, record the exact value and UTC time in an appended access-log row, and save a checksum manifest. A first-access hash proves consistency against later reads, **not** integrity since acquisition.

| Artifact ID | SHA-256 at First Verified Access | UTC Timestamp | Manifest | Status |
| :-- | :-- | :-- | :-- | :-- |
| ART-001 | PENDING — image not supplied | PENDING | `sha256_baselines.txt` | NOT VERIFIED |
| ART-002 | PENDING — dump not supplied | PENDING | `sha256_baselines.txt` | NOT VERIFIED |
| ART-003 | PENDING — dump not supplied | PENDING | `sha256_baselines.txt` | NOT VERIFIED |

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool Used | Hash Verified (yes/no) | Notes |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| 2026-04-14 03:02Z | Mike Torres | ART-002 | acquisition | WinPmem v3.3-rc3 | no | Reconstructed from acquisition notes; live host, before isolation; no acquisition hash. |
| 2026-04-14 03:38Z | Mike Torres | ART-003 | acquisition | WinPmem | no | Reconstructed from acquisition notes; before isolation; no acquisition hash. |
| 2026-04-14 04:51Z–06:14Z | Mike Torres | ART-001 | acquisition | FTK Imager | no | Reconstructed from acquisition notes; host isolated to VLAN 999 before imaging. |
| Time unknown, before 2026-04-14 04:51Z | Mike Torres | ART-001 (source filesystem) | pre-acquisition read-write filesystem mount / inspection | Windows Explorer (mount tool unspecified) | no | **DEVIATION:** Source filesystem accessed read-write while checking `update.xml`; potential metadata changes. Exact timestamp and changes unknown. |
| Time unknown, after each acquisition | Mike Torres | ART-001, ART-002, ART-003 | transfer to evidence share | USB3 / external NVMe / network copy (details incomplete) | no | Reconstructed from notes; exact transfer times, recipients and intermediate access not recorded. |

**Note:** The entries above are a retrospective reconstruction from `acquisition_notes.md`, **not** contemporaneous custody records. No first-access hashing, mounting or analysis of the three binary artifacts has yet been performed as part of this exercise.

## Known Deviations and Preservation Risks

- **DEVIATION-001 — Missing acquisition hashes:** None of the three artifacts was hashed at acquisition. Establish and record first-access baselines; do not label them acquisition hashes.
- **DEVIATION-002 — Incomplete historical custody:** No contemporaneous custody form; people with physical or network access between acquisition and handoff were not recorded. Seek transfer, share, USB and endpoint access records where available; never invent missing events.
- **DEVIATION-003 — Read-write source access:** Mike Torres mounted the live filesystem read-write before disk imaging and opened Explorer to check `update.xml`. Possible metadata changes; document limitations and assess impact on timestamps.
- **DEVIATION-004 — Storage permissions not evidenced:** Actual read-only controls and IR-only permissions have not been verified.

## Procedure for All Future Access

1. Confirm artifact ID, source path, operator, purpose and UTC time; check read-only permissions and preserve original evidence.
2. Before the first forensic analysis access, calculate SHA-256 and record it as a **first-access baseline**, with UTC time and a checksum manifest.
3. For each subsequent access, recompute or verify the hash against the established baseline, and append an access-log row including timestamp, actor, artifact ID, action, tool, result and notes.
4. If a hash differs, **stop**, preserve both values, notify the investigation lead, and append a `DEVIATION` record with the exact UTC timestamp and circumstances.
5. Record exports or derived artifacts separately, including their source artifact, method, path and SHA-256; do not alter earlier entries.

### Example row format (template only — not an event)

`<UTC timestamp> | <analyst> | ART-001 | hash_verify | sha256sum | yes (baseline established) | SHA-256: <actual 64-character hash>; manifest: sha256_baselines.txt; source path: <verified path>`

## Source and Scope Notes

- Source: `acquisition_notes.md` provided with the exercise.
- The binary artifacts `wst-ws-031.dd`, `wst-ws-031.mem` and `wst-ws-017.mem` were **not** provided in the current workspace. Therefore no SHA-256 value, current storage path, or actual read-only access control can yet be verified.
- This record is prepared for the learning exercise. Formal legal admissibility and sufficiency of custody documentation require assessment by the organization's legal and forensic leads.
