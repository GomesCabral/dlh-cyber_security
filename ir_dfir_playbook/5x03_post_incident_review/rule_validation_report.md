# Rule Validation Report: IR-2026-0414-01

**Analyst:** Pedro Cabral  
**Date:** 2026-10-21  
**Status:** Lab validation complete; production deployment not approved

## Scope and methodology

Validated two Sigma YAML detection conditions against the *actual uploaded* Sysmon JSONL samples using `validate_rules.sh`, a compatible Python 3/PyYAML log matcher embedded in a Bash script. The matcher maps normalized JSONL fields (`image`, `parent_image`, `dst_hostname`, `initiated`) to Sigma fields and supports the specific `endswith` and Boolean conditions in these rules. It is **not** a full Sigma backend, and no SIEM execution or `sigma-cli check` was performed.

The uploaded files contain **17 incident events** and **21 clean events**, not the 4,812 and 287,341 events shown in the task's illustrative example. All percentages below use actual file lengths as denominators. A zero-match clean sample this small does not establish a production false-positive rate below 0.1%.

**Important Task 4 dependency:** Only the Task 3 Sigma rule was available in the supplied working folder. `sigma_msbuild_network_c2.yml` is a **provisional second rule**, inferred from the Task 5 C2/clean NuGet context, and must be checked against the actual Task 4 requirements before submission as its replacement. Do not represent this as a previously supplied Task 4 rule.

## Validation results

| Rule | Sample | Total events | Matches | Rate | Verdict |
|---|---|---:|---:|---:|---|
| `sigma_powershell_msbuild_lolbin.yml` | Incident | 17 | 2 | 11.765% | PASS: attack behavior detected |
| `sigma_powershell_msbuild_lolbin.yml` | Clean | 21 | 0 | 0.000% | PASS on sample |
| `sigma_msbuild_network_c2.yml` (provisional) | Incident | 17 | 2 | 11.765% | PASS: attack behavior detected |
| `sigma_msbuild_network_c2.yml` (provisional) | Clean | 21 | 0 | 0.000% | PASS on sample after filtering |

**Incident hits:** Process creation at `2026-04-14T02:46:58Z` on `WST-WS-031` and `2026-04-14T03:27:13Z` on `WST-WS-017`; network connections at `2026-04-14T02:47:02Z` from `WST-WS-031` to `185.220.101.47:443` and `2026-04-14T03:27:15Z` from `WST-WS-017` to `91.234.99.107:443`.

## Tuning decisions and false-positive patterns

### Rule 1: PowerShell spawning trusted developer utilities

- **Change:** None. Original Task 3 Sigma file preserved.
- **Reason:** Both relevant incident process-creation events matched; zero clean matches in this sample. Legitimate Visual Studio -> MSBuild builds in the clean logs do not match the suspicious PowerShell/script-host parent criterion.
- **Remaining risk:** Legitimate PowerShell-driven build automation may generate alerts in environments not represented by the sample. Validate on actual build agents before rollout.

### Rule 2: MSBuild outbound network connections (provisional Task 4 substitute)

- **Initial broad logic:** `Image|endswith: '\\MSBuild.exe'` with outbound `Initiated: 'true'` would match 2 incident events and **14/21 clean events (66.667%)**. All 14 are routine MSBuild connections to `api.nuget.org` from developer workstations (`WST-WS-042` and `WST-WS-051`).
- **Tuning:** Added `filter_nuget: DestinationHostname|endswith: '.nuget.org'` and condition `selection and not filter_nuget`.
- **After tuning:** 2/17 incident matches; 0/21 clean matches (0.000%).
- **Why:** Removes an evidenced normal NuGet restore pattern without filtering the two malicious connections, whose `dst_hostname` values are null.
- **Remaining risk:** Hostname-based exceptions require trustworthy DNS/EDR telemetry and could be abused or mask other activity; verify the destination IP and authorized package restore context before broad deployment. This is a behavioral detection, not proof of C2.

## Evidence and limitations

- `incident_sysmon.jsonl` and `clean_sysmon.jsonl`: observed process/network events and match counts.
- `forensic_findings_summary.md`: `ART-002-M01` (PowerShell -> MSBuild), `ART-002-M02` (external C2), and `ART-003-M01` (second host beacon).
- No clean matched events remain after tuning, so the clean-match listing is empty. The pre-tuning 14-event false-positive pattern is documented above.
- The local matcher intentionally supports only the operators used by these two rules and rejects unsupported fields/modifiers; it is not a general-purpose Sigma implementation.
- Additional tests needed: larger 30-day baseline, alternate parent processes, signed internal build scripts, NuGet edge cases, and validation with `sigma check` plus the target SIEM backend.

## Reproduction

Place both JSONL files in the same directory as the script, then run:

```bash
chmod +x validate_rules.sh
./validate_rules.sh
```

Or supply absolute input paths:

```bash
./validate_rules.sh /path/to/incident_sysmon.jsonl /path/to/clean_sysmon.jsonl
```

Requires `bash`, `python3`, and `PyYAML` (`python3 -m pip install pyyaml`). The script exits with an error for missing files, malformed JSONL, or unsupported Sigma constructs.

## Deployment decision

**Lab PASS; production NOT YET APPROVED.** Validate the provisional second rule against Task 4, use the full baseline, run `sigma check`, test conversion for the actual SIEM, and obtain detection engineering review before deploying either rule.
