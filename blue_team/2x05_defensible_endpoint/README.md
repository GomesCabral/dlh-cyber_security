# Hawthorne Medical Center — Defensible Endpoint Package

## Task 0

```bash
./0-environment_intake.sh
```
```powershell
.\0-environment_intake.ps1
```

```bash
jq -e '.schema_version and .captured_at and .host.hostname' environment_intake.json > /dev/null
```
```powershell
(Get-Content .\environment_intake.json | ConvertFrom-Json) | ForEach-Object { $_.schema_version -and $_.captured_at -and $_.host.hostname }
```

---

## Task 1
 
**Linux**
```bash
./0-environment_intake.sh; ./1-baseline_snapshot.sh
```
 
**Windows**
```powershell
.\0-environment_intake.ps1; .\1-baseline_snapshot.ps1
```
 
## Verify
 
**Linux**
```bash
jq -e '.schema_version and .captured_at and .host.hostname' environment_intake.json > /dev/null && jq -e '.hostname and (.hardening_index != null)' capstone/baseline/baseline_linux.json > /dev/null
```
 
**Windows**
```powershell
$i = Get-Content .\environment_intake.json | ConvertFrom-Json; $b = Get-Content .\capstone\baseline\baseline_windows.json | ConvertFrom-Json; ($i.schema_version -and $i.captured_at -and $i.host.hostname) -and ($b.hostname -and ($null -ne $b.pass_rate_percent))
```

---

## Task 2
 
**Linux**
```bash
./2-target_state.sh; ./0-environment_intake.sh; ./1-baseline_snapshot.sh
```
 
**Windows**
```powershell
.\0-environment_intake.ps1; .\1-baseline_snapshot.ps1
```
 
## Verify
 
**Linux**
```bash
jq -e '.schema_version and .generated_at and (.controls | length > 0) and ([.controls[] | (.id and .platform and .family and .description and .check_type and .check_target and (.expected_value != null) and .source_project and .severity)] | all)' capstone/target_state.json > /dev/null && jq -e '.schema_version and .captured_at and .host.hostname' environment_intake.json > /dev/null && jq -e '.hostname and (.hardening_index != null)' capstone/baseline/baseline_linux.json > /dev/null
```
 
**Windows**
```powershell
$i = Get-Content .\environment_intake.json | ConvertFrom-Json; $b = Get-Content .\capstone\baseline\baseline_windows.json | ConvertFrom-Json; ($i.schema_version -and $i.captured_at -and $i.host.hostname) -and ($b.hostname -and ($null -ne $b.pass_rate_percent))
```
---

## Task 3
 
**Linux**
```bash
./2-target_state.sh; ./0-environment_intake.sh; ./1-baseline_snapshot.sh; ./3-linux_harden.sh
```
 
**Windows**
```powershell
.\0-environment_intake.ps1; .\1-baseline_snapshot.ps1
```
 
## Verify
 
**Linux**
```bash
jq -e '.schema_version and .generated_at and (.controls | length > 0) and ([.controls[] | (.id and .platform and .family and .description and .check_type and .check_target and (.expected_value != null) and .source_project and .severity)] | all)' capstone/target_state.json > /dev/null && jq -e '.schema_version and .captured_at and .host.hostname' environment_intake.json > /dev/null && jq -e '.hostname and (.hardening_index != null)' capstone/baseline/baseline_linux.json > /dev/null && jq -e '.timestamp and .hostname and (.steps | length == 7) and (.lynis_before != null) and (.lynis_after != null)' capstone/exec/linux_harden.json > /dev/null
```
 
**Windows**
```powershell
$i = Get-Content .\environment_intake.json | ConvertFrom-Json; $b = Get-Content .\capstone\baseline\baseline_windows.json | ConvertFrom-Json; ($i.schema_version -and $i.captured_at -and $i.host.hostname) -and ($b.hostname -and ($null -ne $b.pass_rate_percent))
```
---