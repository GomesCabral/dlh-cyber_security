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
