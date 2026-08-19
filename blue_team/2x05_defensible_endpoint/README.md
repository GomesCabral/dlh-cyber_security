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