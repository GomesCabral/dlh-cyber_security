# Incident Report — INC-20260916-A

## Executive Summary

INC-20260916-A affected ctr-admin-01, sth-ws-03, wst-bill-01, wst-dc-01, wst-dc-02.
The investigation hypothesis is: Repeated authentication failures followed by off-hours logons across correlated hosts indicate credential abuse requiring identity and source validation.
The finding has medium confidence and was classified for continued SOC investigation.

## Timeline

2026-04-07T23:49:26Z | wst-dc-01 | Network connection: lsass.exe -> 52[.]168[.]112[.]45:135
2026-04-07T23:49:36Z | wst-bill-01 | Process Create: C:\Windows\System32\csrss.exe by smss.exe
2026-04-07T23:49:46Z | wst-dc-01 | Network connection: lsass.exe -> 151[.]101[.]65[.]140:443
2026-04-07T23:49:51Z | wst-dc-01 | Network connection: lsass.exe -> 13[.]107[.]42[.]14:445
2026-04-07T23:50:19Z | sth-ws-03 | Network connection: lsass.exe -> 151[.]101[.]65[.]140:3389
2026-04-07T23:50:25Z | wst-bill-01 | Network connection: RuntimeBroker.exe -> 192[.]0[.]2[.]200:389
2026-04-07T23:50:40Z | wst-dc-02 | Network connection: taskhostw.exe -> 52[.]168[.]112[.]45:80
2026-04-07T23:50:49Z | sth-ws-03 | Process Create: C:\Windows\System32\RuntimeBroker.exe by explorer.exe
2026-04-07T23:51:10Z | sth-ws-03 | Network connection: taskhostw.exe -> 10[.]3[.]1[.]11:389
2026-04-07T23:51:15Z | wst-bill-01 | Network connection: explorer.exe -> 104[.]16[.]51[.]111:80
2026-04-07T23:51:55Z | ctr-admin-01 | Process Create: C:\Windows\System32\RuntimeBroker.exe by explorer.exe
2026-04-07T23:52:12Z | wst-dc-01 | Network connection: lsass.exe -> 13[.]107[.]42[.]14:389
2026-04-07T23:52:18Z | ctr-admin-01 | Process Create: C:\Program Files\Google\Chrome\Application\chrome.exe by explorer.exe
2026-04-07T23:52:28Z | sth-ws-03 | An account was logged off. User: l_snguyen
2026-04-07T23:52:33Z | sth-ws-03 | Process Create: C:\Windows\System32\RuntimeBroker.exe by explorer.exe

## Affected Assets

| HOST | CRITICALITY | DATA_CLASS | ZONE |
|---|---|---|---|
| ctr-admin-01 | LOW | unknown | CENTRAL_ADMIN |
| sth-ws-03 | MEDIUM | unknown | SOUTH_CLINIC |
| wst-bill-01 | MEDIUM | unknown | WEST_BILLING |
| wst-dc-01 | CRITICAL | unknown | WEST_SERVERS |
| wst-dc-02 | CRITICAL | unknown | WEST_SERVERS |

## Indicators of Compromise

| TYPE | VALUE | CONFIDENCE | SOURCE |
|---|---|---|---|
| none | No direct IOC match | n/a | Current evidence |

## ATT&CK Mapping

| TECHNIQUE | NAME | EVIDENCE |
|---|---|---|
| T1110.001 | Password Guessing | Repeated authentication failures followed by off-hours logons across correlated hosts indicate credential abuse requirin |
| T1078 | Valid Accounts | Repeated authentication failures followed by off-hours logons across correlated hosts indicate credential abuse requirin |

## Detection Performance

- FIRED: 391a0e44-57da-4ccd-8d56-f8153187af53 — Windows Off-Hours Privileged Logon — 200 alert(s)
- MISSED: No additional missed detection was documented in the finding.

## Recommended Actions

1. Validate the affected user accounts with the identity owner.
2. Review authentication logs for the identified source systems.
3. Contain confirmed compromised accounts or hosts.
4. Block confirmed malicious indicators at applicable controls.
5. Preserve relevant endpoint, authentication and network evidence.
6. Escalate unresolved activity to Tier 2 for further investigation.

## Evidence References

- windows:3:2026-04-07T23:49:26Z:wst-dc-01
- windows:1:2026-04-07T23:49:36Z:wst-bill-01
- windows:3:2026-04-07T23:49:46Z:wst-dc-01
- windows:3:2026-04-07T23:49:51Z:wst-dc-01
- windows:3:2026-04-07T23:50:19Z:sth-ws-03
- windows:3:2026-04-07T23:50:25Z:wst-bill-01
- windows:3:2026-04-07T23:50:40Z:wst-dc-02
- windows:1:2026-04-07T23:50:49Z:sth-ws-03
- windows:3:2026-04-07T23:51:10Z:sth-ws-03
- windows:3:2026-04-07T23:51:15Z:wst-bill-01
- windows:1:2026-04-07T23:51:55Z:ctr-admin-01
- windows:3:2026-04-07T23:52:12Z:wst-dc-01
