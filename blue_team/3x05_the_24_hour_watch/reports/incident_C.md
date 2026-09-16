# Incident Report — INC-20260916-C

## Executive Summary

INC-20260916-C affected ctr-db-02, sth-ids-01, sth-log-01, wst-web-01.
The investigation hypothesis is: Repeated SSH authentication failures involving shared accounts and multiple hosts indicate possible credential abuse.
The finding has medium confidence and was classified for continued SOC investigation.

## Timeline

2026-04-08T00:03:23Z | wst-web-01 | Apr 08 00:03:23 wst-web-01 ntpd[33334]: synchronized to 10[.]1[.]1[.]60, stratum 2
2026-04-08T00:04:03.581000Z | sth-ids-01 | type=USER_AUTH msg=audit(1775606643.581:60): pid=55872 uid=0 auid=2115 ses=284 msg='op=PAM:authentication acct="l.nguyen" exe="/usr/sbin/sshd" hostname=sth-ids-
2026-04-08T00:04:15Z | wst-web-01 | Apr 08 00:04:15 wst-web-01 su[50734]: pam_unix(su:session): session opened for user a_sthompson
2026-04-08T00:04:27Z | ctr-db-02 | Apr 08 00:04:27 ctr-db-02 login[55861]: pam_unix(login:session): session closed for user j_smartinez
2026-04-08T00:04:54.661000Z | sth-ids-01 | type=USER_ACCT msg=audit(1775606694.661:81): pid=18848 uid=0 auid=3726 ses=58 msg='op=PAM:authentication acct="m.johnson" exe="/usr/sbin/sshd" hostname=sth-ids-
2026-04-08T00:05:41Z | sth-log-01 | Apr 08 00:05:41 sth-log-01 ntpd[20936]: synchronized to 10[.]1[.]1[.]60, stratum 2
2026-04-08T00:06:02.938000Z | sth-log-01 | type=USER_AUTH msg=audit(1775606762.938:32): pid=18465 uid=0 auid=3739 ses=462 msg='op=PAM:authentication acct="a.thompson" exe="/usr/sbin/sshd" hostname=sth-lo
2026-04-08T00:06:11.420000Z | sth-log-01 | type=USER_AUTH msg=audit(1775606771.420:18): pid=5972 uid=0 auid=4529 ses=451 msg='op=PAM:authentication acct="svc_ehr" exe="/usr/sbin/sshd" hostname=sth-log-01
2026-04-08T00:06:20.645000Z | sth-ids-01 | type=USER_AUTH msg=audit(1775606780.645:16): pid=13179 uid=0 auid=4776 ses=93 msg='op=PAM:authentication acct="svc_backup" exe="/usr/sbin/sshd" hostname=sth-ids
2026-04-08T00:06:28.669000Z | ctr-db-02 | type=USER_ACCT msg=audit(1775606788.669:63): pid=14228 uid=0 auid=2913 ses=479 msg='op=PAM:authentication acct="j.martinez" exe="/usr/sbin/sshd" hostname=ctr-db
2026-04-08T00:06:34.220000Z | sth-log-01 | type=USER_ACCT msg=audit(1775606794.220:85): pid=41137 uid=0 auid=4328 ses=319 msg='op=PAM:authentication acct="l.nguyen" exe="/usr/sbin/sshd" hostname=sth-log-
2026-04-08T00:06:59.986000Z | wst-web-01 | type=USER_ACCT msg=audit(1775606819.986:96): pid=5878 uid=0 auid=3923 ses=260 msg='op=PAM:authentication acct="d.wilson" exe="/usr/sbin/sshd" hostname=wst-web-0
2026-04-08T00:07:14.587000Z | ctr-db-02 | type=USER_ACCT msg=audit(1775606834.587:82): pid=26378 uid=0 auid=4110 ses=155 msg='op=PAM:authentication acct="l.nguyen" exe="/usr/sbin/sshd" hostname=ctr-db-0
2026-04-08T00:08:34Z | ctr-db-02 | Apr 08 00:08:34 ctr-db-02 systemd-logind[62889]: New session 101 of user svc_ehr.
2026-04-08T00:08:48Z | ctr-db-02 | Apr 08 00:08:48 ctr-db-02 su[4537]: pam_unix(su:session): session opened for user sarah.park_west

## Affected Assets

| HOST | CRITICALITY | DATA_CLASS | ZONE |
|---|---|---|---|
| ctr-db-02 | CRITICAL | unknown | CENTRAL_DATA |
| sth-ids-01 | HIGH | unknown | SOUTH_DMZ |
| sth-log-01 | HIGH | unknown | SOUTH_SERVERS |
| wst-web-01 | MEDIUM | unknown | WEST_SERVERS |

## Indicators of Compromise

| TYPE | VALUE | CONFIDENCE | SOURCE |
|---|---|---|---|
| none | No direct IOC match | n/a | Current evidence |

## ATT&CK Mapping

| TECHNIQUE | NAME | EVIDENCE |
|---|---|---|
| T1110.001 | Password Guessing | Repeated SSH authentication failures involving shared accounts and multiple hosts indicate possible credential abuse. |

## Detection Performance

- FIRED: 7d5d4b22-60c2-4ba7-8cce-1a5bc92cc5ef — SSH Repeated Authentication Failures from Single Source — 8 alert(s)
- MISSED: No additional missed detection was documented in the finding.

## Recommended Actions

1. Validate the affected user accounts with the identity owner.
2. Review authentication logs for the identified source systems.
3. Contain confirmed compromised accounts or hosts.
4. Block confirmed malicious indicators at applicable controls.
5. Preserve relevant endpoint, authentication and network evidence.
6. Escalate unresolved activity to Tier 2 for further investigation.

## Evidence References

- linux:none:2026-04-08T00:03:23Z:wst-web-01
- linux:none:2026-04-08T00:04:03.581000Z:sth-ids-01
- linux:none:2026-04-08T00:04:15Z:wst-web-01
- linux:none:2026-04-08T00:04:27Z:ctr-db-02
- linux:none:2026-04-08T00:04:54.661000Z:sth-ids-01
- linux:none:2026-04-08T00:05:41Z:sth-log-01
- linux:none:2026-04-08T00:06:02.938000Z:sth-log-01
- linux:none:2026-04-08T00:06:11.420000Z:sth-log-01
- linux:none:2026-04-08T00:06:20.645000Z:sth-ids-01
- linux:none:2026-04-08T00:06:28.669000Z:ctr-db-02
- linux:none:2026-04-08T00:06:34.220000Z:sth-log-01
- linux:none:2026-04-08T00:06:59.986000Z:wst-web-01
