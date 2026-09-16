# Incident Report — INC-20260916-B

## Executive Summary

INC-20260916-B affected ctr-db-01, ctr-db-02, sth-ids-01, sth-log-01.
The investigation hypothesis is: Repeated SSH authentication failures using the same account across multiple systems indicate credential abuse not covered by the approved maintenance ticket.
The finding has medium confidence and was classified for continued SOC investigation.

## Timeline

2026-04-07T23:51:32.271000Z | sth-ids-01 | type=USER_ACCT msg=audit(1775605892.271:70): pid=53209 uid=0 auid=1528 ses=136 msg='op=PAM:authentication acct="m.johnson" exe="/usr/sbin/sshd" hostname=sth-ids
2026-04-07T23:51:48Z | sth-log-01 | Apr 07 23:51:48 sth-log-01 polkitd[22610]: pam_unix(polkitd:session): session opened for user d_swilson
2026-04-07T23:52:00Z | sth-ids-01 | Apr 07 23:52:00 sth-ids-01 kernel[51242]: [UFW ALLOW] IN=eth0 OUT= SRC=10[.]5[.]0[.]10 DST=10[.]5[.]0[.]10 PROTO=TCP SPT=55144 DPT=25
2026-04-07T23:52:26.818000Z | ctr-db-01 | type=USER_AUTH msg=audit(1775605946.818:95): pid=47647 uid=0 auid=2695 ses=475 msg='op=PAM:authentication acct="k.brown" exe="/usr/sbin/sshd" hostname=ctr-db-01
2026-04-07T23:52:31.752000Z | ctr-db-01 | type=USER_LOGIN msg=audit(1775605951.752:55): pid=27086 uid=0 auid=3433 ses=155 msg='op=PAM:authentication acct="r.garcia" exe="/usr/sbin/sshd" hostname=ctr-db-
2026-04-07T23:52:43Z | ctr-db-02 | Apr 07 23:52:43 ctr-db-02 login[37412]: pam_unix(login:session): session closed for user k_sbrown
2026-04-07T23:52:55Z | ctr-db-02 | Apr 07 23:52:55 ctr-db-02 kernel[58949]: [UFW ALLOW] IN=eth0 OUT= SRC=52[.]168[.]112[.]78 DST=10[.]4[.]2[.]11 PROTO=TCP SPT=47592 DPT=80
2026-04-07T23:53:10Z | ctr-db-02 | Apr 07 23:53:10 ctr-db-02 sshd[35517]: pam_unix(sshd:session): session closed for user l_snguyen
2026-04-07T23:53:16.344000Z | sth-log-01 | type=USER_ACCT msg=audit(1775605996.344:18): pid=55901 uid=0 auid=1198 ses=384 msg='op=PAM:authentication acct="a.thompson" exe="/usr/sbin/sshd" hostname=sth-lo
2026-04-07T23:53:16Z | ctr-db-01 | Apr 07 23:53:16 ctr-db-01 polkitd[33639]: pam_unix(polkitd:session): session closed for user m_sjohnson
2026-04-07T23:54:22.942000Z | sth-log-01 | type=USER_AUTH msg=audit(1775606062.942:66): pid=49934 uid=0 auid=3768 ses=324 msg='op=PAM:authentication acct="a.thompson" exe="/usr/sbin/sshd" hostname=sth-lo
2026-04-07T23:54:36Z | sth-ids-01 | Apr 07 23:54:36 sth-ids-01 polkitd[24474]: pam_unix(polkitd:session): session closed for user k_sbrown
2026-04-07T23:54:40.134000Z | ctr-db-01 | type=CRED_ACQ msg=audit(1775606080.134:47): pid=32767 uid=0 auid=1619 ses=131 msg='op=PAM:authentication acct="svc_backup" exe="/usr/sbin/sshd" hostname=ctr-db-
2026-04-07T23:54:48Z | sth-ids-01 | Apr 07 23:54:48 sth-ids-01 su[7202]: pam_unix(su:session): session opened for user l_snguyen
2026-04-07T23:55:29.145000Z | ctr-db-02 | type=USER_LOGIN msg=audit(1775606129.145:93): pid=41467 uid=0 auid=3600 ses=180 msg='op=PAM:authentication acct="svc_backup" exe="/usr/sbin/sshd" hostname=ctr-d

## Affected Assets

| HOST | CRITICALITY | DATA_CLASS | ZONE |
|---|---|---|---|
| ctr-db-01 | CRITICAL | unknown | CENTRAL_DATA |
| ctr-db-02 | CRITICAL | unknown | CENTRAL_DATA |
| sth-ids-01 | HIGH | unknown | SOUTH_DMZ |
| sth-log-01 | HIGH | unknown | SOUTH_SERVERS |

## Indicators of Compromise

| TYPE | VALUE | CONFIDENCE | SOURCE |
|---|---|---|---|
| none | No direct IOC match | n/a | Current evidence |

## ATT&CK Mapping

| TECHNIQUE | NAME | EVIDENCE |
|---|---|---|
| T1110.001 | Password Guessing | Repeated SSH authentication failures using the same account across multiple systems indicate credential abuse not covere |
| T1078 | Valid Accounts | Repeated SSH authentication failures using the same account across multiple systems indicate credential abuse not covere |

## Detection Performance

- FIRED: 7d5d4b22-60c2-4ba7-8cce-1a5bc92cc5ef — SSH Repeated Authentication Failures from Single Source — 5 alert(s)
- MISSED: No additional missed detection was documented in the finding.

## Recommended Actions

1. Validate the affected user accounts with the identity owner.
2. Review authentication logs for the identified source systems.
3. Contain confirmed compromised accounts or hosts.
4. Block confirmed malicious indicators at applicable controls.
5. Preserve relevant endpoint, authentication and network evidence.
6. Escalate unresolved activity to Tier 2 for further investigation.

## Evidence References

- linux:none:2026-04-07T23:51:32.271000Z:sth-ids-01
- linux:none:2026-04-07T23:51:48Z:sth-log-01
- linux:none:2026-04-07T23:52:00Z:sth-ids-01
- linux:none:2026-04-07T23:52:26.818000Z:ctr-db-01
- linux:none:2026-04-07T23:52:31.752000Z:ctr-db-01
- linux:none:2026-04-07T23:52:43Z:ctr-db-02
- linux:none:2026-04-07T23:52:55Z:ctr-db-02
- linux:none:2026-04-07T23:53:10Z:ctr-db-02
- linux:none:2026-04-07T23:53:16.344000Z:sth-log-01
- linux:none:2026-04-07T23:53:16Z:ctr-db-01
- linux:none:2026-04-07T23:54:22.942000Z:sth-log-01
- linux:none:2026-04-07T23:54:36Z:sth-ids-01
