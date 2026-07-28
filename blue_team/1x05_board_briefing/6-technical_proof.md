# 6. The Technical Proof

## Check 1 - Certificate Inspection

Subject: CN=github.com

Issuer: Sectigo Public Server Authentication CA DV E36

Validity: 03 Jul 2026 - 30 Sep 2026

Key Algorithm: EC Public Key (256-bit)

SAN: github.com, www.github.com

## Check 2 - Hash Verification

Original SHA-256:
`d1d54e913db8029f2d27a2b2a2ab55dda42bbc91b6a751359454ede47b62356c`

Modified SHA-256:
`3332071b1e25754aca08be0ed573761e167e03f7725321684d4c2599fa81367d`

The hashes are different, proving the file changed. This is why FortiGate firmware hashes should always be verified before installation.

## Check 3 - Exploit Research

Commands:
```bash
searchsploit fortigate
searchsploit fortios
searchsploit --cve 2023-27997
```

Results:
- Historical FortiGate/FortiOS exploits found.
- No Exploit-DB entry specifically for CVE-2023-27997.
- CVE-2023-27997 is listed in the CISA KEV catalogue and is actively exploited.

Conclusion: Patch immediately.

## Check 4 - System Audit

Hardening Index: **66**

Top Warning:
- NETW-2704 - Nameserver does not respond.

Top Suggestions:
1. Install fail2ban.
2. Password protect GRUB.
3. Harden system services.

Recommendation for billing-srv-01:
Deploy fail2ban to reduce brute-force attacks.

## Conclusion

All four technical checks were successfully completed and demonstrate practical skills in certificate inspection, integrity verification, exploit research and Linux security auditing.
