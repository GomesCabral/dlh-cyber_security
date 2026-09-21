# Click Investigation — Diane Marsh / WS-NURSE-04

## Confirmed Facts

The following facts are confirmed by the supplied evidence batch:

- User: Diane Marsh
- Workstation: WS-NURSE-04
- Workstation IP: 10.10.2.15
- Source email: Email 2 (E2)
- Suspicious domain: meddefense-portal.com
- Original URL: `https://meddefense-portal.com/verify?user=dmarsh@meddefense.com`
- Defanged URL: `hxxps://meddefense-portal[.]com/verify?user=dmarsh@meddefense[.]com`
- Click timestamp: 2026-04-14 15:02:33 CDT
- Related sending IP: 91.234.99.107
- Diane Marsh reported clicking the E2 link.
- E2 impersonated MedDefense IT Security.
- SPF failed.
- DKIM was absent.
- DMARC failed.

The evidence confirms that Diane Marsh clicked the E2 phishing link from
WS-NURSE-04 (10.10.2.15) at 2026-04-14 15:02:33 CDT.

The evidence does not confirm that Diane entered credentials or that her
account or workstation was compromised.


## Key Unknowns

The supplied evidence does not establish:

- Whether Diane entered her username or password.
- Whether Diane received or approved an MFA prompt.
- Whether the phishing page downloaded a file.
- Whether the browser was redirected to additional domains.
- Whether scripts or commands executed on WS-NURSE-04.
- Whether suspicious processes were launched.
- Whether files were created or modified.
- Whether Diane's credentials were later used by an attacker.
- Whether unusual successful or failed logins occurred.
- Whether authentication sessions or tokens were stolen.
- Whether mailbox or account settings were modified.


## Risk Assessment

The reported click represents a serious security risk because E2 uses the
lookalike domain meddefense-portal.com and impersonates MedDefense IT Security.

The phishing URL uses a portal re-verification pretext and contains Diane's
email address. This is consistent with a targeted credential-harvesting lure.

A click alone does not prove compromise. Diane may have opened the page and
closed it without entering information.

However, credential exposure must be considered possible until endpoint and
identity evidence can be reviewed.


## Endpoint Checks To Perform

If endpoint logs or forensic evidence from WS-NURSE-04 become available, the
following checks should be performed around 2026-04-14 15:02:33 CDT.

### Browser History

- Review browser history around the click timestamp.
- Confirm access to meddefense-portal.com.
- Identify redirects to additional domains.
- Review browser download history.
- Check browser cache and temporary artifacts if available.

### Downloaded and Created Files

- Check the Downloads directory.
- Check temporary directories.
- Identify files created shortly after the click.
- Record file names, paths, timestamps and hashes.
- Do not open suspicious files directly.

### Process Execution

Review endpoint telemetry for unexpected processes launched after the click,
including:

- Browser child processes
- powershell.exe
- pwsh.exe
- cmd.exe
- wscript.exe
- cscript.exe
- mshta.exe
- rundll32.exe
- Other unexpected executables

Check parent-child process relationships to determine whether the browser
launched another process.


### PowerShell and Command-Line Activity

If command-line telemetry is available, check for:

- PowerShell execution
- cmd execution
- Script execution
- Encoded PowerShell commands
- Download commands
- Unexpected network commands

These are recommended follow-up checks only. The supplied evidence does not
confirm that any of these activities occurred.


## Account Checks To Perform

Identity and account activity for Diane Marsh should be reviewed after the
click timestamp.

### Authentication Activity

Check for:

- Failed logons.
- Successful logons from unusual IP addresses.
- Successful logons from unusual geographic locations.
- Logons from unknown devices.
- Authentication at unusual times.
- New or unexpected sessions.


### MFA Activity

Check for:

- Unexpected MFA prompts.
- Repeated MFA requests.
- MFA approvals Diane does not recognize.
- New MFA methods.
- Changes to registered authentication methods.


### Password and Session Activity

Check for:

- Password changes.
- Password reset attempts.
- New authentication sessions.
- Suspicious active sessions.
- Session or token activity from unusual sources.


### Mailbox Activity

Check for:

- New inbox rules.
- New forwarding rules.
- Suspicious sent messages.
- Deleted or hidden messages.
- Mailbox permission changes.
- Automatic forwarding to external addresses.


### Account Changes

Check for:

- Group membership changes.
- Role or permission changes.
- New application consent.
- Account recovery changes.
- Other unauthorized security-setting changes.

These are recommended follow-up checks. No identity or account logs were
provided in the evidence batch.


## Decision Matrix

| Outcome | Evidence | Assessment | Response |
|---|---|---|---|
| No compromise found | Click confirmed, but no credential submission, suspicious login, download, execution or account change is identified | Interaction occurred but there is no evidence of compromise | Continue monitoring and document the incident |
| Possible credential exposure | Diane confirms entering credentials or suspicious authentication activity is found without enough evidence to confirm account takeover | Credentials may have been exposed | Reset password, revoke sessions, verify MFA and increase monitoring |
| Confirmed compromise | Unauthorized successful login, malicious account changes, malicious execution or other confirmed attacker activity is identified | Account or endpoint compromise confirmed | Contain the account and endpoint, revoke sessions, reset credentials, preserve evidence and escalate the incident |


## Recommended Containment

Recommended actions include:

1. Interview Diane and determine exactly what happened after the click.
2. Ask whether she entered her username or password.
3. Ask whether she received or approved an MFA prompt.
4. Ask whether the browser downloaded a file.
5. Reset Diane's password if credential exposure cannot be excluded.
6. Revoke active authentication sessions.
7. Verify Diane's MFA methods.
8. Review authentication activity after the click.
9. Review mailbox rules and forwarding configuration.
10. Monitor the account for suspicious login attempts.
11. Preserve relevant browser, endpoint and identity evidence.
12. Escalate to incident response if compromise is confirmed.


## Evidence Limitations

No Sysmon, Wazuh, Suricata, Windows Security, browser, endpoint or identity logs
were provided for this task.

The checks listed in this report are recommended follow-up actions. They were
not performed as part of this evidence-only investigation.

No account or endpoint compromise is claimed based solely on the available
evidence.


## Conclusion

The evidence confirms that Diane Marsh clicked the Email 2 (E2) phishing link
from WS-NURSE-04 with IP address 10.10.2.15 at
2026-04-14 15:02:33 CDT.

The phishing message used the lookalike domain meddefense-portal.com and was
sent from infrastructure associated with IP 91.234.99.107.

The click creates a credible risk of credential exposure, but the available
evidence does not prove that Diane submitted credentials or that her account
or workstation was compromised.

Endpoint, browser and identity evidence should be reviewed to determine the
final incident status. Precautionary password reset, session revocation and
account monitoring are appropriate if credential exposure cannot be excluded.