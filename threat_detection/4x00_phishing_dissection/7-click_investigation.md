# Click Investigation — Diane Marsh / WS-NURSE-04

## Confirmed Facts

The following facts are confirmed by the supplied email evidence batch:

- User: Diane Marsh
- Workstation: WS-NURSE-04
- Source email: E2
- Phishing theme: MedDefense portal re-verification
- Suspicious domain: `meddefense-portal.com`
- URL: `https://meddefense-portal.com/verify?user=dmarsh@meddefense.com`
- Defanged URL: `hxxps://meddefense-portal[.]com/verify?user=dmarsh@meddefense[.]com`
- Click timestamp: 2026-04-15 15:02:33 CDT
- Related sending IP: `91.234.99.107`
- Diane Marsh reported clicking the link.
- E2 impersonated MedDefense IT Security.
- SPF failed.
- DKIM was absent.
- DMARC failed.
- The message used the external lookalike domain `meddefense-portal.com`.

The evidence confirms interaction with the phishing link but does not confirm
that credentials were entered or that the workstation or account was
compromised.


## Key Unknowns

The supplied evidence does not establish:

- Whether Diane entered her username or password into the phishing page.
- Whether Diane approved or received an unexpected MFA request.
- Whether the phishing page downloaded any files.
- Whether browser redirects occurred after the click.
- Whether scripts or other content executed on WS-NURSE-04.
- Whether suspicious processes were created.
- Whether PowerShell or cmd activity occurred.
- Whether new files were created on the workstation.
- Whether Diane's credentials were subsequently used by another party.
- Whether successful or failed logins occurred from unusual IP addresses or locations.
- Whether authentication sessions or tokens were stolen.
- Whether mailbox rules or account settings were modified.

Endpoint, identity and network telemetry would be required to answer these
questions.


## Risk Assessment

The reported click should be treated as a high-risk security event because E2
uses a lookalike MedDefense domain and a portal re-verification pretext
consistent with credential harvesting.

The URL also contains Diane's MedDefense email address, indicating that the
phishing page may have been prepared for a specific recipient.

A click alone does not prove compromise. Diane may have opened the page and
closed it without submitting information.

However, because the purpose of the lure appears to be account verification,
credential exposure must be considered possible until follow-up investigation
shows otherwise.


## Endpoint Checks To Perform

If endpoint telemetry from WS-NURSE-04 becomes available, perform the following
checks around the click timestamp.

### Browser Activity

- Review browser history around 2026-04-15 15:02:33 CDT.
- Confirm whether `meddefense-portal.com` was accessed.
- Identify redirects or additional domains contacted after the initial click.
- Review browser download history.
- Check whether files were downloaded after the visit.
- Review cached browser artifacts if available.

### File Activity

- Search for files created or downloaded around the click timestamp.
- Review the Downloads and temporary directories.
- Record file names, paths, timestamps and hashes for suspicious files.
- Do not open suspicious downloaded files directly.
- Submit hashes to approved reputation or sandbox services when appropriate.

### Process Execution

Review available endpoint telemetry for processes launched shortly after the
click, particularly:

- Browser child processes
- `powershell.exe`
- `pwsh.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `mshta.exe`
- `rundll32.exe`
- Other unexpected executables

Investigate suspicious parent-child process relationships originating from the
browser.

### Command-Line Activity

If command-line telemetry is available, review for:

- PowerShell commands
- cmd commands
- Script execution
- Encoded PowerShell
- Download commands
- Unexpected network-related commands

These are recommended follow-up checks only. The supplied evidence does not
confirm that any of these activities occurred.


## Account Checks To Perform

Identity and account telemetry for Diane Marsh should be reviewed around and
after the click timestamp.

### Authentication Activity

Check for:

- Failed login attempts after the click.
- Successful logins from unusual IP addresses.
- Successful logins from unusual geographic locations.
- Logins from devices not normally associated with Diane.
- New browser or authentication sessions.
- Impossible or abnormal travel patterns.
- Authentication activity at unusual times.

### MFA Activity

Check for:

- Unexpected MFA prompts.
- Repeated MFA requests.
- MFA approvals that Diane does not recognize.
- Changes to registered MFA methods.
- Addition of new authentication methods.

### Password and Session Activity

Check for:

- Password changes after the phishing event.
- Password reset attempts.
- New sessions established after the click.
- Existing session or token activity from unusual sources.

### Mailbox Activity

Check for:

- New inbox rules.
- Automatic forwarding rules.
- Deleted or hidden messages.
- Changes to mailbox permissions.
- Suspicious sent messages.
- Messages sent from Diane's account that she does not recognize.

### Account and Privilege Changes

Check for:

- Group membership changes.
- Role or permission changes.
- New application consent.
- Changes to account recovery information.
- Other unauthorized security-setting changes.

These checks are recommended follow-up actions. The supplied evidence does not
contain identity or account logs confirming any of these events.


## Decision Matrix

| Outcome | Required Evidence | Assessment | Response |
|---|---|---|---|
| No compromise found | Click confirmed, but no credential submission indicators, suspicious authentication, downloads, execution or account changes are identified | Interaction occurred but available evidence does not show compromise | Continue monitoring, document findings and provide phishing awareness guidance |
| Possible credential exposure | Diane confirms entering credentials, or investigation finds suspicious authentication indicators without enough evidence to prove account takeover | Credentials may have been exposed | Reset password, revoke active sessions, verify MFA configuration and increase account monitoring |
| Confirmed compromise | Unauthorized successful login, malicious account changes, confirmed attacker activity, malicious execution or other strong evidence of unauthorized access is identified | Account and/or endpoint compromise confirmed | Contain the account and affected endpoint, revoke sessions, reset credentials, preserve evidence and escalate incident response |


## Recommended Containment

Because Diane interacted with a credential-harvesting-style phishing link,
reasonable precautionary actions include:

1. Interview Diane and determine exactly what happened after she clicked the link.
2. Ask whether she entered her username, password or any other information.
3. Ask whether she received or approved an MFA prompt.
4. Ask whether the browser downloaded a file or displayed another page.
5. Reset Diane's password if credential exposure cannot be confidently excluded.
6. Revoke existing authentication sessions where supported.
7. Verify Diane's MFA methods and remove unauthorized changes if identified.
8. Review authentication activity following the click.
9. Review mailbox rules and forwarding configuration.
10. Monitor Diane's account for suspicious login attempts.
11. Preserve relevant endpoint, browser and identity evidence.
12. Escalate to incident response if evidence of account or endpoint compromise is identified.


## Evidence Limitations

No Sysmon, Wazuh, Suricata, Windows Security, browser, endpoint or identity logs
were supplied for this task.

The endpoint and account checks described above are recommended follow-up
investigation steps only. They were not performed as part of this evidence-only
analysis.

Therefore, no endpoint or account compromise is claimed based solely on the
available evidence.


## Conclusion

The evidence confirms that Diane Marsh clicked the E2 phishing link from
WS-NURSE-04 at 2026-04-15 15:02:33 CDT.

E2 used the lookalike domain `meddefense-portal.com` and a portal
re-verification pretext consistent with an attempt to collect credentials.

The click creates a credible risk of credential exposure, but the available
evidence does not establish that Diane submitted credentials or that her
workstation or account was compromised.

Endpoint, browser and identity telemetry should therefore be reviewed around
and after the click timestamp. Precautionary credential and session containment
is appropriate if credential exposure cannot be confidently excluded.