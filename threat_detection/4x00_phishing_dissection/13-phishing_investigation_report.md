# Phishing Campaign Investigation Report

## Executive Summary

MedDefense Health Systems received a group of suspicious emails targeting
employees through IT verification, invoice/payment and employee-benefits
pretexts. The investigation identified E2, E3, E5 and E7 as phishing-related,
while E1 and E6 were spam and E4 and E8 were legitimate. Evidence supports the
assessment that E2, E5 and E7 are likely connected components of a coordinated
campaign targeting different MedDefense business functions. Diane Marsh
confirmed clicking the E2 phishing link, creating a risk of credential exposure,
although the supplied evidence does not prove that credentials were submitted
or that her account or workstation was compromised. Immediate follow-up should
focus on Diane's account and workstation, campaign IOC blocking, recipient
searches and monitoring for suspicious authentication activity.


## Investigation Timeline

The investigation covered eight emails supplied in the evidence batch and
examined their headers, authentication results, sender infrastructure, URLs,
attachments, social-engineering techniques and campaign relationships.

| Date / Time | Event |
|---|---|
| April 14, 2026 | E2 delivered using a MedDefense IT portal re-verification pretext |
| 2026-04-14 15:02:33 CDT | Diane Marsh reported clicking the E2 phishing link from WS-NURSE-04 (10.10.2.15) |
| April 16, 2026 | E5 delivered using an invoice/payment pretext |
| April 16, 2026 | E7 delivered using an HR/benefits open-enrollment pretext |
| Evidence collection window | Eight emails, E1 through E8, were reviewed as part of the supplied investigation batch |

The investigation scope included:

- Email header analysis
- SPF, DKIM and DMARC analysis
- Sender and infrastructure correlation
- Social-engineering analysis
- URL and attachment assessment
- Reported user interaction
- Campaign correlation
- IOC extraction
- Detection and control recommendations

No endpoint, browser, SIEM or identity telemetry was supplied. Any endpoint or
account checks described in this report are recommended follow-up actions and
are not presented as completed searches.


## Email-by-Email Analysis

| Email | Final Classification | Confidence | Key Evidence |
|---|---|---|---|
| E1 | SPAM | HIGH | Authenticated bulk newsletter; SPF, DKIM and DMARC pass; bulk-mail and unsubscribe characteristics; no targeted credential or payment lure |
| E2 | PHISHING-TARGETED | HIGH | MedDefense lookalike `meddefense-portal.com`; SPF fail; DKIM none; DMARC fail; PHPMailer 6.6.0; urgent portal re-verification lure; Diane Marsh confirmed clicking |
| E3 | PHISHING-TARGETED | HIGH | Claims to be Microsoft Account Protection but uses `outlook-protection.com`; account-verification lure; account-lock threat; PHPMailer 6.6.0; authentication passes only for the sender's lookalike domain |
| E4 | LEGITIMATE | HIGH | Internal `meddefense.com` sender and Exchange infrastructure; SPF, DKIM and DMARC pass; users directed to normal internal portal |
| E5 | PHISHING-TARGETED | HIGH | Unexpected $24,716.38 invoice; finance/AP context; SPF softfail; DKIM none; DMARC fail; suspicious invoice/login URLs; PDF attachment; recipient reported invoice looked wrong |
| E6 | SPAM | HIGH | Unsolicited pharmaceutical advertising; spam score 9.8; authentication problems; direct numeric-IP HTTP link |
| E7 | PHISHING-TARGETED | HIGH | MedDefense HR impersonation; lookalike `meddefense-benefits.org`; SPF fail; DKIM none; DMARC fail; urgent benefits enrollment lure |
| E8 | LEGITIMATE | HIGH | Authenticated HHS/HC3 sender; SPF, DKIM and DMARC pass for `hhs.gov`; healthcare phishing advisory relevant to observed activity |


### E1 — Spam

E1 is an authenticated bulk newsletter. SPF, DKIM and DMARC pass, and the
message contains bulk-mail and unsubscribe characteristics.

The evidence supports spam classification rather than phishing.


### E2 — Targeted Phishing

E2 impersonates MedDefense IT Security and uses the lookalike domain
`meddefense-portal.com`.

SPF failed, DKIM was absent and DMARC failed. The message pressures Diane Marsh
to complete portal re-verification within 24 hours and directs her to an
external verification URL containing her MedDefense email address.

Diane confirmed clicking the link, making E2 the highest-priority incident in
the evidence batch.


### E3 — Targeted Phishing

E3 claims to represent Microsoft Account Protection and warns of unusual
sign-in activity and possible account locking.

SPF, DKIM and DMARC pass, but this authentication applies to
`outlook-protection.com`. It does not establish that the sender is Microsoft.

The combination of brand impersonation, account-verification language, urgency
and an external verification page supports the phishing classification.


### E4 — Legitimate

E4 originates from MedDefense infrastructure and passes SPF, DKIM and DMARC.

The message directs users to the normal internal portal rather than an external
credential-verification page.

The evidence supports a legitimate classification.


### E5 — Targeted Phishing

E5 uses an invoice/payment pretext involving invoice `INV-2026-04891` and a
payment amount of $24,716.38.

SPF softfailed, DKIM was absent and DMARC failed. The message contains external
invoice and login URLs and a PDF attachment.

The financial pretext is relevant to an Accounts Payable workflow, and the
recipient reported that the invoice looked wrong.

The evidence supports targeted phishing classification.


### E6 — Spam

E6 is unsolicited pharmaceutical advertising with a spam score of 9.8.

The message also has authentication failures and contains a direct numeric-IP
HTTP link.

The overall evidence supports spam classification.


### E7 — Targeted Phishing

E7 impersonates MedDefense HR Benefits using the lookalike domain
`meddefense-benefits.org`.

SPF failed, DKIM was absent and DMARC failed. The message creates urgency by
claiming that open enrollment closes the following day and directs the
recipient to an external enrollment page.

The evidence supports targeted phishing classification.


### E8 — Legitimate

E8 is an authenticated HHS/HC3 healthcare-sector security advisory.

SPF, DKIM and DMARC pass for `hhs.gov`. Its description of healthcare phishing,
lookalike domains, urgency and role-specific targeting provides useful threat
context for the MedDefense investigation.

The evidence supports a legitimate classification.


## Campaign Analysis

### Relationship Between E2, E5 and E7

E2, E5 and E7 use different domains and different pretexts, but several
characteristics support the assessment that they are likely connected.

All three target MedDefense within a short time window. E2 was observed on
April 14, while E5 and E7 were observed on April 16.

The messages use business-process-specific social engineering:

- E2 targets clinical staff through IT portal verification.
- E5 targets Accounts Payable / finance through an invoice.
- E7 uses an HR / employee-benefits enrollment pretext.

All three use urgency or deadline pressure and direct recipients toward
external infrastructure.

They also share technical characteristics including PHPMailer 6.6.0,
PHP-style Message-ID patterns and high-priority messaging.

E2 and E7 additionally use MedDefense-themed lookalike domains:
`meddefense-portal.com` and `meddefense-benefits.org`.

These combined characteristics support a coordinated campaign assessment,
although they do not prove common threat-actor ownership.


### Relationship With E8 / HC3

E8 describes healthcare-sector phishing characteristics that are consistent
with the MedDefense evidence.

The observed overlap includes:

- Healthcare-sector targeting
- Lookalike domains
- Role-specific targeting
- Urgency and deadline pressure
- Organizational impersonation
- Business-process-specific phishing lures

E8 therefore provides external context supporting the campaign hypothesis.

However, similarity with the HC3 alert does not prove that E2, E5 and E7 were
sent by a specific actor described by HC3.


### Interpretation of E3

E3 is phishing-related but should not automatically be considered part of the
same coordinated E2/E5/E7 campaign.

E3 shares some characteristics with the other phishing messages, including
PHPMailer 6.6.0, PHP-style message generation, urgency and an account
verification lure.

However, E3 uses Microsoft Account Protection impersonation rather than a
MedDefense-specific business process. Its SPF, DKIM and DMARC checks also pass
for `outlook-protection.com`.

The evidence therefore supports E3 as phishing while the available evidence is
not sufficient to establish that it belongs to the same coordinated campaign
as E2, E5 and E7.


## Click Incident Assessment

### Confirmed Facts

The evidence confirms:

- User: Diane Marsh
- Workstation: WS-NURSE-04
- Workstation IP: 10.10.2.15
- Source email: E2
- Domain: `meddefense-portal.com`
- Click timestamp: 2026-04-14 15:02:33 CDT
- E2 sending IP: `91.234.99.107`
- Diane reported clicking the phishing link

The E2 URL was:

`hxxps://meddefense-portal[.]com/verify?user=dmarsh@meddefense[.]com`


### What Can Be Concluded

The evidence proves that Diane interacted with the E2 phishing link.

Because E2 uses a portal re-verification pretext and a targeted external URL,
the click creates a credible risk of credential exposure.


### What Cannot Be Concluded

The evidence batch does not establish:

- That Diane entered her password.
- That credentials were successfully harvested.
- That she approved an MFA request.
- That a file was downloaded.
- That malicious code executed.
- That WS-NURSE-04 was compromised.
- That Diane's account was accessed by an attacker.
- That session tokens were stolen.

A click alone must not be treated as proof of endpoint or account compromise.


### Recommended Follow-Up

Diane should be interviewed to determine exactly what occurred after the click.

If available, defenders should review browser history, downloads, file
creation, browser child processes, PowerShell/cmd activity and other endpoint
telemetry around the click timestamp.

Identity telemetry should be reviewed for failed and successful logons,
unusual source IPs, unexpected MFA activity, password changes, session
activity, inbox/forwarding rules and group or permission changes.

If credential exposure cannot be confidently excluded, Diane's password should
be reset and active authentication sessions revoked.


## IOC Summary

### Domains

- `meddefense-portal[.]com` — E2
- `outlook-protection[.]com` — E3
- `medequip-supplies[.]net` — E5
- `meddefense-benefits[.]org` — E7


### IP Addresses

- `91[.]234[.]99[.]107` — E2 sending infrastructure
- `51[.]38[.]42[.]17` — E3 sending infrastructure
- `185[.]176[.]43[.]22` — E5 sending infrastructure
- `203[.]0[.]113[.]228` — E5 contextual indicator
- `164[.]90[.]218[.]73` — E7 sending infrastructure


### Sender Addresses

- `noreply@meddefense-portal[.]com`
- `security@outlook-protection[.]com`
- `invoices@medequip-supplies[.]net`
- `hr-notifications@meddefense-benefits[.]org`


### URLs

- `hxxps://meddefense-portal[.]com/verify?user=dmarsh@meddefense[.]com`
- `hxxps://outlook-protection[.]com/account/verify`
- `hxxps://medequip-supplies[.]net/invoices/INV-2026-04891`
- `hxxps://medequip-supplies[.]net/portal/login`
- `hxxps://meddefense-benefits[.]org/enrollment`


### Attachment / File Indicators

E5 contains the attachment:

`Invoice_INV-2026-04891[.]pdf`

No verified cryptographic file hash was supplied by the evidence batch.

A SHA-256 value should be calculated if the original attachment becomes
available. No file hash is invented in this report.


### Context-Only Indicators

The following are useful for correlation but should not be independently
blocked:

- PHPMailer 6.6.0
- PHP-style Message-ID patterns
- High-priority headers
- Urgency language
- Invoice/payment themes
- Benefits-enrollment themes
- Account-verification themes

These characteristics are not uniquely malicious and could create false
positives if used alone.


## Detection and Control Gaps

### Observed Control Gaps

The investigation shows that multiple phishing messages reached employee
mailboxes despite authentication failures and suspicious characteristics.

E2 and E7 had SPF and DMARC failures and no DKIM signature, yet the messages
were still delivered.

E5 had an SPF softfail, no DKIM signature and a DMARC failure.

The successful delivery of E3 also demonstrates why SPF, DKIM and DMARC cannot
be treated as phishing verdicts. An attacker can authenticate a domain they
control while using that domain to impersonate another organization.

The confirmed E2 click demonstrates that technical delivery controls alone did
not prevent user interaction with the phishing infrastructure.


### Recommended Control Improvements

Email security controls should increase scrutiny of messages that combine:

- External senders
- Organizational lookalike domains
- SPF or DMARC failures
- Missing DKIM
- High-priority headers
- Credential-verification language
- Payment/invoice language
- HR/benefits themes
- External login or verification URLs

Lookalike-domain detection should be strengthened for domains resembling
`meddefense.com`.

Web/DNS controls should ingest validated high-confidence phishing domains and
URLs.

Identity monitoring should prioritize suspicious authentication activity
following reported phishing interaction.


### Detection Ideas

Detection logic should correlate multiple weak signals rather than relying on
one indicator alone.

Useful detection ideas include:

1. Alert when an external sender uses a domain visually similar to
   `meddefense.com`.

2. Alert when SPF or DMARC fails and the message contains credential,
   verification, password, enrollment or payment language.

3. Alert when an external email contains login or verification URLs combined
   with high-priority headers.

4. Detect multiple emails using similar PHPMailer and PHP-style Message-ID
   characteristics together with different business-process lures.

5. Search for messages containing known campaign domains and sender addresses.

6. Correlate reported phishing clicks with subsequent unusual authentication
   events.

7. Alert on suspicious post-phishing account changes such as new forwarding
   rules, MFA changes or unexpected group membership changes.

PHPMailer or high-priority headers should not be used as standalone malicious
detections because they can occur in legitimate email.


## Recommendations

### Immediate — Next 24 Hours

1. Interview Diane Marsh and determine whether credentials or MFA information
   were entered after the E2 click.

2. Reset Diane's password if credential exposure cannot be confidently
   excluded.

3. Revoke Diane's active authentication sessions if credential exposure is
   possible.

4. Review Diane's authentication and MFA activity after
   2026-04-14 15:02:33 CDT.

5. Review WS-NURSE-04 browser and endpoint evidence around the click timestamp.

6. Block validated phishing domains and URLs associated with E2, E3, E5 and E7.

7. Search mailboxes for matching campaign sender addresses, domains, URLs and
   subjects.

8. Quarantine matching phishing messages.

9. Identify any additional users who clicked or interacted with the campaign.


### Short-Term — Next 7 Days

1. Complete historical searches for all identified campaign IOCs.

2. Safely extract and calculate the SHA-256 hash of the E5 PDF attachment if
   the original file is available.

3. Review web/DNS/proxy telemetry for access to identified phishing domains.

4. Review authentication telemetry for affected recipients.

5. Deploy detections for MedDefense lookalike domains.

6. Tune email security rules for authentication failures combined with
   credential, invoice and benefits lures.

7. Review mailbox forwarding rules and suspicious account changes for users
   who interacted with campaign messages.

8. Provide targeted phishing awareness guidance using the observed IT,
   invoice and benefits pretexts.


### Medium-Term — Next 30 Days

1. Improve lookalike-domain and brand-impersonation detection.

2. Review email-gateway handling of SPF and DMARC failures.

3. Integrate validated campaign IOCs into email, DNS, web and detection
   controls.

4. Develop correlation between phishing reports, URL interaction and identity
   telemetry.

5. Implement monitoring for suspicious mailbox rules, MFA changes and
   authentication anomalies following phishing events.

6. Review incident-response procedures for reported phishing clicks.

7. Perform a retrospective campaign review to identify missed recipients or
   related infrastructure.

8. Share appropriate campaign indicators and findings with HC3 according to
   organizational information-sharing procedures.


## Final Assessment

The investigation identified four phishing-related emails: E2, E3, E5 and E7.
E1 and E6 were classified as spam, while E4 and E8 were legitimate.

The combined timing, targeting, social-engineering and technical
characteristics support the assessment that E2, E5 and E7 are likely parts of
a coordinated phishing campaign targeting multiple MedDefense business
functions. E8 provides healthcare-sector threat context consistent with that
assessment, while E3 is confirmed phishing but cannot be conclusively linked
to the same campaign from the supplied evidence.

The most urgent unresolved issue is Diane Marsh's confirmed interaction with
E2. The evidence proves the click but does not prove credential submission,
account takeover or endpoint compromise, making endpoint and identity
follow-up the immediate investigative priority.