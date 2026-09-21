# Final Email Verdict Matrix

This matrix provides the final classification of all eight emails after
reviewing email headers, authentication results, sender infrastructure,
URLs, attachments and social-engineering indicators.

| Email | Initial Class | Final Class | Confidence | Key Evidence | Recommended Action |
|---|---|---|---|---|---|
| E1 | SPAM | SPAM | HIGH | SPF, DKIM and DMARC pass; authenticated bulk newsletter; `Precedence: bulk`; MailChimp and unsubscribe indicators; no targeted security lure | Mark as spam or unwanted bulk mail; no incident escalation required |
| E2 | SUSPICIOUS | PHISHING-TARGETED | HIGH | MedDefense lookalike domain `meddefense-portal.com`; SPF fail; DKIM none; DMARC fail; PHPMailer 6.6.0; portal re-verification lure; 24-hour urgency; Diane Marsh confirmed clicking the link | Block/monitor indicators, investigate Diane's account and WS-NURSE-04, reset credentials if exposure cannot be excluded, revoke sessions and monitor authentication |
| E3 | SUSPICIOUS | PHISHING-OPPORTUNISTIC | HIGH | Claims to be Microsoft Account Protection but uses `outlook-protection.com`; account-verification lure; 48-hour account-lock threat; PHPMailer 6.6.0; SPF/DKIM/DMARC pass only for the lookalike domain | Block the phishing domain, search for additional recipients/clicks and monitor related authentication activity |
| E4 | LEGITIMATE | LEGITIMATE | HIGH | Internal `meddefense.com` sender; internal Exchange infrastructure; SPF, DKIM and DMARC pass; directs users to the normal internal portal rather than an external credential link | No security action required |
| E5 | SUSPICIOUS | PHISHING-TARGETED | HIGH | Unexpected $24,716.38 invoice; Accounts Payable recipient; SPF softfail; DKIM none; DMARC fail; PHPMailer 6.6.0; suspicious invoice/login URLs; PDF attachment; recipient reported invoice looked wrong | Quarantine related messages, block/monitor indicators, investigate recipients and safely analyze attachment metadata/hash |
| E6 | SPAM | SPAM | HIGH | Unsolicited pharmaceutical advertising; spam score 9.8; SPF softfail; DKIM none; DMARC fail with quarantine action; direct numeric-IP HTTP link | Quarantine or delete as spam and block related sender/infrastructure according to mail-security policy |
| E7 | SUSPICIOUS | PHISHING-TARGETED | HIGH | MedDefense HR impersonation; lookalike `meddefense-benefits.org` domain; SPF fail; DKIM none; DMARC fail; PHPMailer 6.6.0; open-enrollment deadline lure | Block the domain, quarantine matching messages, identify other recipients and investigate any reported clicks |
| E8 | LEGITIMATE | LEGITIMATE | HIGH | HHS/HC3 sender; SPF, DKIM and DMARC pass for `hhs.gov`; healthcare-sector phishing advisory consistent with the investigation context | Retain as legitimate threat-intelligence information and use the advisory to support investigation |

## Final Classification Summary

- SPAM: E1, E6
- PHISHING-OPPORTUNISTIC: E3
- PHISHING-TARGETED: E2, E5, E7
- LEGITIMATE: E4, E8
- LEGITIMATE-WITH-ISSUE: None


## Classification Changes After Deeper Analysis

### E2

Initial classification: `SUSPICIOUS`

Final classification: `PHISHING-TARGETED`

Deeper analysis identified a MedDefense lookalike domain, failed SPF and DMARC,
no DKIM signature, PHPMailer infrastructure, a portal re-verification lure and
a URL containing Diane Marsh's email address.

The evidence batch also confirms that Diane clicked the link from
WS-NURSE-04, increasing the operational importance of the incident.


### E3

Initial classification: `SUSPICIOUS`

Final classification: `PHISHING-OPPORTUNISTIC`

E3 initially appeared more trustworthy because SPF, DKIM and DMARC all pass.

Deeper analysis showed that those mechanisms authenticate
`outlook-protection.com`, not Microsoft. The email claims to represent
Microsoft Account Protection, but `outlook-protection.com` is not the same
domain as `microsoft.com` or `outlook.com`.

The account-verification lure, account-lock threat and lookalike branding
support the final phishing classification.


### E5

Initial classification: `SUSPICIOUS`

Final classification: `PHISHING-TARGETED`

Deeper analysis identified an invoice specifically relevant to an Accounts
Payable workflow, a payment amount of $24,716.38, suspicious invoice/login
URLs and a PDF attachment.

SPF softfailed, DKIM was absent and DMARC failed. The recipient also reported
that the invoice looked wrong.

The combination of recipient role, financial pretext and technical indicators
supports a targeted phishing classification.


### E7

Initial classification: `SUSPICIOUS`

Final classification: `PHISHING-TARGETED`

Deeper analysis identified impersonation of MedDefense HR using the lookalike
domain `meddefense-benefits.org`.

SPF failed, DKIM was absent and DMARC failed. The message also uses an urgent
open-enrollment deadline to pressure the recipient into interacting with an
external page.

These indicators support a targeted phishing classification.


## Triage Accuracy Assessment

The initial triage correctly separated the eight emails into the appropriate
high-level investigation categories:

- E1 correctly identified as spam.
- E2 correctly identified as suspicious.
- E3 correctly identified as suspicious.
- E4 correctly identified as legitimate.
- E5 correctly identified as suspicious.
- E6 correctly identified as spam.
- E7 correctly identified as suspicious.
- E8 correctly identified as legitimate.

Therefore:

- Correct initial triage decisions: 8 of 8
- Triage accuracy: 100%

The initial `SUSPICIOUS` classification for E2, E3, E5 and E7 was appropriate
for first-pass triage. Deeper investigation then provided enough evidence to
replace the broad suspicious label with specific phishing classifications.


## Recommended Response Summary

E2 requires the highest operational attention because a user interaction is
confirmed. Diane Marsh's account and WS-NURSE-04 should be investigated and
precautionary credential/session containment should be considered if
credential exposure cannot be excluded.

E3 should be treated as phishing despite passing email authentication because
the authenticated domain is the lookalike `outlook-protection.com`, not
Microsoft.

E5 should be treated as targeted phishing against the Accounts Payable
workflow. The attachment and associated infrastructure should be investigated
using safe static and passive methods.

E7 should be treated as targeted HR-themed phishing. Matching messages should
be identified and quarantined, and recipients should be checked for interaction.

E1 and E6 can be handled as spam, while E4 and E8 require no phishing
containment action.