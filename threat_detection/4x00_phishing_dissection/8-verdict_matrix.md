# Final Email Verdict Matrix

| Email | Initial Class | Final Class | Confidence | Key Evidence | Recommended Action |
|---|---|---|---|---|---|
| E1 | SPAM | SPAM | HIGH | SPF, DKIM and DMARC pass; authenticated bulk newsletter; bulk-mail and unsubscribe indicators; no credential or payment lure | Mark as spam or unwanted bulk mail |
| E2 | SUSPICIOUS | PHISHING-TARGETED | HIGH | MedDefense lookalike domain `meddefense-portal.com`; SPF fail; DKIM none; DMARC fail; portal re-verification lure; 24-hour urgency; Diane Marsh confirmed clicking the link | Investigate Diane and WS-NURSE-04, reset password if exposure cannot be excluded, revoke sessions, monitor logins and block indicators |
| E3 | SUSPICIOUS | PHISHING-TARGETED | HIGH | Impersonates Microsoft Account Protection; uses `outlook-protection.com` instead of a Microsoft-owned domain; credential-verification lure; account-lock threat; PHPMailer 6.6.0; authentication passes only for the lookalike sender domain | Block the domain, quarantine matching messages, identify recipients and investigate clicks or credential submission |
| E4 | LEGITIMATE | LEGITIMATE | HIGH | Internal `meddefense.com` sender; internal Exchange infrastructure; SPF, DKIM and DMARC pass; directs users to the normal internal portal | No security action required |
| E5 | SUSPICIOUS | PHISHING-TARGETED | HIGH | Unexpected $24,716.38 invoice; Accounts Payable context; SPF softfail; DKIM none; DMARC fail; suspicious invoice and login URLs; PDF attachment; recipient reported invoice looked wrong | Quarantine matching messages, block indicators, investigate recipients and safely analyze the attachment |
| E6 | SPAM | SPAM | HIGH | Unsolicited pharmaceutical advertising; spam score 9.8; SPF softfail; DKIM none; DMARC fail; direct numeric-IP HTTP link | Quarantine or delete as spam and block related spam infrastructure according to policy |
| E7 | SUSPICIOUS | PHISHING-TARGETED | HIGH | MedDefense HR impersonation; lookalike domain `meddefense-benefits.org`; SPF fail; DKIM none; DMARC fail; urgent open-enrollment lure | Block the domain, quarantine matching messages, identify recipients and investigate reported interaction |
| E8 | LEGITIMATE | LEGITIMATE | HIGH | Authenticated HHS/HC3 sender; SPF, DKIM and DMARC pass for `hhs.gov`; message is a healthcare phishing advisory relevant to the investigation | Retain as legitimate threat-intelligence information |

## Final Classification Summary

- E1: SPAM
- E2: PHISHING-TARGETED
- E3: PHISHING-TARGETED
- E4: LEGITIMATE
- E5: PHISHING-TARGETED
- E6: SPAM
- E7: PHISHING-TARGETED
- E8: LEGITIMATE

The final investigation therefore identifies:

- Spam-related emails: E1 and E6
- Phishing-related emails: E2, E3, E5 and E7
- Legitimate emails: E4 and E8


## Classification Changes After Deeper Analysis

### E2 — SUSPICIOUS to PHISHING-TARGETED

Initial triage identified E2 as suspicious.

Deeper analysis confirmed multiple phishing indicators: the sender impersonates
MedDefense IT Security, uses the lookalike domain `meddefense-portal.com`,
fails SPF and DMARC, has no DKIM signature and directs Diane Marsh to a portal
re-verification URL.

The URL also contains Diane's email address and the evidence confirms that she
clicked the link.

Final classification: PHISHING-TARGETED.


### E3 — SUSPICIOUS to PHISHING-TARGETED

Initial triage identified E3 as suspicious.

Deeper analysis showed that the message impersonates Microsoft Account
Protection and attempts to convince the recipient to perform account
verification.

Although SPF, DKIM and DMARC pass, they authenticate
`outlook-protection.com`. They do not authenticate Microsoft.

The sender uses a Microsoft-themed lookalike domain, an unusual-sign-in
security pretext and a threat that the account will be locked within 48 hours.

The combination of brand impersonation, credential-verification pretext and
urgency supports a phishing classification.

Final classification: PHISHING-TARGETED.


### E5 — SUSPICIOUS to PHISHING-TARGETED

Initial triage identified E5 as suspicious.

Deeper analysis identified an unexpected invoice for $24,716.38, suspicious
invoice and login URLs and a PDF attachment.

The email is relevant to an Accounts Payable workflow, making the financial
pretext more targeted than generic spam.

SPF softfailed, DKIM was absent and DMARC failed. The recipient also reported
that the invoice looked wrong.

Final classification: PHISHING-TARGETED.


### E7 — SUSPICIOUS to PHISHING-TARGETED

Initial triage identified E7 as suspicious.

Deeper analysis showed that the sender impersonates MedDefense HR Benefits
using the lookalike domain `meddefense-benefits.org`.

SPF failed, DKIM was absent and DMARC failed. The message also pressures the
recipient with an open-enrollment deadline and directs the recipient to an
external enrollment page.

Final classification: PHISHING-TARGETED.


## Why E1 and E6 Remain Spam

E1 remains SPAM because it is an authenticated bulk newsletter. SPF, DKIM and
DMARC pass, and the message contains bulk-mail and unsubscribe characteristics.
The investigation found no targeted credential, payment or account-security
pretext.

E6 remains SPAM because it is unsolicited pharmaceutical advertising with a
high spam score and bulk advertising characteristics. Its authentication
failures and numeric-IP link increase suspicion, but the evidence supports
spam classification rather than the targeted phishing pattern identified in
E2, E3, E5 and E7.


## Why E4 and E8 Remain Legitimate

E4 remains LEGITIMATE because it originates from MedDefense infrastructure,
passes SPF, DKIM and DMARC and instructs employees to use the normal internal
portal rather than an external credential-verification page.

E8 remains LEGITIMATE because it is an authenticated HHS/HC3 healthcare
security advisory. SPF, DKIM and DMARC pass for `hhs.gov`, and the advisory is
consistent with the phishing activity being investigated.


## Triage Accuracy Assessment

The initial triage correctly separated all eight emails into the appropriate
high-level investigation categories.

- E1 was correctly identified as spam.
- E2 was correctly identified as suspicious.
- E3 was correctly identified as suspicious.
- E4 was correctly identified as legitimate.
- E5 was correctly identified as suspicious.
- E6 was correctly identified as spam.
- E7 was correctly identified as suspicious.
- E8 was correctly identified as legitimate.

Correct initial triage decisions: 8 of 8.

Triage accuracy: 100%.

The initial SUSPICIOUS label for E2, E3, E5 and E7 was appropriate during
first-pass triage. Deeper investigation provided sufficient evidence to
replace that broad label with the final phishing classification.


## Recommended Actions

E2 requires immediate follow-up because Diane Marsh confirmed clicking the
phishing link. Her account and WS-NURSE-04 should be investigated. Password
reset, session revocation and increased authentication monitoring should be
performed if credential exposure cannot be excluded.

E3 should be blocked and matching messages should be quarantined. Recipients
should be identified and checked for clicks or credential submission.

E5 should be quarantined and its indicators blocked or monitored. The PDF
attachment should be analyzed safely using hashes, metadata and an authorized
isolated analysis environment.

E7 should be blocked and matching messages quarantined. Other recipients
should be identified and investigated for interaction with the phishing link.


## Conclusion

The final evidence-based verdict is:

E1 and E6 are spam-related messages.

E2, E3, E5 and E7 are phishing-related messages.

E4 and E8 are legitimate messages.

E2 is the highest-priority phishing incident because the evidence confirms
that Diane Marsh clicked the phishing link.