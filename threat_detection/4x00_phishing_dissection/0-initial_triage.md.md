# Initial Email Triage

| Email | From | Subject | SPF | DKIM | DMARC | Class | Priority | Evidence |
|---|---|---|---|---|---|---|---|---|
| E1 | newsletter@healthcare-education-weekly.com | Your April newsletter: Medication reconciliation best practices | PASS | PASS | PASS | SPAM | P4-LOW | Authenticated bulk newsletter with `Precedence: bulk`, MailChimp headers and unsubscribe information. No urgent or targeted security request. |
| E2 | noreply@meddefense-portal.com | ACTION REQUIRED: Portal re-verification needed within 24 hours | FAIL | NONE | FAIL | SUSPICIOUS | P1-URGENT | Lookalike MedDefense domain, failed SPF/DMARC, no DKIM, PHPMailer, urgent 24-hour deadline and credential-verification link. Diane Marsh confirmed clicking the link. |
| E3 | security@outlook-protection.com | Unusual sign-in activity detected on your Microsoft 365 account | PASS | PASS | PASS | SUSPICIOUS | P2-HIGH | Claims to be Microsoft but uses `outlook-protection.com`, creates urgency with a 48-hour account-lock threat and directs the user to an account verification page. Authentication only validates the sender's domain, not Microsoft ownership. |
| E4 | it-announcements@meddefense.com | Reminder: Quarterly password change window opens April 20 | PASS | PASS | PASS | LEGITIMATE | P4-LOW | Internal MedDefense sender via internal Exchange infrastructure, all authentication checks pass, and users are instructed to use the normal internal portal rather than an external password-change link. |
| E5 | invoices@medequip-supplies.net | Invoice INV-2026-04891 — Payment required within 7 days | SOFTFAIL | NONE | FAIL | SUSPICIOUS | P2-HIGH | SPF softfail, no DKIM, DMARC failure, unexpected high-value invoice, payment/login links and PDF attachment. Angela Rivera reported that the invoice looks wrong. |
| E6 | deals@canadian-pharma-discount.org | 90% OFF Viagra, Cialis, Xanax — No prescription needed!!! | SOFTFAIL | NONE | FAIL | SPAM | P4-LOW | Obvious unsolicited pharmaceutical advertising. Spam score is 9.8 and the message contains a direct numeric-IP HTTP link and bulk-mail characteristics. |
| E7 | hr-notifications@meddefense-benefits.org | Open Enrollment closes TOMORROW — action required | FAIL | NONE | FAIL | SUSPICIOUS | P2-HIGH | Lookalike MedDefense benefits domain, SPF and DMARC fail, no DKIM, PHPMailer infrastructure and urgency-based enrollment lure. Linda Patterson reported that she never signed up for anything. |
| E8 | HC3@hhs.gov | [HC3 ALERT — TLP:CLEAR] Active phishing campaign targeting regional healthcare | PASS | PASS | PASS | LEGITIMATE | P3-MEDIUM | Authenticated HHS sender with SPF, DKIM and DMARC passing. Message contains an HC3 advisory reference and describes an active healthcare phishing campaign relevant to the investigation. |

## Triage Summary

- SPAM: E1, E6
- SUSPICIOUS: E2, E3, E5, E7
- LEGITIMATE: E4, E8
- Highest priority: E2 (P1-URGENT) because Diane Marsh confirmed clicking the suspicious verification link approximately 36 hours before the investigation.