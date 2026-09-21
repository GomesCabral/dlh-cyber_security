# Social Engineering Analysis

## Email 2 — Portal re-verification lure

- Psychological lever: Urgency, fear, authority and impersonation.
- Pretext: The sender impersonates MedDefense IT Security and claims that the recipient's portal access must be re-verified within 24 hours to avoid account restrictions.
- Requested action: Click the verification link and verify portal access.
- Targeting level: TARGETED
- Content red flags:
  - Claims to represent MedDefense IT Security.
  - Uses the lookalike domain `meddefense-portal.com`.
  - Creates a 24-hour deadline.
  - Threatens loss or restriction of portal access.
  - Directs the recipient to an external verification page.
  - Uses security/account verification as justification for requesting immediate action.
- Attacker knowledge required:
  - The MedDefense organization name.
  - Knowledge that employees use a portal.
  - The recipient's email address.
  - Knowledge of terminology that would appear normal in an IT/security notification.
- Conclusion: E2 uses a targeted credential-verification pretext. By impersonating internal IT and combining authority, urgency and fear of losing access, the attacker attempts to push the recipient into clicking the link without independently verifying the request.


## Email 3 — Microsoft 365 account security lure

- Psychological lever: Fear, urgency, authority and impersonation.
- Pretext: The sender impersonates Microsoft Account Protection and claims that unusual sign-in activity was detected on the recipient's Microsoft 365 account.
- Requested action: Click the supplied link and verify the account.
- Targeting level: SEMI-TARGETED
- Content red flags:
  - Claims to be Microsoft Account Protection.
  - Uses `outlook-protection.com` rather than `microsoft.com` or `outlook.com`.
  - Claims that unusual account activity occurred.
  - Creates a 48-hour deadline.
  - Threatens account locking if the recipient does not act.
  - Directs the recipient to an external verification page.
- Attacker knowledge required:
  - The recipient's email address.
  - Knowledge or assumption that the organization uses Microsoft 365.
  - Familiarity with common Microsoft security notification language.
- Conclusion: E3 uses fear of account compromise and loss of access to encourage rapid action. The lure is more customized than generic phishing because it references Microsoft 365, but it does not require the same level of internal MedDefense knowledge as E2.


## Email 5 — Invoice lure

- Psychological lever: Financial pressure, urgency and authority.
- Pretext: The sender impersonates a medical equipment supplier and claims that invoice `INV-2026-04891` for $24,716.38 must be paid within seven days.
- Requested action: Review the invoice, open the attached PDF and/or use the external invoice/payment links.
- Targeting level: TARGETED
- Content red flags:
  - Unexpected high-value invoice.
  - Specific invoice number and payment deadline.
  - Large payment amount of $24,716.38.
  - External payment/login links.
  - PDF attachment.
  - Payment pressure designed to encourage quick processing.
  - The recipient reported that the invoice looked wrong.
- Attacker knowledge required:
  - The recipient's email address.
  - Knowledge that the recipient works in Accounts Payable or handles invoices.
  - Knowledge that medical suppliers would be plausible vendors for the organization.
  - Familiarity with normal invoice and payment workflows.
- Conclusion: E5 is a targeted financial phishing lure. The attacker uses a plausible medical supplier scenario, invoice details and payment pressure to make the request fit the recipient's professional responsibilities.


## Email 7 — Employee benefits lure

- Psychological lever: Urgency, scarcity, authority and impersonation.
- Pretext: The sender impersonates MedDefense HR Benefits and claims that open enrollment closes the following day, requiring immediate employee action.
- Requested action: Click the supplied link and complete or review benefits enrollment.
- Targeting level: TARGETED
- Content red flags:
  - Claims to represent MedDefense HR Benefits.
  - Uses the lookalike domain `meddefense-benefits.org`.
  - Uses "closes TOMORROW" to create urgency.
  - Creates fear of missing an enrollment deadline.
  - Directs the recipient to an external benefits page.
  - The recipient reported that she never signed up for the referenced process.
- Attacker knowledge required:
  - The MedDefense organization name.
  - The recipient's email address.
  - Knowledge that employee benefits/open enrollment is a plausible HR process.
  - Familiarity with HR terminology and employee workflows.
- Conclusion: E7 uses a targeted HR impersonation pretext. The attacker combines authority with deadline pressure and fear of missing employee benefits to encourage the recipient to click before verifying the message.


## Social Engineering Summary

| Email | Main Lever | Pretext | Requested Action | Targeting |
|---|---|---|---|---|
| E2 | Urgency / Fear / Authority | Portal re-verification | Click and verify | TARGETED |
| E3 | Fear / Urgency | Microsoft 365 security alert | Click and verify account | SEMI-TARGETED |
| E5 | Financial pressure / Urgency | Supplier invoice | Review/pay/open attachment | TARGETED |
| E7 | Urgency / Scarcity / Authority | Benefits enrollment | Click and complete enrollment | TARGETED |