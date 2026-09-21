# Email Authentication Analysis

## Email 1 — healthcare-education-weekly.com

- SPF: PASS — The sending IP 198.51.100.42 is authorized to send email for healthcare-education-weekly.com.
- DKIM: PASS — The message contains a valid DKIM signature for healthcare-education-weekly.com using selector `mail01`.
- DMARC: PASS — The visible From domain aligns with the authenticated domain. The header shows `action=none`.
- Authentication verdict: Authentication supports the apparent sender identity.
- Investigation meaning: The authentication results are consistent with a legitimate bulk newsletter. Other headers such as `Precedence: bulk`, MailChimp and unsubscribe information also support this interpretation.
- Final verdict: SPAM / authenticated bulk newsletter.


## Email 2 — meddefense-portal.com

- SPF: FAIL — The sending IP 91.234.99.107 is explicitly shown as not authorized to send email for meddefense-portal.com.
- DKIM: NONE — The message contains no DKIM signature, so no cryptographic domain authentication is available.
- DMARC: FAIL — Authentication does not satisfy DMARC for the visible From domain. The header shows `action=none`.
- Authentication verdict: Authentication contradicts the apparent legitimacy of the message.
- Investigation meaning: The sender claims to represent MedDefense IT Security, but the message uses the external lookalike domain `meddefense-portal.com`. SPF fails, DKIM is absent and DMARC fails. These results strongly support the phishing suspicion.
- Final verdict: SUSPICIOUS — strong authentication failures and domain impersonation indicators.


## Email 3 — outlook-protection.com

- SPF: PASS — The sending IP 51.38.42.17 is authorized to send email for outlook-protection.com.
- DKIM: PASS — The message has a valid DKIM signature for `outlook-protection.com` using selector `default`.
- DMARC: PASS — The authenticated domain aligns with the visible From domain `outlook-protection.com`. The header shows `action=none`.
- Authentication verdict: Authentication confirms that the message was legitimately sent on behalf of `outlook-protection.com`, but it does not confirm that the sender is Microsoft.
- Investigation meaning: The email presents itself as "Microsoft Account Protection", but `outlook-protection.com` is not the same domain as `microsoft.com` or `outlook.com`. A malicious actor can register a lookalike domain and correctly configure SPF, DKIM and DMARC for that domain. Therefore, passing all three authentication mechanisms does not make this email legitimate.
- Final verdict: SUSPICIOUS — authentication passes for the sender-controlled domain, but does not validate the claimed Microsoft identity.


## Email 4 — meddefense.com

- SPF: PASS — The sending IP 10.10.1.15 is identified as an internal MedDefense system and is authorized for meddefense.com.
- DKIM: PASS — The message has a valid DKIM signature for meddefense.com using selector `selector1`.
- DMARC: PASS — The authenticated domain aligns with the visible From domain `meddefense.com`. The header shows `action=none`.
- Authentication verdict: Authentication supports the apparent legitimacy of the email.
- Investigation meaning: The message originates from internal MedDefense Exchange infrastructure and all three authentication mechanisms pass for the legitimate meddefense.com domain.
- Final verdict: LEGITIMATE.


## Email 5 — medequip-supplies.net

- SPF: SOFTFAIL — The sending IP 185.176.43.22 is not clearly authorized for medequip-supplies.net. A softfail indicates that the domain's SPF policy identifies the sender as probably unauthorized, but does not request a hard rejection.
- DKIM: NONE — The message is not DKIM-signed.
- DMARC: FAIL — Authentication does not satisfy DMARC for the visible From domain. The header shows `action=none`.
- Authentication verdict: Authentication weakens the apparent legitimacy of the invoice email.
- Investigation meaning: SPF softfails, DKIM is absent and DMARC fails. Combined with the unexpected invoice, payment links and attachment, the authentication evidence supports continued phishing investigation.
- Final verdict: SUSPICIOUS.


## Email 6 — canadian-pharma-discount.org

- SPF: SOFTFAIL — The sender does not clearly pass the SPF authorization policy for canadian-pharma-discount.org.
- DKIM: NONE — No DKIM signature is present.
- DMARC: FAIL — DMARC validation fails and the header specifies `action=quarantine`.
- Authentication verdict: Authentication does not support trusting the sender.
- Investigation meaning: DMARC indicates quarantine rather than normal delivery. The message also has a spam score of 9.8 and obvious unsolicited pharmaceutical advertising, so the authentication failures reinforce the spam classification.
- Final verdict: SPAM.


## Email 7 — meddefense-benefits.org

- SPF: FAIL — The sending IP 164.90.218.73 is explicitly shown as not authorized to send email for meddefense-benefits.org.
- DKIM: NONE — The message contains no DKIM signature.
- DMARC: FAIL — Authentication does not satisfy DMARC for the visible From domain. The header shows `action=none`.
- Authentication verdict: Authentication contradicts the apparent claim that this is legitimate MedDefense HR communication.
- Investigation meaning: The sender claims to represent MedDefense HR Benefits while using the external lookalike domain `meddefense-benefits.org`. SPF fails, DKIM is absent and DMARC fails, providing strong evidence supporting phishing suspicion.
- Final verdict: SUSPICIOUS — likely MedDefense impersonation.


## Email 8 — hhs.gov

- SPF: PASS — The sending IP 134.174.47.82 is authorized to send email for hhs.gov.
- DKIM: PASS — The message contains a valid DKIM signature for hhs.gov using selector `hhs2026`.
- DMARC: PASS — The authenticated domain aligns with the visible From domain `hhs.gov`. The header shows `action=none`.
- Authentication verdict: Authentication supports the apparent HHS/HC3 sender identity.
- Investigation meaning: SPF, DKIM and DMARC all pass for hhs.gov. The message also uses HHS mail infrastructure and identifies itself as an HC3 sector alert. The authentication evidence is consistent with the message's apparent identity.
- Final verdict: LEGITIMATE.


## Authentication Summary

| Email | SPF | DKIM | DMARC | DMARC Action | Verdict |
|---|---|---|---|---|---|
| E1 | PASS | PASS | PASS | none | SPAM / authenticated bulk mail |
| E2 | FAIL | NONE | FAIL | none | SUSPICIOUS |
| E3 | PASS | PASS | PASS | none | SUSPICIOUS |
| E4 | PASS | PASS | PASS | none | LEGITIMATE |
| E5 | SOFTFAIL | NONE | FAIL | none | SUSPICIOUS |
| E6 | SOFTFAIL | NONE | FAIL | quarantine | SPAM |
| E7 | FAIL | NONE | FAIL | none | SUSPICIOUS |
| E8 | PASS | PASS | PASS | none | LEGITIMATE |