# URL and Attachment Autopsy

This analysis uses only indicators contained in the supplied email evidence.
Suspicious URLs were not opened directly and attachments were not executed or
opened on the analyst workstation.

## Indicator 1 — MedDefense Portal Lookalike

- Source email: E2
- Original value: https://meddefense-portal.com/verify?user=dmarsh@meddefense.com
- Defanged value: hxxps://meddefense-portal[.]com/verify?user=dmarsh@meddefense[.]com
- Domain or IP: meddefense-portal.com
- Indicator type: URL / lookalike domain / credential-verification lure
- Evidence from email:
  - The sender claims to represent MedDefense IT Security.
  - The domain resembles the legitimate `meddefense.com` domain but adds `-portal`.
  - The URL contains a `/verify` path.
  - The recipient's MedDefense email address appears in the URL parameter.
  - The message creates a 24-hour deadline.
  - SPF failed, DKIM was absent and DMARC failed.
  - The sending IP observed in the email headers was `91.234.99.107`.
  - Diane Marsh reported clicking the link.
- Safe investigation method:
  - `whois meddefense-portal.com`
  - `dig meddefense-portal.com`
  - `nslookup meddefense-portal.com`
  - Passive VirusTotal domain/URL lookup
  - Passive urlscan.io search
  - `curl -I` only from an isolated investigation environment if authorized
- Finding: The URL is highly suspicious because it impersonates the MedDefense name, requests portal verification and includes the targeted employee's email address. The reported click increases the incident relevance.
- Risk rating: HIGH


## Indicator 2 — Outlook Protection Lookalike

- Source email: E3
- Original value: https://outlook-protection.com/account/verify
- Defanged value: hxxps://outlook-protection[.]com/account/verify
- Domain or IP: outlook-protection.com
- Indicator type: URL / brand impersonation / credential-verification lure
- Evidence from email:
  - The message claims to be from Microsoft Account Protection.
  - `outlook-protection.com` is not the same domain as `microsoft.com` or `outlook.com`.
  - The URL uses an `/account/verify` path consistent with the account-verification pretext.
  - The message claims unusual sign-in activity and threatens account locking.
  - SPF, DKIM and DMARC pass, but only authenticate `outlook-protection.com`.
  - The message was generated using PHPMailer 6.6.0.
  - The sending IP observed in the headers was `51.38.42.17`.
- Safe investigation method:
  - `whois outlook-protection.com`
  - `dig outlook-protection.com`
  - `nslookup outlook-protection.com`
  - Passive VirusTotal domain/URL lookup
  - Passive urlscan.io search
  - `curl -I` only from an isolated investigation environment if authorized
- Finding: The domain is suspicious because it presents itself as Microsoft-related infrastructure while using a separate lookalike domain. Successful SPF, DKIM and DMARC authentication does not establish Microsoft ownership.
- Risk rating: HIGH


## Indicator 3 — MedEquip Invoice Infrastructure

- Source email: E5
- Original value: https://medequip-supplies.net/invoices/INV-2026-04891
- Defanged value: hxxps://medequip-supplies[.]net/invoices/INV-2026-04891
- Domain or IP: medequip-supplies.net
- Indicator type: URL / invoice lure
- Evidence from email:
  - The URL is associated with invoice `INV-2026-04891`.
  - The message requests payment of $24,716.38 within seven days.
  - The recipient reported that the invoice looked wrong.
  - SPF softfailed, DKIM was absent and DMARC failed.
  - The sending IP observed in the headers was `185.176.43.22`.
  - The message was generated using PHPMailer 6.6.0.
- Safe investigation method:
  - `whois medequip-supplies.net`
  - `dig medequip-supplies.net`
  - `nslookup medequip-supplies.net`
  - Passive VirusTotal domain/URL lookup
  - Passive urlscan.io search
  - `curl -I` only from an isolated investigation environment if authorized
- Finding: The URL is suspicious because it is embedded in an unexpected high-value invoice workflow and appears together with authentication failures and other phishing indicators.
- Risk rating: HIGH


## Indicator 4 — MedEquip Login URL

- Source email: E5
- Original value: https://medequip-supplies.net/portal/login
- Defanged value: hxxps://medequip-supplies[.]net/portal/login
- Domain or IP: medequip-supplies.net
- Indicator type: URL / login page
- Evidence from email:
  - The URL points to a login path on the same infrastructure used by the suspicious invoice lure.
  - The message pressures the recipient to interact with an unexpected invoice.
  - The same email contains a PDF attachment.
  - SPF softfailed, DKIM was absent and DMARC failed.
- Safe investigation method:
  - Passive VirusTotal URL/domain lookup
  - Passive urlscan.io search
  - WHOIS and DNS investigation of the parent domain
  - HTTP header inspection only from an isolated environment if authorized
- Finding: A login endpoint associated with the suspicious invoice infrastructure could potentially be used for credential collection. The email evidence alone does not prove credential harvesting, so further sandbox or passive intelligence analysis would be required.
- Risk rating: HIGH


## Indicator 5 — Invoice PDF Attachment

- Source email: E5
- Original value: Invoice_INV-2026-04891.pdf
- Defanged value: Invoice_INV-2026-04891[.]pdf
- Domain or IP: N/A
- Indicator type: PDF attachment
- Evidence from email:
  - The attachment uses the same invoice number as the email pretext.
  - The email requests payment of $24,716.38.
  - The recipient reported that the invoice looked wrong.
  - The message contains suspicious external invoice and login infrastructure.
  - Email authentication is weak: SPF softfail, no DKIM and DMARC fail.
- Safe investigation method:
  - Do not open the PDF on the workstation.
  - Extract metadata and hashes in an isolated analysis environment.
  - Calculate SHA-256 with `sha256sum`.
  - Inspect metadata with `pdfinfo` or `exiftool`.
  - Inspect PDF structure with tools such as `pdfid.py`.
  - Submit the hash to VirusTotal before considering file submission.
  - Use an authorized malware sandbox if deeper analysis is required.
- Finding: The attachment is suspicious because it supports the unexpected high-value invoice lure. The raw email evidence provides an attachment indicator, but the attachment must not be declared malicious without further analysis.
- Risk rating: HIGH


## Indicator 6 — MedDefense Benefits Lookalike

- Source email: E7
- Original value: https://meddefense-benefits.org/enrollment
- Defanged value: hxxps://meddefense-benefits[.]org/enrollment
- Domain or IP: meddefense-benefits.org
- Indicator type: URL / lookalike domain / HR phishing lure
- Evidence from email:
  - The sender claims to represent MedDefense HR Benefits.
  - The domain resembles MedDefense but is not `meddefense.com`.
  - The URL uses an `/enrollment` path consistent with the benefits pretext.
  - The message claims that enrollment closes the following day.
  - SPF failed, DKIM was absent and DMARC failed.
  - The sending IP observed in the headers was `164.90.218.73`.
  - The message was generated using PHPMailer 6.6.0.
- Safe investigation method:
  - `whois meddefense-benefits.org`
  - `dig meddefense-benefits.org`
  - `nslookup meddefense-benefits.org`
  - Passive VirusTotal domain/URL lookup
  - Passive urlscan.io search
  - `curl -I` only from an isolated investigation environment if authorized
- Finding: The URL is highly suspicious because it uses a MedDefense lookalike domain and an HR benefits pretext designed to create deadline pressure.
- Risk rating: HIGH


## Indicator 7 — Suspicious IP Address

- Source email: E5
- Original value: 203.0.113.228
- Defanged value: 203[.]0[.]113[.]228
- Domain or IP: 203.0.113.228
- Indicator type: IPv4 indicator
- Evidence from email:
  - The IP appears as an indicator associated with the suspicious E5 invoice evidence.
  - E5 contains external invoice/payment infrastructure and a PDF attachment.
  - The email uses financial pressure and requests interaction with suspicious resources.
- Safe investigation method:
  - `whois 203.0.113.228`
  - Reverse DNS lookup with `dig -x 203.0.113.228`
  - `nslookup 203.0.113.228`
  - Passive VirusTotal IP lookup
  - Passive reputation and historical DNS lookup
- Finding: The IP should be preserved as an IOC candidate and correlated with the other E5 indicators. Conclusions should be based on the supplied evidence and passive investigation rather than direct browsing.
- Risk rating: HIGH


## Cross-Indicator Findings

The suspicious emails contain several recurring characteristics:

- E2 and E7 use MedDefense lookalike domains.
- E3 uses a Microsoft/Outlook-themed lookalike domain.
- E5 uses invoice and payment infrastructure relevant to the recipient's work.
- E2, E3, E5 and E7 were generated using PHPMailer 6.6.0.
- Their Message-IDs follow a similar `PHP-*` pattern.
- The URLs use action-oriented paths such as `/verify`, `/account/verify`, `/portal/login` and `/enrollment`.
- E5 also introduces an attachment into the attack surface.

These similarities provide useful correlation indicators, but they do not by themselves prove that every email was sent by the same threat actor.

## Safety Notes

Suspicious URLs must not be opened directly in a browser.

For reporting and ticketing, URLs and IP addresses should be defanged. Passive
services such as VirusTotal and urlscan.io can be searched without directly
navigating to the suspicious site.

Commands such as `whois`, `dig` and `nslookup` can provide infrastructure
information without browsing to the phishing page. `curl -I` still contacts the
remote server and should therefore only be used from an authorized isolated
analysis environment.

Attachments must not be opened on the analyst workstation. Metadata, hashes and
static analysis should be collected in an isolated environment before any
deeper investigation.