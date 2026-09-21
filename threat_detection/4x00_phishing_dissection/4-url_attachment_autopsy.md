# URL and Attachment Autopsy

This investigation was performed using only the supplied email evidence.
No suspicious URL was opened directly and no suspicious attachment was opened
on the analyst workstation.

All suspicious URLs and IP addresses are defanged for safe documentation.

## Indicator 1 — MedDefense Portal Lookalike

- Source email: E2
- Original value: `https://meddefense-portal.com/verify?user=dmarsh@meddefense.com`
- Defanged value: `hxxps://meddefense-portal[.]com/verify?user=dmarsh@meddefense[.]com`
- Domain or IP: `meddefense-portal.com`
- Indicator type: URL / lookalike domain / credential verification lure
- Evidence from email:
  - The sender claims to represent MedDefense IT Security.
  - The domain resembles the legitimate `meddefense.com` domain but adds `-portal`.
  - The URL contains a `/verify` path.
  - The recipient's MedDefense email address appears in the URL parameter.
  - The message creates a 24-hour deadline.
  - SPF failed.
  - DKIM was absent.
  - DMARC failed.
  - The sending IP observed in the email headers was `91.234.99.107`.
  - Diane Marsh reported clicking the link.
- Safe investigation method:
  - Query domain registration information with `whois meddefense-portal.com`.
  - Query DNS information with `dig meddefense-portal.com`.
  - Query DNS information with `nslookup meddefense-portal.com`.
  - Search the defanged domain or URL using VirusTotal passive intelligence.
  - Search existing urlscan.io results for the defanged domain.
  - Do not navigate directly to the suspicious URL.
- Finding: The URL is highly suspicious because it uses a MedDefense lookalike domain, requests portal verification and contains the targeted employee's email address. The reported click makes this indicator especially important to the investigation.
- Risk rating: HIGH


## Indicator 2 — Outlook Protection Lookalike

- Source email: E3
- Original value: `https://outlook-protection.com/account/verify`
- Defanged value: `hxxps://outlook-protection[.]com/account/verify`
- Domain or IP: `outlook-protection.com`
- Indicator type: URL / brand impersonation / credential verification lure
- Evidence from email:
  - The message claims to be from Microsoft Account Protection.
  - `outlook-protection.com` is not the same domain as `microsoft.com` or `outlook.com`.
  - The URL contains an `/account/verify` path.
  - The message claims that unusual sign-in activity occurred.
  - The recipient is threatened with account locking if no action is taken.
  - SPF, DKIM and DMARC pass, but they authenticate `outlook-protection.com`, not Microsoft.
  - The message was generated using PHPMailer 6.6.0.
  - The sending IP observed in the headers was `51.38.42.17`.
- Safe investigation method:
  - Query domain registration information with `whois outlook-protection.com`.
  - Query DNS information with `dig outlook-protection.com`.
  - Query DNS information with `nslookup outlook-protection.com`.
  - Search the defanged domain or URL using VirusTotal passive intelligence.
  - Search existing urlscan.io results for the defanged domain.
  - Do not navigate directly to the suspicious URL.
- Finding: The URL is suspicious because it presents itself as Microsoft-related infrastructure while using a separate lookalike domain. Successful email authentication only validates the sender's domain and does not establish Microsoft ownership.
- Risk rating: HIGH


## Indicator 3 — MedEquip Invoice URL

- Source email: E5
- Original value: `https://medequip-supplies.net/invoices/INV-2026-04891`
- Defanged value: `hxxps://medequip-supplies[.]net/invoices/INV-2026-04891`
- Domain or IP: `medequip-supplies.net`
- Indicator type: URL / invoice lure
- Evidence from email:
  - The URL references invoice `INV-2026-04891`.
  - The message requests payment of $24,716.38.
  - Payment is requested within seven days.
  - Angela Rivera reported that the invoice looked wrong.
  - SPF returned softfail.
  - DKIM was absent.
  - DMARC failed.
  - The sending IP observed in the headers was `185.176.43.22`.
  - The message was generated using PHPMailer 6.6.0.
- Safe investigation method:
  - Query domain registration information with `whois medequip-supplies.net`.
  - Query DNS information with `dig medequip-supplies.net`.
  - Query DNS information with `nslookup medequip-supplies.net`.
  - Search the defanged domain or URL using VirusTotal passive intelligence.
  - Search existing urlscan.io results for the defanged domain.
  - Do not navigate directly to the suspicious URL.
- Finding: The URL is suspicious because it is associated with an unexpected high-value invoice and appears together with multiple email authentication failures.
- Risk rating: HIGH


## Indicator 4 — MedEquip Login URL

- Source email: E5
- Original value: `https://medequip-supplies.net/portal/login`
- Defanged value: `hxxps://medequip-supplies[.]net/portal/login`
- Domain or IP: `medequip-supplies.net`
- Indicator type: URL / login page
- Evidence from email:
  - The URL contains a `/portal/login` path.
  - It belongs to the same domain used by the suspicious invoice.
  - The email pressures the recipient to interact with an unexpected invoice.
  - The message also contains a PDF attachment.
  - SPF returned softfail.
  - DKIM was absent.
  - DMARC failed.
- Safe investigation method:
  - Search the defanged URL or domain using VirusTotal passive intelligence.
  - Search existing urlscan.io results for the domain.
  - Review WHOIS information for the parent domain.
  - Review DNS records for the parent domain.
  - Do not navigate directly to the login page.
- Finding: The login path may indicate an attempt to collect credentials. However, the email evidence alone does not prove credential harvesting, so the indicator remains suspicious pending further safe analysis.
- Risk rating: HIGH


## Indicator 5 — Invoice PDF Attachment

- Source email: E5
- Original value: `Invoice_INV-2026-04891.pdf`
- Defanged value: `Invoice_INV-2026-04891[.]pdf`
- Domain or IP: N/A
- Indicator type: PDF attachment
- Evidence from email:
  - The attachment name contains the same invoice number used in the email.
  - The email requests payment of $24,716.38.
  - The recipient reported that the invoice looked wrong.
  - The email contains suspicious external invoice and login URLs.
  - SPF returned softfail.
  - DKIM was absent.
  - DMARC failed.
- Safe investigation method:
  - Do not open the attachment on the analyst workstation.
  - Preserve the attachment in an isolated analysis environment.
  - Calculate a SHA-256 hash using `sha256sum`.
  - Extract metadata using `pdfinfo` or `exiftool`.
  - Perform static PDF inspection using `pdfid.py`.
  - Search the calculated SHA-256 hash in VirusTotal.
  - Use an authorized malware sandbox if deeper analysis is required.
- Finding: The attachment is suspicious because it supports the unexpected high-value invoice pretext. The email evidence alone is not sufficient to classify the PDF itself as malicious.
- Risk rating: HIGH


## Indicator 6 — MedDefense Benefits Lookalike

- Source email: E7
- Original value: `https://meddefense-benefits.org/enrollment`
- Defanged value: `hxxps://meddefense-benefits[.]org/enrollment`
- Domain or IP: `meddefense-benefits.org`
- Indicator type: URL / lookalike domain / HR phishing lure
- Evidence from email:
  - The sender claims to represent MedDefense HR Benefits.
  - The domain resembles MedDefense but is not the legitimate `meddefense.com` domain.
  - The URL contains an `/enrollment` path.
  - The email states that enrollment closes the following day.
  - SPF failed.
  - DKIM was absent.
  - DMARC failed.
  - The sending IP observed in the headers was `164.90.218.73`.
  - The message was generated using PHPMailer 6.6.0.
- Safe investigation method:
  - Query domain registration information with `whois meddefense-benefits.org`.
  - Query DNS information with `dig meddefense-benefits.org`.
  - Query DNS information with `nslookup meddefense-benefits.org`.
  - Search the defanged domain or URL using VirusTotal passive intelligence.
  - Search existing urlscan.io results for the defanged domain.
  - Do not navigate directly to the suspicious URL.
- Finding: The URL is highly suspicious because it uses a MedDefense lookalike domain combined with an HR benefits pretext and deadline pressure.
- Risk rating: HIGH


## Indicator 7 — Suspicious IP Address

- Source email: E5
- Original value: `203.0.113.228`
- Defanged value: `203[.]0[.]113[.]228`
- Domain or IP: `203.0.113.228`
- Indicator type: IPv4 indicator
- Evidence from email:
  - The IP appears as an indicator associated with the suspicious E5 invoice evidence.
  - E5 contains suspicious invoice and login infrastructure.
  - E5 also contains a PDF attachment.
  - The email uses financial pressure to encourage interaction with the supplied resources.
- Safe investigation method:
  - Query registration information with `whois 203.0.113.228`.
  - Perform a reverse DNS query with `dig -x 203.0.113.228`.
  - Perform a reverse DNS query with `nslookup 203.0.113.228`.
  - Search the defanged IP using VirusTotal passive intelligence.
  - Review passive reputation and historical DNS information if available.
  - Do not connect directly to the suspicious IP.
- Finding: The IP should be preserved as an IOC candidate and correlated with the other indicators associated with E5. No direct connection to the IP is required for this investigation.
- Risk rating: HIGH


## Cross-Indicator Findings

The suspicious emails contain several recurring characteristics:

- E2 uses the MedDefense lookalike domain `meddefense-portal.com`.
- E3 uses the Microsoft-themed domain `outlook-protection.com`.
- E5 uses `medequip-supplies.net` for an invoice and login pretext.
- E7 uses the MedDefense lookalike domain `meddefense-benefits.org`.
- E2, E3, E5 and E7 were generated using PHPMailer 6.6.0.
- Their Message-IDs follow a similar `PHP-*` format.
- Several URLs contain action-oriented paths such as `/verify`, `/account/verify`, `/portal/login` and `/enrollment`.
- E5 contains both suspicious URLs and a PDF attachment.
- The repeated infrastructure characteristics provide useful correlation evidence, but they do not alone prove common threat-actor ownership.


## Safety Notes

Suspicious URLs were not opened directly during this investigation.

URLs and IP addresses are defanged when documented to reduce the risk of
accidental interaction.

Passive investigation methods such as WHOIS, DNS queries, VirusTotal searches
and existing urlscan.io results should be preferred.

Suspicious attachments must not be opened on the analyst workstation.
Attachment analysis should use hashes, metadata extraction, static analysis
and authorized sandbox services in an isolated environment.

No direct connection to suspicious web infrastructure is required for the
conclusions documented in this report.