# IOC Extraction Report

This report consolidates indicators identified during the phishing investigation
of Emails E2, E3, E5 and E7 and compares them with the healthcare-sector
phishing context provided by E8.

Indicators are separated by confidence and operational value. Shared tools,
generic infrastructure characteristics and HC3 campaign patterns are retained
as context when they are not sufficiently specific to block safely.

## Structured IOC Table

| IOC Type | IOC Value | Source | Context | Confidence | Recommended Action |
|---|---|---|---|---|---|
| domain | `meddefense-portal[.]com` | E2 | MedDefense lookalike domain used for portal re-verification phishing | HIGH | block |
| URL | `hxxps://meddefense-portal[.]com/verify?user=dmarsh@meddefense[.]com` | E2 | Targeted verification URL containing Diane Marsh's email address | HIGH | block |
| email address | `noreply@meddefense-portal[.]com` | E2 | Sender impersonating MedDefense IT Security | HIGH | block |
| IP | `91[.]234[.]99[.]107` | E2 | Sending IP observed in E2 headers | HIGH | alert |
| domain | `outlook-protection[.]com` | E3 | Microsoft-themed lookalike domain used for account verification | HIGH | block |
| URL | `hxxps://outlook-protection[.]com/account/verify` | E3 | Account-verification phishing URL | HIGH | block |
| email address | `security@outlook-protection[.]com` | E3 | Sender claiming to be Microsoft Account Protection | HIGH | block |
| IP | `51[.]38[.]42[.]17` | E3 | Sending IP observed in E3 headers | HIGH | alert |
| domain | `medequip-supplies[.]net` | E5 | Domain used for suspicious invoice and login workflow | HIGH | block |
| URL | `hxxps://medequip-supplies[.]net/invoices/INV-2026-04891` | E5 | URL associated with suspicious invoice INV-2026-04891 | HIGH | block |
| URL | `hxxps://medequip-supplies[.]net/portal/login` | E5 | Login URL associated with suspicious invoice lure | HIGH | block |
| email address | `invoices@medequip-supplies[.]net` | E5 | Sender of suspicious high-value invoice | HIGH | block |
| IP | `185[.]176[.]43[.]22` | E5 | Sending IP observed in E5 headers | HIGH | alert |
| IP | `203[.]0[.]113[.]228` | E5 | IP indicator associated with E5 evidence | MEDIUM | monitor |
| infrastructure note | `Invoice_INV-2026-04891[.]pdf` | E5 | PDF attachment associated with suspicious invoice lure | MEDIUM | alert |
| domain | `meddefense-benefits[.]org` | E7 | MedDefense-themed lookalike domain used for benefits phishing | HIGH | block |
| URL | `hxxps://meddefense-benefits[.]org/enrollment` | E7 | External enrollment URL used in HR/benefits lure | HIGH | block |
| email address | `hr-notifications@meddefense-benefits[.]org` | E7 | Sender impersonating MedDefense HR Benefits | HIGH | block |
| IP | `164[.]90[.]218[.]73` | E7 | Sending IP observed in E7 headers | HIGH | alert |
| tool | `PHPMailer 6.6.0` | E2, E3, E5, E7 | Common mail-generation software observed across phishing emails | LOW | context only |
| infrastructure note | `PHP-* Message-ID pattern` | E2, E3, E5, E7 | Similar message-generation characteristic across phishing emails | MEDIUM | monitor |
| infrastructure note | `X-Priority: 1 / high-priority messaging` | E2, E3, E5, E7 | Priority characteristic associated with urgency-based phishing | LOW | context only |
| infrastructure note | `healthcare-sector phishing` | E8 | HC3 campaign pattern relevant to MedDefense | MEDIUM | context only |
| infrastructure note | `lookalike domains` | E8 | HC3 pattern consistent with E2 and E7 | MEDIUM | context only |
| infrastructure note | `role-specific targeting` | E8 | HC3 pattern consistent with clinical, finance and HR lures | MEDIUM | context only |
| infrastructure note | `urgency-based social engineering` | E8 | HC3 pattern consistent with observed phishing messages | MEDIUM | context only |

## Attack Phase Categorization

### Delivery

The following indicators are associated with phishing email delivery:

| IOC | Source | Confidence | Action |
|---|---|---|---|
| `noreply@meddefense-portal[.]com` | E2 | HIGH | block |
| `91[.]234[.]99[.]107` | E2 | HIGH | alert |
| `security@outlook-protection[.]com` | E3 | HIGH | block |
| `51[.]38[.]42[.]17` | E3 | HIGH | alert |
| `invoices@medequip-supplies[.]net` | E5 | HIGH | block |
| `185[.]176[.]43[.]22` | E5 | HIGH | alert |
| `hr-notifications@meddefense-benefits[.]org` | E7 | HIGH | block |
| `164[.]90[.]218[.]73` | E7 | HIGH | alert |

Sender addresses are useful for mail-gateway blocking and historical searches.

Sending IPs are valuable for alerting and correlation, but IP ownership and
hosting can change. Therefore, IP blocking should be validated against current
infrastructure ownership and organizational policy.


### Credential Harvesting

The following indicators are associated with pages that attempt to cause
account or credential-related interaction:

| IOC | Source | Confidence | Action |
|---|---|---|---|
| `meddefense-portal[.]com` | E2 | HIGH | block |
| `hxxps://meddefense-portal[.]com/verify?user=dmarsh@meddefense[.]com` | E2 | HIGH | block |
| `outlook-protection[.]com` | E3 | HIGH | block |
| `hxxps://outlook-protection[.]com/account/verify` | E3 | HIGH | block |
| `medequip-supplies[.]net` | E5 | HIGH | block |
| `hxxps://medequip-supplies[.]net/portal/login` | E5 | HIGH | block |
| `meddefense-benefits[.]org` | E7 | HIGH | block |
| `hxxps://meddefense-benefits[.]org/enrollment` | E7 | HIGH | block |

The E2 URL has especially high investigative value because Diane Marsh
confirmed clicking it.

A click confirms interaction with the URL but does not by itself prove that
credentials were submitted.


### Attachment or Lure Artifact

The main attachment artifact is associated with E5:

| IOC | Source | Confidence | Action |
|---|---|---|---|
| `Invoice_INV-2026-04891[.]pdf` | E5 | MEDIUM | alert |
| `hxxps://medequip-supplies[.]net/invoices/INV-2026-04891` | E5 | HIGH | block |
| `hxxps://medequip-supplies[.]net/portal/login` | E5 | HIGH | block |

The filename alone should not be treated as proof that the PDF is malicious.

If the attachment is available, it should be preserved and hashed. A SHA-256
hash should then be added to the IOC report after calculation.

No file hash should be invented when the attachment itself has not been
analyzed.


### Infrastructure

Infrastructure-related indicators include:

| IOC | Source | Confidence | Action |
|---|---|---|---|
| `91[.]234[.]99[.]107` | E2 | HIGH | alert |
| `51[.]38[.]42[.]17` | E3 | HIGH | alert |
| `185[.]176[.]43[.]22` | E5 | HIGH | alert |
| `203[.]0[.]113[.]228` | E5 | MEDIUM | monitor |
| `164[.]90[.]218[.]73` | E7 | HIGH | alert |
| `PHPMailer 6.6.0` | E2, E3, E5, E7 | LOW | context only |
| `PHP-* Message-ID pattern` | E2, E3, E5, E7 | MEDIUM | monitor |

PHPMailer and PHP-style Message-IDs help correlate the messages, but neither
one uniquely identifies an attacker.


### Context-Only Indicators

The following characteristics provide campaign context but should not be
blocked independently:

- PHPMailer 6.6.0
- PHP-style Message-ID characteristics
- High-priority email headers
- Urgency and deadline language
- Healthcare-sector targeting
- Role-specific targeting
- IT portal verification themes
- Invoice/payment themes
- HR benefits themes
- Lookalike-domain usage as a general technique

These characteristics are useful for threat hunting and correlation but are
too broad to use as standalone blocking indicators.


## IOC Quality Assessment

### High-Confidence IOCs

The strongest IOCs are the specific phishing domains and URLs observed directly
in the malicious messages.

High-confidence domains include:

- `meddefense-portal[.]com`
- `outlook-protection[.]com`
- `medequip-supplies[.]net`
- `meddefense-benefits[.]org`

High-confidence URLs include:

- `hxxps://meddefense-portal[.]com/verify?user=dmarsh@meddefense[.]com`
- `hxxps://outlook-protection[.]com/account/verify`
- `hxxps://medequip-supplies[.]net/invoices/INV-2026-04891`
- `hxxps://medequip-supplies[.]net/portal/login`
- `hxxps://meddefense-benefits[.]org/enrollment`

These indicators are directly associated with the phishing evidence and are
appropriate candidates for blocking in web, DNS and email security controls,
subject to normal organizational validation procedures.


### Indicators Better Suited To Alerting or Monitoring

Sending IP addresses should be used for detection and correlation because
hosting infrastructure can be reused, reassigned or shared.

The following should therefore be investigated and monitored:

- `91[.]234[.]99[.]107`
- `51[.]38[.]42[.]17`
- `185[.]176[.]43[.]22`
- `164[.]90[.]218[.]73`

The indicator `203[.]0[.]113[.]228` should also be retained as evidence and
correlated with E5, but it should not be treated as sufficient standalone
proof of malicious activity.


### Indicators That Should Not Be Used Alone

PHPMailer 6.6.0 must not be blocked simply because it appears in E2, E3, E5
and E7.

PHPMailer is legitimate software and can be used by both legitimate and
malicious senders.

Likewise, a PHP-style Message-ID, high-priority header, urgent language or
invoice theme is not independently malicious.

Blocking these generic characteristics would create false positives.

Their investigative value comes from correlation with stronger indicators such
as lookalike domains, suspicious URLs, authentication failures and
social-engineering behavior.


## HC3 Pattern Comparison

E8 provides healthcare-sector threat context rather than a new set of
organization-specific malicious IOCs.

Relevant HC3 patterns include:

- Healthcare-sector phishing
- Lookalike domain usage
- Role-specific targeting
- Urgency-based social engineering
- Credential-verification themes
- Business-process impersonation

These patterns align with the observed MedDefense activity:

- E2 targets a clinical employee through an IT portal verification lure.
- E5 targets an Accounts Payable workflow through an invoice lure.
- E7 uses an HR/benefits enrollment lure.
- E2 and E7 use MedDefense-themed lookalike domains.

These similarities support campaign correlation but should not be treated as
standalone blocking indicators.


## HC3-Ready Summary

The MedDefense investigation identified phishing activity associated with E2,
E3, E5 and E7.

### Domains

- `meddefense-portal[.]com`
- `outlook-protection[.]com`
- `medequip-supplies[.]net`
- `meddefense-benefits[.]org`

### IP Addresses

- `91[.]234[.]99[.]107`
- `51[.]38[.]42[.]17`
- `185[.]176[.]43[.]22`
- `164[.]90[.]218[.]73`
- `203[.]0[.]113[.]228` — contextual E5 indicator

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

### Attachment Artifact

- `Invoice_INV-2026-04891[.]pdf`

No attachment hash is reported because no verified file hash is available from
the supplied evidence.

The strongest indicators are the phishing domains and URLs. Sending IPs should
be used primarily for alerting, hunting and correlation. Generic
characteristics such as PHPMailer 6.6.0, high-priority headers and urgency
language should remain context-only indicators because they are not uniquely
malicious.


## Conclusion

The investigation produced actionable IOCs across delivery, credential
harvesting, lure artifacts and infrastructure.

The phishing domains and URLs have the highest confidence because they are
directly associated with the investigated phishing messages.

Sender addresses are useful for mail filtering, while sending IP addresses
should be used for alerting and correlation with appropriate validation.

Generic tooling and behavioral characteristics are valuable for campaign
correlation but should not be blocked independently because doing so could
generate false positives.

The IOC set can be shared with defenders to support blocking, detection,
historical searching and investigation of additional campaign activity.