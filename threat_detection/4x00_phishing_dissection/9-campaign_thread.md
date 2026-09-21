# Campaign Thread Analysis

This analysis evaluates whether Emails E2, E5 and E7 are related components of
a coordinated phishing campaign targeting MedDefense Health Systems.

The assessment is based on shared infrastructure characteristics, tooling,
timing, targeting, social-engineering techniques and comparison with the HC3
alert contained in E8.

## Shared Indicators

E2, E5 and E7 use different sender domains and different social-engineering
pretexts, but they share several characteristics that support correlation.

| Indicator | E2 | E5 | E7 |
|---|---|---|---|
| Phishing-related classification | Yes | Yes | Yes |
| PHPMailer 6.6.0 | Yes | Yes | Yes |
| PHP-style Message-ID | Yes | Yes | Yes |
| High-priority header | Yes | Yes | Yes |
| External domain | `meddefense-portal.com` | `medequip-supplies.net` | `meddefense-benefits.org` |
| MedDefense lookalike domain | Yes | No | Yes |
| Urgency / deadline | 24-hour verification deadline | Payment required within 7 days | Enrollment closes tomorrow |
| Business-process lure | IT portal verification | Invoice/payment | HR benefits enrollment |
| External action requested | Portal verification | Invoice/payment interaction | Benefits enrollment |
| Authentication problem | SPF fail, DKIM none, DMARC fail | SPF softfail, DKIM none, DMARC fail | SPF fail, DKIM none, DMARC fail |
| Targeted recipient context | Clinical staff | Accounts payable / finance | HR / benefits-related context |

### Infrastructure and Tooling Correlation

E2 was delivered from infrastructure associated with:

- Domain: `meddefense-portal.com`
- Sending IP: `91.234.99.107`
- Mailer: PHPMailer 6.6.0

E5 was delivered from infrastructure associated with:

- Domain: `medequip-supplies.net`
- Sending IP: `185.176.43.22`
- Mailer: PHPMailer 6.6.0

E7 was delivered from infrastructure associated with:

- Domain: `meddefense-benefits.org`
- Sending IP: `164.90.218.73`
- Mailer: PHPMailer 6.6.0

The domains and sending IP addresses are different, so there is no single
shared domain or sending IP that proves common ownership.

However, the repeated use of PHPMailer 6.6.0, similar PHP-style Message-IDs,
high-priority messaging, authentication weaknesses and external action pages
provides useful campaign-level correlation.

PHPMailer alone is not sufficient for attribution because it is widely
available software. Its value comes from its presence alongside the other
shared indicators.


## Targeting Map

The three phishing emails target different business functions inside the same
healthcare organization.

| Email | Target Area | Pretext | Requested Action | Intended Effect |
|---|---|---|---|---|
| E2 | Clinical staff | MedDefense IT portal re-verification | Click verification link and interact with portal | Obtain account interaction and potentially credentials |
| E5 | Accounts payable / finance | Medical equipment invoice | Review invoice, access portal or process payment | Trigger financial or account interaction |
| E7 | HR / benefits-related staff | Open enrollment / employee benefits | Access enrollment page before deadline | Trigger account or benefits-portal interaction |

### E2 — Clinical Staff

E2 targets Diane Marsh and uses a MedDefense IT Security portal
re-verification pretext.

The attacker attempts to make the message relevant to an employee who depends
on organizational systems by threatening portal restrictions if verification
is not completed within 24 hours.

The evidence confirms that Diane clicked the link.


### E5 — Accounts Payable / Finance

E5 uses a business invoice pretext involving invoice `INV-2026-04891` and a
payment amount of $24,716.38.

The lure is relevant to an Accounts Payable or finance workflow and attempts
to cause interaction with invoice, login or payment infrastructure.

This differs from the IT pretext in E2 but continues the pattern of using a
business-process-specific lure.


### E7 — HR / Benefits

E7 impersonates MedDefense HR Benefits and claims that open enrollment closes
the following day.

The lure uses an employee-benefits process and deadline pressure to encourage
interaction with an external enrollment page.

Together, E2, E5 and E7 show phishing activity aimed at multiple operational
functions rather than a single generic spam audience.


## Timing Map

The evidence places the three phishing emails within a short time window.

| Date | Email | Theme |
|---|---|---|
| April 14, 2026 | E2 | IT portal re-verification |
| April 16, 2026 | E5 | Invoice / payment |
| April 16, 2026 | E7 | HR benefits / open enrollment |

The observed sequence is:

`April 14 — E2 → April 16 — E5 + E7`

E2 occurred first on April 14.

E5 and E7 were delivered on April 16.

There is no April 15 delivery being inferred for these three messages.

The short time window, combined with the different business-process lures,
supports the possibility of a coordinated phishing operation targeting
multiple functions inside MedDefense.


## Comparison With HC3 Alert

Email E8 contains an HC3 healthcare-sector phishing alert and provides
external threat context for the MedDefense investigation.

The MedDefense evidence should be compared with the pattern described by the
alert rather than assuming automatically that every suspicious message belongs
to the campaign.

| HC3 Pattern | MedDefense Evidence |
|---|---|
| Healthcare-sector phishing | MedDefense Health Systems is the organization being targeted |
| Lookalike domains | E2 uses `meddefense-portal.com`; E7 uses `meddefense-benefits.org` |
| Role-specific targeting | E2 targets clinical staff; E5 targets finance/accounts payable; E7 uses an HR/benefits workflow |
| Urgency | E2 uses a 24-hour deadline; E5 uses a payment deadline; E7 says enrollment closes tomorrow |
| Organizational impersonation | E2 impersonates MedDefense IT and E7 impersonates MedDefense HR Benefits |
| Business-process lures | Portal verification, invoice/payment and benefits enrollment are used |

The observed MedDefense phishing activity therefore has multiple
characteristics consistent with the healthcare-sector phishing pattern
described in E8.

This comparison strengthens the campaign hypothesis but does not independently
prove that the MedDefense emails were sent by the same actor described in the
HC3 alert.


## Attribution Assessment

### What Can Be Inferred

The evidence supports correlation between E2, E5 and E7 because:

- They occur within a short time window.
- They target the same healthcare organization.
- They use role-specific business-process lures.
- They use urgency to pressure recipients.
- They direct recipients toward external infrastructure.
- They use PHPMailer 6.6.0.
- They contain similar PHP-style Message-ID characteristics.
- They use high-priority messaging.
- E2 and E7 use MedDefense-themed lookalike domains.
- Their patterns are consistent with characteristics described in the HC3 alert.

These similarities make a coordinated campaign a reasonable evidence-based
assessment.


### What Cannot Be Proven

The available evidence does not prove:

- The real-world identity of the attacker.
- A specific threat actor or criminal group.
- That the same individual sent all three emails.
- That the different domains are controlled by the same person.
- That the different sending IP addresses belong to the same infrastructure owner.
- That PHPMailer 6.6.0 uniquely identifies one attacker.
- That E2, E5 and E7 are definitively the same campaign based on infrastructure ownership alone.
- That the sender is the same actor referenced by HC3.

No specific threat-actor attribution should therefore be made from the
available evidence.


## Conclusion

The combined evidence supports the assessment that E2, E5 and E7 are likely
components of a single coordinated phishing campaign targeting MedDefense
Health Systems.

The strongest correlation comes from the combination of close timing,
role-specific targeting, urgency-based social engineering, similar mailer
tooling, similar message-generation characteristics and repeated targeting of
MedDefense business processes.

The campaign appears to use different pretexts for different organizational
functions:

- E2: clinical staff through IT portal verification.
- E5: accounts payable / finance through an invoice.
- E7: HR / benefits through open enrollment.

The observed activity is also consistent with the healthcare-sector phishing
pattern described in the HC3 alert in E8.

However, the evidence supports campaign correlation, not definitive
threat-actor attribution. The available evidence is insufficient to identify
a specific attacker or prove common infrastructure ownership.