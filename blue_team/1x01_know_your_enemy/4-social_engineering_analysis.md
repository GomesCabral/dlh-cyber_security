# Social Engineering Analysis

## Scenario 1

**Vector Type:** Brand Impersonation

**Target:** Sarah Park (IT Director) – Responsible for firewall management and likely to respond quickly to security-related emails.

**Psychological Lever:** Urgency

**Red Flags:**
- Sender domain is `fortinet-support.net` instead of the official Fortinet domain.
- The email creates unnecessary urgency.
- The patch is provided through a link instead of the official support portal.

**Technical Control:** Email filtering with anti-phishing protection.

**Administrative Control:** Verify software updates only through official vendor websites.

---

## Scenario 2

**Vector Type:** Business Email Compromise (BEC)

**Target:** Robert Kim (CFO) – Has authority to approve financial transfers.

**Psychological Lever:** Authority

**Red Flags:**
- Slightly different sender email address.
- Request for secrecy.
- Urgent request for a large wire transfer.

**Technical Control:** Email authentication (SPF, DKIM and DMARC).

**Administrative Control:** Require verbal approval for high-value financial transactions.

---

## Scenario 3

**Vector Type:** Vishing

**Target:** Nurse – Has access to the EHR system and may trust IT staff.

**Psychological Lever:** Authority

**Red Flags:**
- IT asks for a password.
- Caller creates urgency using a recent security incident.
- Credentials requested over the phone.

**Technical Control:** Multi-Factor Authentication (MFA).

**Administrative Control:** Security awareness training stating IT never requests passwords.

---

## Scenario 4

**Vector Type:** Smishing

**Target:** All employees – Many use mobile devices and may respond quickly.

**Psychological Lever:** Fear

**Red Flags:**
- Unexpected text message.
- Urgent warning about parking.
- Link requesting Active Directory credentials.

**Technical Control:** Mobile anti-phishing protection.

**Administrative Control:** Employees should access HR services only through official portals.

---

## Scenario 5

**Vector Type:** Watering Hole Attack

**Target:** Physicians – They regularly visit the Regional Healthcare Association website.

**Psychological Lever:** Familiarity

**Red Flags:**
- Unexpected browser redirects.
- Browser requests unusual downloads.
- Security warnings while visiting a trusted website.

**Technical Control:** Endpoint Detection and Response (EDR).

**Administrative Control:** Keep browsers updated and report unusual website behavior.

---

## Scenario 6

**Vector Type:** Typosquatting

**Target:** Patients – They may not notice the fake domain.

**Psychological Lever:** Familiarity

**Red Flags:**
- Domain spelling is different ("defence" instead of "defense").
- Website requests login credentials unexpectedly.
- Search result is a sponsored advertisement.

**Technical Control:** DNS and web filtering.

**Administrative Control:** Educate patients to verify the official MedDefense website.

---

## Scenario 7

**Vector Type:** Impersonation

**Target:** Hospital employee with badge access – Expected to help coworkers.

**Psychological Lever:** Helpfulness

**Red Flags:**
- Expired visitor badge.
- Person requests access without using their own badge.
- Attempts to follow someone through a secure door.

**Technical Control:** CCTV and badge access monitoring.

**Administrative Control:** Enforce an anti-tailgating policy requiring everyone to use their own badge.
