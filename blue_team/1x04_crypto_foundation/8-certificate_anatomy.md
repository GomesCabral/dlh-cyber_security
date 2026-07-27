# 8. The Certificate Anatomy

## Goal

This laboratory inspects X.509 certificates from live HTTPS websites using OpenSSL. It identifies the fields that browsers use to validate server identity, certificate trust, validity, public-key strength, permitted usage, and revocation information.

Three targets were selected:

1. `letsencrypt.org`
2. `github.com`
3. `expired.badssl.com`

The certificate extraction for `letsencrypt.org` was unsuccessful during the first collection attempt. The failure is documented honestly below and includes the commands required to repeat the collection.

---

# Part 1 - Inspect Three Real Certificates

# Certificate 1 - letsencrypt.org

## Certificate Download Command

```bash
openssl s_client \
  -connect letsencrypt.org:443 \
  -servername letsencrypt.org \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM \
  > certificates/letsencrypt.org.pem
```

## Inspection Result

The certificate file could not be parsed successfully.

Output:

```text
Could not find certificate from certificates/letsencrypt.org.pem
```

The same error occurred when attempting to inspect the certificate extensions:

```text
Could not find certificate from certificates/letsencrypt.org.pem

Key Usage: Not present

Extended Key Usage: Not present

Authority Information Access: Not present
```

## Cause

The file `certificates/letsencrypt.org.pem` was either empty or did not contain a valid PEM certificate. This can happen if:

- the TLS connection failed;
- the output pipeline did not receive a certificate;
- DNS or Internet connectivity failed;
- the remote server closed the connection;
- the certificate extraction command removed useful error output.

## Corrective Commands

First, inspect the connection without suppressing error messages:

```bash
openssl s_client \
  -connect letsencrypt.org:443 \
  -servername letsencrypt.org \
  -showcerts </dev/null
```

Then extract only the first certificate:

```bash
openssl s_client \
  -connect letsencrypt.org:443 \
  -servername letsencrypt.org \
  -showcerts </dev/null 2>/dev/null \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
  | awk '
      /-----BEGIN CERTIFICATE-----/ {count++}
      count == 1 {print}
      /-----END CERTIFICATE-----/ && count == 1 {exit}
    ' \
  > certificates/letsencrypt.org.pem
```

Verify the file:

```bash
head -n 2 certificates/letsencrypt.org.pem
```

A valid PEM certificate must begin with:

```text
-----BEGIN CERTIFICATE-----
```

Validate the certificate:

```bash
openssl x509 \
  -in certificates/letsencrypt.org.pem \
  -noout \
  -subject \
  -issuer \
  -serial \
  -dates
```

## letsencrypt.org Certificate Evidence

| Field | Result |
|---|---|
| Subject | Not collected because the certificate extraction failed |
| Issuer | Not collected because the certificate extraction failed |
| Validity Period | Not collected because the certificate extraction failed |
| Serial Number | Not collected because the certificate extraction failed |
| Signature Algorithm | Not collected because the certificate extraction failed |
| Public Key Algorithm | Not collected because the certificate extraction failed |
| Public Key Size | Not collected because the certificate extraction failed |
| Subject Alternative Names | Not collected because the certificate extraction failed |
| Key Usage | Not collected because the certificate extraction failed |
| Extended Key Usage | Not collected because the certificate extraction failed |
| Authority Information Access | Not collected because the certificate extraction failed |
| Inspection Status | Failed: no valid certificate found in the saved PEM file |

## Analysis

The failed extraction does not prove that the live website has an invalid certificate. It proves only that the local collection process did not produce a valid certificate file.

This result must not be replaced with invented certificate values. The collection should be repeated using the corrective commands above.

---

# Certificate 2 - github.com

## Certificate Download Command

```bash
openssl s_client \
  -connect github.com:443 \
  -servername github.com \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM \
  > certificates/github.com.pem
```

## Identity, Issuer, Serial Number, and Validity

Command:

```bash
openssl x509 \
  -in certificates/github.com.pem \
  -noout \
  -subject \
  -issuer \
  -serial \
  -dates
```

Output:

```text
subject=CN=github.com
issuer=C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
serial=72010E03F4A067FE4E796266430718F6
notBefore=Jul  3 00:00:00 2026 GMT
notAfter=Sep 30 23:59:59 2026 GMT
```

## Signature and Public-Key Information

Command:

```bash
openssl x509 \
  -in certificates/github.com.pem \
  -text \
  -noout \
  | grep -E "Signature Algorithm|Public Key Algorithm|Public-Key:"
```

Output:

```text
Signature Algorithm: ecdsa-with-SHA256
Public Key Algorithm: id-ecPublicKey
Public-Key: (256 bit)
Signature Algorithm: ecdsa-with-SHA256
```

## Subject Alternative Names

Command:

```bash
openssl x509 \
  -in certificates/github.com.pem \
  -noout \
  -ext subjectAltName
```

Output:

```text
X509v3 Subject Alternative Name:
    DNS:github.com, DNS:www.github.com
```

## Key Usage

Command:

```bash
openssl x509 \
  -in certificates/github.com.pem \
  -noout \
  -ext keyUsage
```

Output:

```text
X509v3 Key Usage: critical
    Digital Signature
```

## Extended Key Usage

Command:

```bash
openssl x509 \
  -in certificates/github.com.pem \
  -noout \
  -ext extendedKeyUsage
```

Output:

```text
X509v3 Extended Key Usage:
    TLS Web Server Authentication
```

## Authority Information Access

Command:

```bash
openssl x509 \
  -in certificates/github.com.pem \
  -noout \
  -ext authorityInfoAccess
```

Output:

```text
Authority Information Access:
    CA Issuers - URI:http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt
    OCSP - URI:http://ocsp.sectigo.com
```

## github.com Certificate Profile

| Field | Value |
|---|---|
| Subject CN | `github.com` |
| Subject O | Not present |
| Subject L | Not present |
| Subject ST | Not present |
| Subject C | Not present |
| Issuer C | `GB` |
| Issuer O | `Sectigo Limited` |
| Issuer CN | `Sectigo Public Server Authentication CA DV E36` |
| Serial Number | `72010E03F4A067FE4E796266430718F6` |
| Not Before | `Jul 3 00:00:00 2026 GMT` |
| Not After | `Sep 30 23:59:59 2026 GMT` |
| Signature Algorithm | `ecdsa-with-SHA256` |
| Public Key Algorithm | `id-ecPublicKey` |
| Public Key Size | `256 bit` |
| SAN | `github.com`, `www.github.com` |
| Key Usage | `Digital Signature` |
| Extended Key Usage | `TLS Web Server Authentication` |
| CA Issuers URL | `http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt` |
| OCSP URL | `http://ocsp.sectigo.com` |
| Certificate Type | Domain Validation certificate |
| Status | Valid during the documented validity period |

## Analysis

The GitHub certificate identifies `github.com` as the certificate subject and includes both `github.com` and `www.github.com` in the Subject Alternative Name extension. The certificate uses an elliptic-curve public key with a size of 256 bits and is signed using ECDSA with SHA-256.

Its Extended Key Usage permits TLS Web Server Authentication, meaning it is intended to authenticate an HTTPS server. The Authority Information Access extension provides an OCSP endpoint for revocation checks and a CA Issuers URL for retrieving the intermediate certificate.

The certificate is a Domain Validation certificate. Organisation fields such as `O`, `L`, `ST`, and `C` are not included in the Subject because the CA validated control of the domain rather than the full legal identity of the organisation.

---

# Certificate 3 - expired.badssl.com

## Certificate Download Command

```bash
openssl s_client \
  -connect expired.badssl.com:443 \
  -servername expired.badssl.com \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM \
  > certificates/expired.badssl.com.pem
```

## Identity, Issuer, Serial Number, and Validity

Command:

```bash
openssl x509 \
  -in certificates/expired.badssl.com.pem \
  -noout \
  -subject \
  -issuer \
  -serial \
  -dates
```

Output:

```text
subject=OU=Domain Control Validated, OU=PositiveSSL Wildcard, CN=*.badssl.com
issuer=C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Domain Validation Secure Server CA
serial=4AE79549FA9ABE3F100F17A478E16909
notBefore=Apr  9 00:00:00 2015 GMT
notAfter=Apr 12 23:59:59 2015 GMT
```

## Signature and Public-Key Information

Command:

```bash
openssl x509 \
  -in certificates/expired.badssl.com.pem \
  -text \
  -noout \
  | grep -E "Signature Algorithm|Public Key Algorithm|Public-Key:"
```

Output:

```text
Signature Algorithm: sha256WithRSAEncryption
Public Key Algorithm: rsaEncryption
Public-Key: (2048 bit)
Signature Algorithm: sha256WithRSAEncryption
```

## Subject Alternative Names

Command:

```bash
openssl x509 \
  -in certificates/expired.badssl.com.pem \
  -noout \
  -ext subjectAltName
```

Output:

```text
X509v3 Subject Alternative Name:
    DNS:*.badssl.com, DNS:badssl.com
```

## Key Usage

Command:

```bash
openssl x509 \
  -in certificates/expired.badssl.com.pem \
  -noout \
  -ext keyUsage
```

Output:

```text
X509v3 Key Usage: critical
    Digital Signature, Key Encipherment
```

## Extended Key Usage

Command:

```bash
openssl x509 \
  -in certificates/expired.badssl.com.pem \
  -noout \
  -ext extendedKeyUsage
```

Output:

```text
X509v3 Extended Key Usage:
    TLS Web Server Authentication, TLS Web Client Authentication
```

## Authority Information Access

Command:

```bash
openssl x509 \
  -in certificates/expired.badssl.com.pem \
  -noout \
  -ext authorityInfoAccess
```

Output:

```text
Authority Information Access:
    CA Issuers - URI:http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt
    OCSP - URI:http://ocsp.comodoca.com
```

## expired.badssl.com Certificate Profile

| Field | Value |
|---|---|
| Subject CN | `*.badssl.com` |
| Subject O | Not present |
| Subject OU | `Domain Control Validated`, `PositiveSSL Wildcard` |
| Subject L | Not present |
| Subject ST | Not present |
| Subject C | Not present |
| Issuer C | `GB` |
| Issuer ST | `Greater Manchester` |
| Issuer L | `Salford` |
| Issuer O | `COMODO CA Limited` |
| Issuer CN | `COMODO RSA Domain Validation Secure Server CA` |
| Serial Number | `4AE79549FA9ABE3F100F17A478E16909` |
| Not Before | `Apr 9 00:00:00 2015 GMT` |
| Not After | `Apr 12 23:59:59 2015 GMT` |
| Signature Algorithm | `sha256WithRSAEncryption` |
| Public Key Algorithm | `rsaEncryption` |
| Public Key Size | `2048 bit` |
| SAN | `*.badssl.com`, `badssl.com` |
| Key Usage | `Digital Signature`, `Key Encipherment` |
| Extended Key Usage | `TLS Web Server Authentication`, `TLS Web Client Authentication` |
| CA Issuers URL | `http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt` |
| OCSP URL | `http://ocsp.comodoca.com` |
| Certificate Type | Domain Validation wildcard certificate |
| Status | Expired |

---

# Certificate Comparison Table

| Field | letsencrypt.org | github.com | expired.badssl.com |
|---|---|---|---|
| Subject CN | Not collected due to extraction failure | `github.com` | `*.badssl.com` |
| Subject O | Not collected | Not present | Not present |
| Subject L | Not collected | Not present | Not present |
| Subject ST | Not collected | Not present | Not present |
| Subject C | Not collected | Not present | Not present |
| Issuer | Not collected | Sectigo Public Server Authentication CA DV E36 | COMODO RSA Domain Validation Secure Server CA |
| Not Before | Not collected | `Jul 3 00:00:00 2026 GMT` | `Apr 9 00:00:00 2015 GMT` |
| Not After | Not collected | `Sep 30 23:59:59 2026 GMT` | `Apr 12 23:59:59 2015 GMT` |
| Serial Number | Not collected | `72010E03F4A067FE4E796266430718F6` | `4AE79549FA9ABE3F100F17A478E16909` |
| Signature Algorithm | Not collected | `ecdsa-with-SHA256` | `sha256WithRSAEncryption` |
| Public Key Algorithm | Not collected | `id-ecPublicKey` | `rsaEncryption` |
| Public Key Size | Not collected | 256 bits | 2048 bits |
| SAN Entries | Not collected | `github.com`, `www.github.com` | `*.badssl.com`, `badssl.com` |
| Key Usage | Not collected | Digital Signature | Digital Signature, Key Encipherment |
| Extended Key Usage | Not collected | TLS Web Server Authentication | TLS Web Server Authentication, TLS Web Client Authentication |
| OCSP URL | Not collected | `http://ocsp.sectigo.com` | `http://ocsp.comodoca.com` |
| CA Issuers URL | Not collected | Sectigo CA certificate URL | COMODO CA certificate URL |
| Validation Status | Inspection incomplete | Valid during documented period | Expired |

---

# Part 2 - Broken Certificate Analysis

The certificate presented by `expired.badssl.com` is invalid because its validity period ended on:

```text
Apr 12 23:59:59 2015 GMT
```

The current date is later than the certificate's `Not After` date. Therefore, the certificate can no longer be accepted as valid.

A browser would display an error similar to:

```text
NET::ERR_CERT_DATE_INVALID
```

Firefox may display an equivalent error such as:

```text
SEC_ERROR_EXPIRED_CERTIFICATE
```

OpenSSL verification may report:

```text
certificate has expired
```

or:

```text
Verify return code: 10 (certificate has expired)
```

## Security Risk

An expired certificate does not automatically mean that the encryption algorithm has been broken. However, it means that the CA's identity assertion is no longer valid for the current date.

The expiration may indicate:

- failed certificate lifecycle management;
- abandoned infrastructure;
- an outdated or unmaintained service;
- renewal automation failure;
- possible use of an unauthorised replacement service;
- increased susceptibility to phishing and impersonation.

## Patient Recommendation

A patient should not proceed past an expired-certificate warning on a healthcare portal.

The patient should not submit:

- login credentials;
- medical information;
- payment information;
- insurance details;
- identity information.

A hospital portal is a high-trust service. Certificate warnings must be treated as security incidents rather than minor technical errors.

---

# Part 3 - MedDefense Certificate Profile

## Certificate Type

MedDefense should use a **Domain Validation certificate** for its public patient portal when the principal requirements are:

- HTTPS encryption;
- domain authentication;
- reliable automated renewal;
- broad browser trust.

DV, OV, and EV certificates can provide the same cryptographic strength when they use the same key algorithm and TLS configuration. OV and EV primarily add additional identity-validation processes.

An OV certificate may be selected if:

- MedDefense policy requires validated organisation details;
- a healthcare partner requires it contractually;
- an integration requires formal organisation validation;
- the compliance programme requires it.

For normal public portal encryption and automated lifecycle management, a DV certificate is appropriate.

---

## Certificate Authority

The certificate should be issued by a publicly trusted CA that supports ACME and automated renewal.

A suitable choice is:

```text
Let's Encrypt
```

Advantages include:

- public browser trust;
- automated domain validation;
- ACME support;
- short certificate lifecycle;
- automatic renewal;
- no manual certificate purchase process.

MedDefense should not use a self-signed certificate for the public portal because patient browsers would not trust it automatically.

---

## Subject Alternative Names

The certificate should contain only the hostnames required by the patient portal.

Recommended SAN entries:

```text
DNS:portal.meddefense.com
DNS:login.meddefense.com
```

Where the `www` hostname is required:

```text
DNS:www.portal.meddefense.com
```

The exact SAN list must match the real production DNS design.

Unnecessary hostnames should not be included because each additional SAN increases the scope and impact of a private-key compromise.

---

## Public-Key Algorithm and Size

Preferred option:

```text
ECDSA P-256
```

ECDSA P-256 provides:

- approximately 128-bit security;
- small key sizes;
- efficient TLS handshakes;
- lower bandwidth use;
- good performance.

Compatibility option:

```text
RSA-2048
```

RSA-2048 remains widely supported and is acceptable when legacy systems cannot use ECDSA.

The CA signature should use:

```text
SHA-256 or stronger
```

MedDefense must not use:

- SHA-1 signatures;
- RSA keys below 2048 bits;
- deprecated elliptic curves;
- MD5 signatures.

---

## Validity Period

MedDefense should use the validity period permitted by the selected public CA and automate the complete lifecycle through ACME.

The process should include:

1. automatic certificate request;
2. domain validation;
3. automatic renewal;
4. automatic deployment;
5. secure private-key installation;
6. web-server reload;
7. post-deployment TLS testing;
8. expiry monitoring;
9. renewal-failure alerting;
10. emergency certificate replacement.

The current situation, with only 18 days remaining and no automatic renewal, represents an avoidable operational risk.

---

## Wildcard or Single-Domain Certificate

MedDefense should use a single-domain or narrowly scoped SAN certificate.

Recommended:

```text
portal.meddefense.com
```

Not preferred:

```text
*.meddefense.com
```

A wildcard certificate increases the impact of a private-key compromise because the same certificate may authenticate many subdomains.

A narrowly scoped certificate provides:

- smaller blast radius;
- clearer ownership;
- simpler monitoring;
- easier revocation;
- easier incident containment;
- separate lifecycle management for critical systems.

A wildcard certificate should be used only when there is a documented operational requirement and the private key is strongly protected.

---

# Recommended MedDefense Certificate Profile

| Field | Recommendation |
|---|---|
| Certificate Type | DV certificate; OV only if required by policy or contract |
| Certificate Authority | Publicly trusted CA with ACME support |
| Suggested CA | Let's Encrypt or another approved public CA |
| Primary Hostname | `portal.meddefense.com` |
| SAN Entries | Only required portal and authentication hostnames |
| Public-Key Algorithm | ECDSA P-256 preferred |
| Compatibility Alternative | RSA-2048 minimum |
| Signature Algorithm | SHA-256 or stronger |
| Key Usage | Digital Signature; additional usage according to key type |
| Extended Key Usage | TLS Web Server Authentication |
| Certificate Validity | CA-permitted short validity period |
| Renewal | Fully automated using ACME |
| Monitoring | Alerts before expiration and on renewal failure |
| Certificate Scope | Single domain or narrow SAN list |
| Wildcard | Avoid unless operationally necessary |
| Private-Key Protection | Restricted permissions, secret manager, or HSM |
| Revocation | OCSP and/or CRL support |
| Certificate Transparency | Public certificate recorded in CT logs |

---

# Certificate Field Explanation

## Subject

The Subject identifies the entity represented by the certificate.

Possible fields include:

- `CN` — Common Name;
- `O` — Organisation;
- `OU` — Organisational Unit;
- `L` — Locality;
- `ST` — State or Province;
- `C` — Country.

DV certificates often include only a hostname and omit organisation details.

## Issuer

The Issuer identifies the CA or intermediate CA that signed the certificate.

The browser verifies the digital signature and builds a chain from:

```text
Leaf certificate
    |
Intermediate CA
    |
Trusted Root CA
```

## Validity Period

The certificate contains:

```text
Not Before
```

and:

```text
Not After
```

A certificate outside this period must be rejected.

## Serial Number

The serial number uniquely identifies the certificate within the issuing CA.

It is used for:

- revocation;
- auditing;
- certificate inventory;
- incident investigation.

## Signature Algorithm

The Signature Algorithm shows how the CA signed the certificate.

Examples from the laboratory:

```text
ecdsa-with-SHA256
```

and:

```text
sha256WithRSAEncryption
```

## Public-Key Algorithm

The public-key algorithm identifies the certificate key type.

Examples:

```text
id-ecPublicKey
```

and:

```text
rsaEncryption
```

## Subject Alternative Name

SAN lists the hostnames covered by the certificate.

Examples:

```text
DNS:github.com
DNS:www.github.com
```

Browsers use SAN for hostname verification.

## Key Usage

Key Usage restricts the permitted cryptographic operations.

Examples:

```text
Digital Signature
```

```text
Key Encipherment
```

## Extended Key Usage

Extended Key Usage identifies the intended application.

For a website, it should include:

```text
TLS Web Server Authentication
```

## Authority Information Access

AIA may provide:

- an OCSP responder URL;
- a CA Issuers URL.

OCSP allows a client to check whether the certificate has been revoked.

The CA Issuers URL helps retrieve the intermediate certificate needed to build the trust chain.

---

# Commands Summary

## Download github.com Certificate

```bash
openssl s_client \
  -connect github.com:443 \
  -servername github.com \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM \
  > certificates/github.com.pem
```

## Download expired.badssl.com Certificate

```bash
openssl s_client \
  -connect expired.badssl.com:443 \
  -servername expired.badssl.com \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM \
  > certificates/expired.badssl.com.pem
```

## Extract Principal Fields

```bash
openssl x509 \
  -in CERTIFICATE.pem \
  -noout \
  -subject \
  -issuer \
  -serial \
  -dates
```

## Extract Signature and Key Details

```bash
openssl x509 \
  -in CERTIFICATE.pem \
  -text \
  -noout \
  | grep -E "Signature Algorithm|Public Key Algorithm|Public-Key:"
```

## Extract SAN

```bash
openssl x509 \
  -in CERTIFICATE.pem \
  -noout \
  -ext subjectAltName
```

## Extract Key Usage

```bash
openssl x509 \
  -in CERTIFICATE.pem \
  -noout \
  -ext keyUsage
```

## Extract Extended Key Usage

```bash
openssl x509 \
  -in CERTIFICATE.pem \
  -noout \
  -ext extendedKeyUsage
```

## Extract Authority Information Access

```bash
openssl x509 \
  -in CERTIFICATE.pem \
  -noout \
  -ext authorityInfoAccess
```

---

# Final Conclusion

This laboratory successfully inspected the certificates presented by `github.com` and `expired.badssl.com`. The GitHub certificate uses a modern ECDSA P-256 public key, SHA-256 signature, correct SAN entries, TLS server authentication usage, and public revocation and issuer information.

The BadSSL certificate uses acceptable RSA-2048 and SHA-256 cryptography but is invalid because it expired in April 2015. This demonstrates that strong algorithms alone do not make a certificate trustworthy. Correct validity, hostname coverage, trust chain, usage, revocation, and certificate lifecycle management are all required.

The `letsencrypt.org` inspection could not be completed because the saved file did not contain a valid certificate. This failure was documented rather than hidden, and corrective commands were provided for repeating the collection.

MedDefense should deploy a publicly trusted, narrowly scoped certificate for its patient portal, use ECDSA P-256 or RSA-2048, automate renewal with ACME, monitor certificate expiration, and ensure that patients never encounter avoidable browser security warnings.
