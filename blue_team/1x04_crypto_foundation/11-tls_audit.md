# 11. The TLS Audit

## Goal

This audit evaluates real-world TLS configurations using Qualys SSL Labs and applies the findings to the MedDefense patient portal.

The audit compares an A+ configuration with a B-rated configuration, predicts the likely rating of the current MedDefense portal, proposes a hardened Apache TLS configuration, and explains how protocol downgrade attacks can be prevented.

---

# Part 1 - SSL Labs Analysis

## Testing Method

The tests were performed using:

```text
https://www.ssllabs.com/ssltest/
```

Assessment date:

```text
27 July 2026
```

The following websites were selected:

1. `www.wikipedia.org` — strong TLS configuration with an A+ grade.
2. `cloudflare.com` — lower-rated configuration with a B grade.

SSL Labs evaluates each server endpoint independently. Where a domain had multiple IPv4 or IPv6 endpoints, all reported endpoints received the same grade.

---

# Website 1 - Wikipedia

## Test Summary

| Field | Result |
|---|---|
| Website | `www.wikipedia.org` |
| IPv4 endpoint | `198.35.26.224` |
| IPv6 endpoint | `2620:0:863:ed1a::1` |
| Assessment date | `27 July 2026` |
| Overall grade | **A+** |
| Certificate score | 100 |
| Protocol support score | 100 |
| Key exchange score | Approximately 90 |
| Cipher strength score | Approximately 90 |

Both tested endpoints received an A+ grade.

---

## Protocol Support

The SSL Labs summary confirms support for:

```text
TLS 1.2
TLS 1.3
```

Obsolete protocols were not reported as enabled:

```text
SSL 2.0: Not supported
SSL 3.0: Not supported
TLS 1.0: Not supported
TLS 1.1: Not supported
```

This protocol selection allows the server to receive the highest protocol-support score.

---

## Protocol Details

| Security Feature | Result |
|---|---|
| Secure Renegotiation | Supported |
| Secure Client-Initiated Renegotiation | No |
| Insecure Client-Initiated Renegotiation | No |
| BEAST | Mitigated server-side |
| POODLE SSLv3 | No; SSL 3 is not supported |
| POODLE TLS | No |
| Zombie POODLE | No |
| GOLDENDOODLE | No |
| OpenSSL 0-Length vulnerability | No |
| Sleeping POODLE | No |
| Downgrade prevention | Yes; `TLS_FALLBACK_SCSV` supported |
| TLS compression | No |
| RC4 | No |
| Heartbeat extension | No |
| Heartbleed | No |
| Ticketbleed | No |
| OpenSSL CCS vulnerability | No |
| OpenSSL Padding Oracle vulnerability | No |
| ROBOT | No |
| Forward Secrecy | Yes with most browsers; robust |
| ALPN | Yes: HTTP/2 and HTTP/1.1 |
| NPN | No |
| Session resumption by cache | Yes |
| Session resumption by tickets | Yes |
| OCSP Stapling | No |
| HSTS | Yes |
| HSTS max-age | `106384710` seconds |
| HSTS includeSubDomains | Yes |
| HSTS preload | Yes |
| HPKP | No |
| Long handshake intolerance | No |
| TLS extension intolerance | No |
| TLS version intolerance | No |
| Incorrect SNI alerts | No |
| Common DH primes | No; DHE suites are not supported |
| ECDH public parameter reuse | No |
| Post-Quantum Key Exchange | Supported |
| 0-RTT | Disabled |

---

## Supported Named Groups

The server advertised the following groups in server-preferred order:

```text
X25519MLKEM768
x25519
secp256r1
x448
secp384r1
secp521r1
ffdhe2048
ffdhe3072
```

The preferred hybrid post-quantum group was:

```text
X25519MLKEM768
```

This combines a classical X25519 exchange with ML-KEM-768.

---

## TLS 1.3 Cipher Suites

The TLS 1.3 cipher suites were ordered by server preference:

```text
TLS_AES_128_GCM_SHA256
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_256_GCM_SHA384
```

### `TLS_AES_128_GCM_SHA256`

This suite provides strong authenticated encryption with excellent performance and a 128-bit encryption key.

### `TLS_CHACHA20_POLY1305_SHA256`

This suite provides strong authenticated encryption and performs well on systems without AES hardware acceleration.

### `TLS_AES_256_GCM_SHA384`

This suite provides AES-256 authenticated encryption and a SHA-384-based key schedule for clients requiring a larger AES key.

All TLS 1.3 suites provide forward secrecy through the negotiated ephemeral key exchange.

---

## TLS 1.2 Cipher Suites

The TLS 1.2 suites were ordered by server preference:

```text
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
```

All supported TLS 1.2 suites use:

- ECDHE for forward secrecy;
- ECDSA for server authentication;
- authenticated encryption;
- modern cryptographic algorithms.

The server does not support TLS 1.2 CBC suites, static RSA key exchange, RC4, DES, or 3DES.

The server prefers ChaCha20-Poly1305 for clients without AES-NI hardware acceleration, such as some Android devices.

---

## Key Exchange Strength

The server uses modern elliptic-curve and hybrid post-quantum key exchange.

For the documented connections, SSL Labs reported:

```text
X25519MLKEM768
Equivalent classical strength: approximately RSA 3072 bits
Forward Secrecy: Yes
```

The configuration also supports X25519, P-256, P-384, P-521, X448, and approved finite-field groups.

The server does not reuse ECDH public parameters.

---

## Certificate Details

The SSL Labs summary gave the certificate category a full score of:

```text
100
```

This confirms that the tested endpoint presented a valid and trusted certificate configuration during the assessment.

The detailed certificate subject, issuer, key type, and validity dates were not included in the supplied SSL Labs evidence. Therefore, those values are not fabricated in this report.

The certificate assessment confirmed:

- a trusted certificate;
- valid hostname coverage;
- a valid certificate chain;
- no certificate warning reducing the grade;
- a certificate configuration strong enough to receive the full category score.

---

## HSTS Configuration

Wikipedia returned:

```text
Strict-Transport-Security:
max-age=106384710; includeSubDomains; preload
```

This directs supported browsers to access the domain and its subdomains only through HTTPS for more than three years.

The domain is also included in major browser preload lists.

---

## Warnings or Weaknesses

No critical TLS weakness was identified.

The only notable limitation in the supplied details was:

```text
OCSP Stapling: No
```

Despite this, the endpoint achieved an A+ rating because its protocol configuration, cipher selection, certificate, forward secrecy, and HSTS policy were strong.

---

## Wikipedia Assessment

Wikipedia demonstrates a strong modern TLS deployment. It disables obsolete protocol versions, restricts TLS 1.2 to forward-secret AEAD cipher suites, supports TLS 1.3, provides robust forward secrecy, enables long-duration HSTS with preload, and protects against downgrade attacks.

The absence of OCSP Stapling is a possible improvement, but it did not prevent the service from achieving an A+ rating.

---

# Website 2 - Cloudflare

## Test Summary

| Field | Result |
|---|---|
| Website | `cloudflare.com` |
| IPv6 endpoint | `2606:4700::6810:85e5` |
| Additional IPv6 endpoint | `2606:4700::6810:84e5` |
| IPv4 endpoint | `104.16.132.229` |
| Additional IPv4 endpoint | `104.16.133.229` |
| Assessment date | `27 July 2026` |
| Overall grade | **B** |
| Certificate score | 100 |
| Protocol support score | Approximately 70 |
| Key exchange score | Approximately 90 |
| Cipher strength score | Approximately 90 |

All four tested endpoints received a B grade.

---

## Primary Reason for the B Grade

SSL Labs reported:

```text
This server supports TLS 1.0 and TLS 1.1.
Grade capped to B.
```

This means that the certificate, modern cipher suites, and key exchange were generally strong, but support for obsolete protocol versions prevented a higher grade.

---

## Protocol Support

The server supports:

```text
TLS 1.0
TLS 1.1
TLS 1.2
TLS 1.3
```

The server does not support SSL 3.0.

The continued support for TLS 1.0 and TLS 1.1 is the principal grading problem.

---

## Protocol Details

| Security Feature | Result |
|---|---|
| Secure Renegotiation | Supported |
| Secure Client-Initiated Renegotiation | No |
| Insecure Client-Initiated Renegotiation | No |
| BEAST | Not mitigated server-side for TLS 1.0 |
| Affected BEAST cipher | `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` |
| POODLE SSLv3 | No; SSL 3 is not supported |
| POODLE TLS | No |
| Zombie POODLE | No |
| GOLDENDOODLE | No |
| OpenSSL 0-Length vulnerability | No |
| Sleeping POODLE | No |
| Downgrade prevention | Yes; `TLS_FALLBACK_SCSV` supported |
| TLS compression | No |
| RC4 | No |
| Heartbeat extension | No |
| Heartbleed | No |
| Ticketbleed | No |
| OpenSSL CCS vulnerability | No |
| OpenSSL Padding Oracle vulnerability | No |
| ROBOT | No |
| Forward Secrecy | Supported with modern browsers |
| ALPN | Yes: HTTP/2 and HTTP/1.1 |
| NPN | Yes: HTTP/2 and HTTP/1.1 |
| Session resumption by cache | No; IDs assigned but not accepted |
| Session resumption by tickets | Yes |
| OCSP Stapling | No |
| HSTS | Yes |
| HSTS max-age | `15780000` seconds |
| HSTS includeSubDomains | Yes |
| HPKP | No |
| Common DH primes | No; DHE suites are not supported |
| ECDH public parameter reuse | No |
| Post-Quantum Key Exchange | Supported |
| SSL 2 handshake compatibility | Yes |
| 0-RTT | Disabled |

---

## Supported Named Groups

The server advertised:

```text
X25519MLKEM768
x25519
secp256r1
secp384r1
secp521r1
```

The server supports the hybrid post-quantum group:

```text
X25519MLKEM768
```

---

## TLS 1.3 Cipher Suites

The server had no fixed preference among:

```text
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
```

These are all strong TLS 1.3 authenticated-encryption suites.

---

## Strong TLS 1.2 Cipher Suites

The server supports strong modern TLS 1.2 suites including:

```text
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

These suites provide forward secrecy through ECDHE and use authenticated encryption.

---

## Weak TLS 1.2 Cipher Suites

SSL Labs marked several TLS 1.2 suites as weak, including:

```text
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
```

These use CBC mode rather than an AEAD cipher.

The server also supports static RSA suites marked as weak:

```text
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA256
```

Static RSA key exchange does not provide forward secrecy.

---

## TLS 1.1 Cipher Suites

The TLS 1.1 configuration contains only legacy CBC suites:

```text
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
```

All were marked weak.

---

## TLS 1.0 Cipher Suites

The TLS 1.0 configuration contains legacy CBC suites:

```text
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
```

It also supports:

```text
TLS_RSA_WITH_3DES_EDE_CBC_SHA
```

SSL Labs marked the 3DES suite as weak with approximately 112-bit effective strength.

The presence of TLS 1.0, TLS 1.1, CBC suites, static RSA suites, and 3DES significantly increases backward compatibility but weakens the overall security posture.

---

## BEAST Exposure

SSL Labs reported:

```text
BEAST attack: Not mitigated server-side
TLS 1.0 cipher: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
```

The simplest remediation is to disable TLS 1.0 completely rather than attempting to preserve obsolete compatibility.

---

## Forward Secrecy

Forward secrecy is available with modern browsers through ECDHE suites.

However, the static RSA suites do not provide forward secrecy. If the relevant private key were compromised, previously recorded sessions using static RSA key exchange could potentially be exposed.

---

## Cloudflare Certificate 1 - RSA

### Leaf Certificate

| Field | Result |
|---|---|
| Subject | `cloudflare.com` |
| Common Name | `cloudflare.com` |
| SAN entries | `cloudflare.com`, `ns.cloudflare.com`, `*.ns.cloudflare.com`, `*.secondary.cloudflare.com`, `secondary.cloudflare.com` |
| Serial number | `1b4921e4fd4160940e5e7e91df85cc19` |
| Valid from | `8 July 2026 21:47:18 UTC` |
| Valid until | `6 October 2026 22:47:11 UTC` |
| Public key | RSA 2048 bits |
| RSA exponent | 65537 |
| Signature algorithm | SHA256withRSA |
| Issuer | `WR1` |
| Extended Validation | No |
| Certificate Transparency | Yes |
| OCSP Must-Staple | No |
| Revocation mechanism | CRL |
| Revocation status | Good |
| Trusted | Yes |

SHA-256 fingerprint:

```text
740981668b05eab33cd55af61e4f8beb2ec1bd27263cc3ff5c948496303f7acd
```

Public-key pin:

```text
jdieDwGZiBm3rKlrM0UwK9XA3m9tkvoDiLedPBZsp0s=
```

AIA issuer URL:

```text
http://i.pki.goog/wr1.crt
```

CRL URL:

```text
http://c.pki.goog/wr1/WFaXJLtXExs.crl
```

---

## RSA Certificate Chain

Three certificates were provided.

### Intermediate Certificate

| Field | Result |
|---|---|
| Subject | `WR1` |
| Valid until | `20 February 2029 14:00:00 UTC` |
| Public key | RSA 2048 bits |
| Issuer | `GTS Root R1` |
| Signature algorithm | SHA256withRSA |

### Additional CA Certificate

| Field | Result |
|---|---|
| Subject | `GTS Root R1` |
| Valid until | `28 January 2028 00:00:42 UTC` |
| Public key | RSA 4096 bits |
| Issuer | `GlobalSign Root CA` |
| Signature algorithm | SHA256withRSA |

Chain issues:

```text
None
```

---

## Cloudflare Certificate 2 - ECC

### Leaf Certificate

| Field | Result |
|---|---|
| Subject | `cloudflare.com` |
| Common Name | `cloudflare.com` |
| SAN entries | `cloudflare.com`, `ns.cloudflare.com`, `*.ns.cloudflare.com`, `*.secondary.cloudflare.com`, `secondary.cloudflare.com` |
| Serial number | `5bb0f0aa84c8fece0e72d805ba7a5d2b` |
| Valid from | `8 July 2026 21:47:39 UTC` |
| Valid until | `6 October 2026 22:47:27 UTC` |
| Public key | EC 256 bits |
| Signature algorithm | SHA256withECDSA |
| Issuer | `WE1` |
| Extended Validation | No |
| Certificate Transparency | Yes |
| OCSP Must-Staple | No |
| Revocation mechanism | CRL |
| Revocation status | Good |
| Trusted | Yes |

SHA-256 fingerprint:

```text
6a7041850081b32dbe52400df0a2842c32d55e80ffa40e339f7c1508a913d3f4
```

Public-key pin:

```text
fxGIXIhaAKvJHEuIKO06PV0wAfgfICkUEVOA04lA8K4=
```

AIA issuer URL:

```text
http://i.pki.goog/we1.crt
```

CRL URL:

```text
http://c.pki.goog/we1/gxIBv6B2hYw.crl
```

---

## ECC Certificate Chain

Three certificates were provided.

### Intermediate Certificate

| Field | Result |
|---|---|
| Subject | `WE1` |
| Valid until | `20 February 2029 14:00:00 UTC` |
| Public key | EC 256 bits |
| Issuer | `GTS Root R4` |
| Signature algorithm | SHA384withECDSA |

### Additional CA Certificate

| Field | Result |
|---|---|
| Subject | `GTS Root R4` |
| Valid until | `28 January 2028 00:00:42 UTC` |
| Public key | EC 384 bits |
| Issuer | `GlobalSign Root CA` |
| Signature algorithm | SHA256withRSA |

Chain issues:

```text
None
```

---

## Certificate Trust

Both Cloudflare leaf certificates were trusted by:

```text
Mozilla
Apple
Android
Java
Windows
```

The certificates were valid, not revoked, and had no chain issues.

The certificate category therefore received a full score. The B rating was caused primarily by obsolete protocol support and weak compatibility cipher suites, not by certificate problems.

---

## HSTS

Cloudflare returned:

```text
Strict-Transport-Security:
max-age=15780000; includeSubDomains
```

HSTS was enabled and the domain appeared in major browser preload lists.

The configured max-age is approximately six months, which is shorter than the one-year value commonly recommended for mature deployments.

---

## Warnings and Weaknesses

The main weaknesses identified were:

1. TLS 1.0 support.
2. TLS 1.1 support.
3. Grade capped at B due to obsolete protocol support.
4. BEAST not mitigated server-side for a TLS 1.0 CBC suite.
5. Multiple CBC cipher suites marked weak.
6. Static RSA cipher suites without forward secrecy.
7. 3DES supported under TLS 1.0.
8. SSL 2 handshake compatibility enabled.
9. OCSP Stapling disabled.
10. Session-ID resumption assigned but not accepted.

---

## Cloudflare Assessment

Cloudflare demonstrates that a server can have a trusted certificate, modern TLS 1.3 support, post-quantum key exchange, HSTS, strong AEAD suites, and forward secrecy while still receiving a B grade.

Its broad legacy-client compatibility introduces TLS 1.0, TLS 1.1, CBC suites, static RSA suites, and 3DES. The grade therefore reflects the weakest permitted negotiation options, not only the strongest available configuration.

---

# Comparison

| Security Area | Wikipedia | Cloudflare |
|---|---|---|
| Overall grade | A+ | B |
| TLS 1.0 | Disabled | Enabled |
| TLS 1.1 | Disabled | Enabled |
| TLS 1.2 | Enabled | Enabled |
| TLS 1.3 | Enabled | Enabled |
| TLS 1.2 AEAD-only | Yes | No |
| CBC suites | No | Yes |
| Static RSA key exchange | No | Yes |
| 3DES | No | Yes under TLS 1.0 |
| Forward secrecy | Robust with most browsers | Available with modern browsers |
| Downgrade prevention | TLS_FALLBACK_SCSV | TLS_FALLBACK_SCSV |
| HSTS | Long duration, includeSubDomains, preload | Enabled with shorter max-age |
| OCSP Stapling | No | No |
| Post-quantum exchange | Supported | Supported |
| Certificate problems | None identified | None |
| Main weakness | OCSP Stapling absent | Legacy protocols and weak suites |

---

# Main Lesson from the Comparison

Wikipedia exposes only modern protocol versions and a small, controlled list of forward-secret authenticated-encryption cipher suites. Cloudflare provides strong modern options but also permits obsolete protocols and weak cipher suites for compatibility.

The comparison demonstrates that a TLS server is judged by the weakest configuration it permits. Supporting a strong TLS 1.3 suite does not compensate for also allowing TLS 1.0 and 3DES.

---

# Part 2 - MedDefense Patient Portal Assessment

## Known Findings

Finding 005 identified:

```text
TLS 1.0 supported
TLS 1.2 supported
TLS 1.3 not supported
HSTS not configured
OCSP Stapling not configured
Default Apache cipher configuration
```

Finding 013 identified:

```text
Certificate expires in 18 days
Automatic renewal is not configured
```

---

## Predicted SSL Labs Grade

The predicted grade is:

```text
B or lower
```

TLS 1.0 support alone would likely cap the grade at B, as demonstrated by Cloudflare.

The grade could be lower if the default Apache configuration includes additional weak ciphers, inadequate key exchange, an incomplete certificate chain, or other legacy behaviour.

If the certificate expires, certificate validation will fail and the service may no longer receive a normal passing grade.

---

## Issues That Would Reduce the Grade

### 1. TLS 1.0 Enabled

TLS 1.0 is obsolete and creates exposure to legacy attacks and downgrade negotiation.

### 2. TLS 1.3 Not Supported

The portal lacks the simplified, modern TLS 1.3 handshake and its removal of legacy cipher constructions.

### 3. Certificate Near Expiration

The certificate has only 18 days remaining, creating a severe operational availability and trust risk.

### 4. No Automatic Renewal

Manual renewal increases the chance that the certificate will expire unnoticed.

### 5. HSTS Missing

The portal does not instruct browsers to enforce HTTPS, leaving initial HTTP access more exposed to SSL stripping.

### 6. OCSP Stapling Missing

Clients cannot receive a recent CA-signed revocation-status response directly from the portal.

### 7. Default Cipher Configuration

The undocumented Apache defaults may permit CBC suites, static RSA, or other legacy options.

### 8. Forward Secrecy Not Confirmed

Static RSA suites may permit historical-session compromise if the certificate private key is later exposed.

### 9. TLS 1.2 Server Preference Not Confirmed

A client may select a weaker mutually supported suite if the server does not enforce a secure preference.

### 10. Session-Ticket Management Unknown

Long-lived ticket-encryption keys may weaken the intended forward-secrecy protection.

### 11. Certificate Chain Not Confirmed

An incomplete intermediate chain would prevent some clients from validating the portal certificate.

### 12. No Documented Downgrade Testing

The portal has not been tested to confirm that obsolete fallback and compatibility behaviour are disabled.

---

# Predicted MedDefense Score Summary

| Category | Predicted Result |
|---|---|
| Certificate | Currently valid but operationally at risk |
| Protocol Support | Reduced because TLS 1.0 is enabled |
| Key Exchange | Unknown |
| Cipher Strength | Unknown due to default configuration |
| HSTS | Missing |
| OCSP Stapling | Missing |
| Overall Grade | B or lower |

---

# Part 3 - Hardened Apache TLS Configuration

## Assumptions

The following configuration assumes:

- Apache HTTP Server 2.4;
- OpenSSL 1.1.1 or newer;
- TLS 1.3 support;
- `mod_ssl` enabled;
- `mod_headers` enabled;
- a valid portal certificate and complete chain;
- ECC and/or RSA certificate compatibility as required.

---

## Recommended Configuration

```apache
<VirtualHost *:443>
    ServerName portal.meddefense.local
    ServerAlias login.meddefense.local
    ServerAlias patient.meddefense.local

    SSLEngine on

    SSLCertificateFile /etc/ssl/certs/portal-fullchain.pem
    SSLCertificateKeyFile /etc/ssl/private/portal_key.pem

    # Allow only TLS 1.2 and TLS 1.3.
    SSLProtocol -all +TLSv1.2 +TLSv1.3

    # Approved TLS 1.2 suites in server-preferred order.
    SSLCipherSuite \
        ECDHE-ECDSA-AES256-GCM-SHA384:\
        ECDHE-RSA-AES256-GCM-SHA384:\
        ECDHE-ECDSA-CHACHA20-POLY1305:\
        ECDHE-RSA-CHACHA20-POLY1305:\
        ECDHE-ECDSA-AES128-GCM-SHA256:\
        ECDHE-RSA-AES128-GCM-SHA256

    # Approved TLS 1.3 cipher suites.
    SSLOpenSSLConfCmd Ciphersuites \
        TLS_AES_256_GCM_SHA384:\
        TLS_CHACHA20_POLY1305_SHA256:\
        TLS_AES_128_GCM_SHA256

    # Approved ephemeral groups in preference order.
    SSLOpenSSLConfCmd Curves X25519:P-256:P-384

    # Prefer the server's TLS 1.2 cipher order.
    SSLHonorCipherOrder on

    # Disable TLS compression.
    SSLCompression off

    # Block insecure legacy renegotiation.
    SSLInsecureRenegotiation off

    # Disable tickets until secure ticket-key rotation is deployed.
    SSLSessionTickets off

    # Enable OCSP Stapling.
    SSLUseStapling on

    # Require SNI for this named virtual host.
    SSLStrictSNIVHostCheck on

    # Enforce HTTPS for one year.
    Header always set Strict-Transport-Security \
        "max-age=31536000; includeSubDomains"

    # Additional browser protections.
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy \
        "strict-origin-when-cross-origin"

    ErrorLog ${APACHE_LOG_DIR}/portal_ssl_error.log
    CustomLog ${APACHE_LOG_DIR}/portal_ssl_access.log combined
</VirtualHost>

SSLStaplingCache "shmcb:/var/run/ocsp_stapling(128000)"
```

---

# Configuration Reasoning

## Protocol Versions

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
```

TLS 1.0 and TLS 1.1 are disabled because they are obsolete and unnecessarily expose patients to weaker protocol negotiation.

---

## TLS 1.3 Cipher Order

### `TLS_AES_256_GCM_SHA384`

This provides AES-256 authenticated encryption and is preferred for highly sensitive healthcare information.

### `TLS_CHACHA20_POLY1305_SHA256`

This provides secure authenticated encryption with strong software performance on clients lacking AES hardware acceleration.

### `TLS_AES_128_GCM_SHA256`

This provides strong authenticated encryption and efficient performance while maintaining an accepted 128-bit security level.

---

## TLS 1.2 Cipher Selection

Every permitted suite uses:

```text
ECDHE
```

to provide forward secrecy.

Only the following authenticated-encryption constructions are allowed:

```text
AES-GCM
ChaCha20-Poly1305
```

CBC, static RSA, RC4, DES, 3DES, export suites, NULL encryption, anonymous authentication, and MD5 are excluded.

---

## ECDSA and RSA Variants

Both authentication variants are listed because MedDefense may use an ECC certificate while retaining an approved RSA certificate for specific legacy compatibility requirements.

When only one certificate type is installed, only the compatible suites will be negotiated.

---

## Named Groups

```apache
SSLOpenSSLConfCmd Curves X25519:P-256:P-384
```

X25519 is preferred for efficient modern key agreement, while P-256 and P-384 provide broad standards-based compatibility.

---

## HSTS

```apache
Header always set Strict-Transport-Security \
    "max-age=31536000; includeSubDomains"
```

The one-year max-age instructs browsers to use HTTPS exclusively.

`includeSubDomains` must be enabled only after MedDefense confirms that every subdomain supports HTTPS.

The `preload` option should not be added until all preload requirements are met and the decision is formally approved.

---

## OCSP Stapling

```apache
SSLUseStapling on
```

OCSP Stapling allows the portal to deliver a CA-signed certificate-status response during the TLS handshake, improving privacy and reducing client dependency on an external OCSP responder.

---

## Session Tickets

```apache
SSLSessionTickets off
```

Tickets are disabled until MedDefense implements secure, automated, frequent ticket-key rotation across all portal nodes.

---

## Secure Renegotiation

```apache
SSLInsecureRenegotiation off
```

The portal must never permit insecure legacy renegotiation.

---

## TLS Compression

```apache
SSLCompression off
```

TLS compression is disabled to prevent compression-based information leakage.

---

## Server Cipher Preference

```apache
SSLHonorCipherOrder on
```

For TLS 1.2, the server's approved cipher ordering takes precedence over a client's weaker preference.

---

# Validation Procedure

## 1. Confirm Required Apache Modules

```bash
apache2ctl -M | grep -E 'ssl|headers'
```

Expected modules:

```text
ssl_module
headers_module
```

---

## 2. Back Up the Existing Configuration

```bash
sudo cp \
  /etc/apache2/sites-available/portal-ssl.conf \
  /etc/apache2/sites-available/portal-ssl.conf.bak
```

---

## 3. Validate Apache Configuration

```bash
sudo apachectl configtest
```

Expected output:

```text
Syntax OK
```

---

## 4. Reload Apache

```bash
sudo systemctl reload apache2
```

---

## 5. Confirm TLS 1.0 Is Rejected

```bash
openssl s_client \
  -connect portal.meddefense.local:443 \
  -servername portal.meddefense.local \
  -tls1
```

Expected result:

```text
Handshake failure or unsupported protocol
```

---

## 6. Confirm TLS 1.1 Is Rejected

```bash
openssl s_client \
  -connect portal.meddefense.local:443 \
  -servername portal.meddefense.local \
  -tls1_1
```

Expected result:

```text
Handshake failure or unsupported protocol
```

---

## 7. Confirm TLS 1.2 Works

```bash
openssl s_client \
  -connect portal.meddefense.local:443 \
  -servername portal.meddefense.local \
  -tls1_2
```

Expected result:

```text
Successful TLS 1.2 handshake
```

---

## 8. Confirm TLS 1.3 Works

```bash
openssl s_client \
  -connect portal.meddefense.local:443 \
  -servername portal.meddefense.local \
  -tls1_3
```

Expected result:

```text
Successful TLS 1.3 handshake
```

---

## 9. Verify HSTS

```bash
curl -I https://portal.meddefense.local
```

Expected header:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## 10. Verify OCSP Stapling

```bash
openssl s_client \
  -connect portal.meddefense.local:443 \
  -servername portal.meddefense.local \
  -status </dev/null
```

Expected output includes:

```text
OCSP Response Status: successful
```

---

## 11. Verify Certificate Details

```bash
echo | openssl s_client \
  -connect portal.meddefense.local:443 \
  -servername portal.meddefense.local 2>/dev/null \
  | openssl x509 \
      -noout \
      -subject \
      -issuer \
      -serial \
      -dates
```

---

# Part 4 - TLS Downgrade Attack

A TLS downgrade attack occurs when an attacker interferes with protocol negotiation and causes the client and server to believe that the strongest common protocol is unavailable. If MedDefense supports both TLS 1.0 and TLS 1.2, the attacker may disrupt the TLS 1.2 negotiation and attempt to force the client to retry using TLS 1.0. The resulting connection may still appear encrypted while using weaker legacy protections and cipher suites. The simplest and most reliable prevention is to disable TLS 1.0 and TLS 1.1 entirely so that no obsolete fallback option exists.

HSTS also helps prevent SSL stripping and insecure HTTP access, but it does not replace disabling obsolete TLS protocols.

---

# Remediation Plan

| Priority | Action | Reason |
|---:|---|---|
| 1 | Renew the portal certificate | Prevent imminent certificate expiration |
| 2 | Configure automatic renewal | Prevent recurrence |
| 3 | Disable TLS 1.0 | Remove obsolete negotiation |
| 4 | Disable TLS 1.1 | Remove obsolete negotiation |
| 5 | Enable TLS 1.3 | Provide modern protocol security |
| 6 | Restrict TLS 1.2 to ECDHE and AEAD suites | Remove weak CBC and static RSA suites |
| 7 | Enable HSTS | Prevent insecure HTTP downgrade |
| 8 | Enable OCSP Stapling | Improve certificate-status delivery |
| 9 | Validate the complete chain | Ensure client trust |
| 10 | Repeat TLS testing after deployment | Confirm remediation effectiveness |

---

# Expected Post-Remediation State

```text
TLS 1.0: Disabled
TLS 1.1: Disabled
TLS 1.2: Enabled
TLS 1.3: Enabled
CBC suites: Disabled
Static RSA key exchange: Disabled
3DES: Disabled
Forward Secrecy: Enabled
HSTS: Enabled
OCSP Stapling: Enabled
Certificate: Valid
Renewal: Automated
```

Expected SSL Labs objective for a public version of the portal:

```text
A or A+
```

An A+ rating would normally require a strong TLS configuration together with an appropriate HSTS policy under the grading methodology in effect at the time.

---

# Final Conclusion

The SSL Labs comparison demonstrates that HTTPS alone does not guarantee a strong TLS configuration.

Wikipedia achieved an A+ grade by disabling obsolete protocol versions, limiting TLS 1.2 to modern ECDHE authenticated-encryption suites, supporting TLS 1.3, providing robust forward secrecy, enabling long-duration HSTS, and protecting against downgrade attacks.

Cloudflare received a B despite having valid certificates, TLS 1.3, modern AEAD suites, post-quantum key exchange, and HSTS. Its support for TLS 1.0, TLS 1.1, CBC suites, static RSA, and 3DES created weaker negotiation paths and capped the grade.

The MedDefense portal has a similar weakness because TLS 1.0 remains enabled. It also lacks TLS 1.3, HSTS, OCSP Stapling, documented cipher restrictions, and automatic certificate renewal.

The primary remediation is to disable obsolete protocols and permit only TLS 1.2 and TLS 1.3 with forward-secret authenticated-encryption suites. The portal must also renew its certificate, automate the next renewal, enable HSTS and OCSP Stapling, and validate the final configuration before closing Findings 005 and 013.
