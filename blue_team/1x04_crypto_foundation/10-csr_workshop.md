# 10. The CSR Workshop

## Goal

This workshop demonstrates the complete process of generating, inspecting, submitting, issuing, installing, verifying, replacing, and monitoring a Certificate Signing Request and certificate for the MedDefense patient portal.

A Certificate Signing Request (CSR) is a PKCS#10 object containing the server identity, public key, and requested X.509 extensions. The CSR is signed with the corresponding private key to prove that MedDefense controls that key before the request is submitted to a Certificate Authority.

> **Important:** The hostname `portal.meddefense.local` is an internal hostname. A public CA such as Let's Encrypt cannot issue a publicly trusted certificate for `.local`. Therefore, this laboratory CSR must be submitted to a MedDefense Internal Enterprise CA. A real Internet-facing portal should use a public DNS name such as `portal.meddefense.com`.

---

# Part 1 - Key Generation Decision

## Selected Algorithm

```text
ECC P-256
```

ECC P-256 was selected because it provides approximately 128-bit classical security with a much smaller key than RSA. It reduces CPU use, certificate size, bandwidth consumption, and TLS handshake overhead, which is suitable for a portal handling approximately 800 patient connections per day. Modern browsers and operating systems support P-256 broadly. RSA-2048 would remain the compatibility fallback if a required legacy client or integration did not support ECDSA certificates.

---

## Generate the Private Key

Command:

```bash
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out portal_key.pem
```

Protect the private key:

```bash
chmod 600 portal_key.pem
```

Verify the permissions:

```bash
ls -l portal_key.pem
```

Output:

```text
-rw-------. 1 gomes gomes 241 Jul 27 16:13 portal_key.pem
```

---

## Private-Key Protection

The private key represents the cryptographic identity of the MedDefense patient portal.

It must never be:

- committed to Git;
- sent by email;
- copied into support tickets;
- stored in plaintext backups;
- shared with unauthorised administrators;
- transferred through insecure channels.

Anyone who obtains this private key may be able to impersonate the MedDefense portal.

---

# Part 2 - CSR Generation

## Selected Subject Information

| Field | Value | Justification |
|---|---|---|
| Country | `LU` | MedDefense operates in Luxembourg. |
| State or Province | `Wiltz` | Scenario location. |
| Locality | `Wiltz` | Scenario locality. |
| Organisation | `MedDefense Health Systems` | Organisational identity. |
| Organisational Unit | `Information Technology` | Team responsible for the portal. |
| Common Name | `portal.meddefense.local` | Primary internal portal hostname required by the task. |

---

## Subject Alternative Names

The CSR requests the following DNS names:

```text
portal.meddefense.local
login.meddefense.local
patient.meddefense.local
```

Modern hostname validation relies on the Subject Alternative Name extension. Every hostname used to access the service must therefore appear in the SAN list.

---

## OpenSSL Configuration File

Create:

```bash
nano openssl.cnf
```

Content:

```ini
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = req_ext
default_md = sha256

[ req_distinguished_name ]
C = LU
ST = Wiltz
L = Wiltz
O = MedDefense Health Systems
OU = Information Technology
CN = portal.meddefense.local

[ req_ext ]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = portal.meddefense.local
DNS.2 = login.meddefense.local
DNS.3 = patient.meddefense.local
```

---

## Generate the CSR

Command:

```bash
openssl req \
  -new \
  -sha256 \
  -key portal_key.pem \
  -out portal.csr \
  -config openssl.cnf
```

Verify the generated files:

```bash
ls -l openssl.cnf portal.csr portal_key.pem
```

Output:

```text
-rw-rw-r--. 1 gomes gomes 472 Jul 27 16:13 openssl.cnf
-rw-rw-r--. 1 gomes gomes 725 Jul 27 16:13 portal.csr
-rw-------. 1 gomes gomes 241 Jul 27 16:13 portal_key.pem
```

---

# Part 3 - CSR Inspection

## Verify the CSR Signature

Command:

```bash
openssl req \
  -in portal.csr \
  -noout \
  -verify
```

Output:

```text
Certificate request self-signature verify OK
```

This confirms that the CSR was signed by the private key corresponding to the public key contained in the request.

---

## Display the Subject

Command:

```bash
openssl req \
  -in portal.csr \
  -noout \
  -subject
```

Output:

```text
subject=C=LU, ST=Wiltz, L=Wiltz, O=MedDefense Health Systems, OU=Information Technology, CN=portal.meddefense.local
```

---

## Display Requested Extensions

Command:

```bash
openssl req \
  -in portal.csr \
  -noout \
  -text \
  | sed -n '/Requested Extensions:/,/Signature Algorithm:/p'
```

Output:

```text
Requested Extensions:
    X509v3 Subject Alternative Name:
        DNS:portal.meddefense.local, DNS:login.meddefense.local, DNS:patient.meddefense.local
    X509v3 Key Usage: critical
        Digital Signature
    X509v3 Extended Key Usage:
        TLS Web Server Authentication
Signature Algorithm: ecdsa-with-SHA256
```

---

## CSR Validation Checklist

| Validation Item | Result |
|---|---|
| CSR signature valid | Yes |
| Country | `LU` |
| State | `Wiltz` |
| Locality | `Wiltz` |
| Organisation | `MedDefense Health Systems` |
| Organisational Unit | `Information Technology` |
| Common Name | `portal.meddefense.local` |
| SAN: `portal.meddefense.local` | Present |
| SAN: `login.meddefense.local` | Present |
| SAN: `patient.meddefense.local` | Present |
| Key algorithm | ECC |
| Curve | P-256 |
| Key Usage | Digital Signature |
| Extended Key Usage | TLS Web Server Authentication |
| CSR signature algorithm | ECDSA with SHA-256 |

---

# Part 4 - The Full Certificate Lifecycle

## Lifecycle Stage 1 - CSR Generated

The CSR generation stage is complete.

Generated files:

```text
portal_key.pem
portal.csr
openssl.cnf
```

The private key remains under MedDefense control. Only the CSR is sent to the CA.

---

## Lifecycle Stage 2 - Submission to CA

### Submission to CA

Because the requested hostname is:

```text
portal.meddefense.local
```

the CSR must be submitted to:

```text
MedDefense Internal Enterprise Certificate Authority
```

The administrator submits:

```text
portal.csr
```

through the approved internal certificate-enrolment portal, CA API, or controlled PKI workflow.

The following file must never be submitted:

```text
portal_key.pem
```

For a public portal using:

```text
portal.meddefense.com
```

MedDefense could use Let's Encrypt through ACME or a commercial public CA.

---

## Lifecycle Stage 3 - Validation Process

### Validation Process

The internal CA verifies:

1. the requester is an authorised MedDefense administrator;
2. the requested hostname belongs to an approved MedDefense service;
3. the SAN entries match the approved service inventory;
4. the CSR signature is valid;
5. the requested key algorithm and size comply with policy;
6. the requester is permitted to obtain a TLS server certificate;
7. the certificate template permits `TLS Web Server Authentication`.

For a public DV certificate, the CA would verify control of each public DNS name through an ACME challenge such as:

```text
HTTP-01
```

or:

```text
DNS-01
```

A public CA validates domain control, not the clinical safety or trustworthiness of the application.

---

## Lifecycle Stage 4 - Certificate Issuance

### Certificate Issuance

After successful validation, the CA signs the public key and requested identity from the CSR.

The CA returns:

- the portal leaf certificate;
- one or more intermediate CA certificates;
- installation instructions;
- certificate serial number;
- validity period;
- revocation information.

The CA does not need access to the private key.

The issued certificate should contain:

```text
Subject:
C=LU
ST=Wiltz
L=Wiltz
O=MedDefense Health Systems
OU=Information Technology
CN=portal.meddefense.local
```

and the requested SAN entries.

---

## Lifecycle Stage 5 - Installation on the Web Server

### Installation on the Web Server

Install the following files on the portal web server or reverse proxy:

```text
portal certificate
intermediate certificate chain
portal_key.pem
```

The private key must remain protected with restrictive permissions.

Example:

```bash
chmod 600 portal_key.pem
```

The web-server configuration must reference the complete certificate chain rather than only the leaf certificate.

---

## Lifecycle Stage 6 - Web-Server Configuration Validation

Before activating the certificate, validate the server configuration.

Apache example:

```bash
sudo apachectl configtest
```

Expected output:

```text
Syntax OK
```

Nginx example:

```bash
sudo nginx -t
```

Expected output:

```text
syntax is ok
test is successful
```

Only reload the web server after the configuration test succeeds.

---

## Lifecycle Stage 7 - Certificate Activation

Reload the applicable service.

Apache example:

```bash
sudo systemctl reload apache2
```

Nginx example:

```bash
sudo systemctl reload nginx
```

A graceful reload reduces service disruption and allows active connections to complete where supported.

---

## Lifecycle Stage 8 - Verification That the New Certificate Is Serving Correctly

### Verification That the New Certificate Is Serving Correctly

Inspect the certificate presented by the live service:

```bash
openssl s_client \
  -connect portal.meddefense.local:443 \
  -servername portal.meddefense.local \
  -showcerts </dev/null
```

Check the live Subject, Issuer, serial number, and dates:

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

Verify the hostname:

```bash
echo | openssl s_client \
  -connect portal.meddefense.local:443 \
  -servername portal.meddefense.local \
  -verify_hostname portal.meddefense.local
```

Confirm:

- the new certificate is presented;
- the Subject is correct;
- every required SAN is present;
- the chain reaches a trusted root;
- the validity period is correct;
- the certificate permits TLS Web Server Authentication;
- the public key matches the new private key;
- there are no browser warnings;
- the portal remains available.

---

## Lifecycle Stage 9 - Functional Testing

Test the main workflows after installation:

- patient login;
- appointment access;
- account recovery;
- mobile browser access;
- portal redirects;
- API integrations;
- all SAN hostnames;
- monitoring probes;
- supported legacy clients.

A certificate may be technically valid but still break access if the required hostname was omitted from the SAN extension.

---

## Lifecycle Stage 10 - Decommission of the Old Certificate

### Decommission of the Old Certificate

After the new certificate is confirmed as active:

1. remove the old certificate from the active web-server configuration;
2. remove old copies from deployment directories;
3. confirm secondary nodes and load balancers no longer present it;
4. archive it only where retention policy requires;
5. record the replacement in the certificate inventory;
6. revoke it if the old private key was exposed or compromised.

A normal renewal does not always require revocation, but the old certificate must no longer be served by production systems.

---

## Lifecycle Stage 11 - Monitoring for the Next Renewal

### Monitoring for the Next Renewal

MedDefense must monitor:

- expiration date;
- failed renewal attempts;
- failed deployment;
- incorrect Subject or SAN entries;
- unexpected issuer changes;
- incomplete certificate chains;
- revoked certificates;
- private-key permission changes;
- old certificates still presented by secondary nodes.

Recommended warning thresholds:

| Time Before Expiration | Severity |
|---|---|
| 60 days | Informational |
| 30 days | Warning |
| 14 days | High |
| 7 days | Critical |

For short-lived certificates renewed automatically, the thresholds should align with the normal ACME renewal window.

---

## Lifecycle Stage 12 - Renewal Process

At the next renewal:

1. generate a new private key or follow the approved key-reuse policy;
2. create a new CSR;
3. submit the CSR to the CA;
4. complete validation;
5. receive the replacement certificate;
6. install the new certificate and chain;
7. test the configuration;
8. reload the service;
9. verify the live certificate;
10. decommission the previous certificate;
11. update the certificate inventory.

The process should be automated where possible.

---

# Internal Versus Public Certificate Decision

## Internal Portal

For:

```text
portal.meddefense.local
```

use:

```text
MedDefense Internal Enterprise CA
```

The internal CA root certificate must be installed in the trust stores of all authorised client systems.

## Public Patient Portal

For real patients accessing the portal over the Internet, use:

```text
portal.meddefense.com
```

Recommended public certificate approach:

| Component | Recommendation |
|---|---|
| Certificate type | DV unless OV is required by policy |
| CA | Publicly trusted CA |
| Issuance method | ACME |
| Key algorithm | ECC P-256 |
| Signature | ECDSA with SHA-256 |
| SANs | Only required public hostnames |
| Renewal | Fully automated |
| Monitoring | Expiration and deployment monitoring |

---

# Companion Automation Script

The companion script is:

```text
10-generate_csr.sh
```

It automates:

1. creation of `openssl.cnf`;
2. ECC P-256 private-key generation;
3. private-key permission hardening;
4. CSR generation;
5. CSR signature verification;
6. Subject display;
7. SAN and requested-extension display.

Run it:

```bash
chmod +x 10-generate_csr.sh
```

Validate the script:

```bash
bash -n 10-generate_csr.sh
```

Execute:

```bash
./10-generate_csr.sh
```

Output:

```text
Certificate request self-signature verify OK
subject=C=LU, ST=Wiltz, L=Wiltz, O=MedDefense Health Systems, OU=Information Technology, CN=portal.meddefense.local

Requested extensions:
            Requested Extensions:
                X509v3 Subject Alternative Name:
                    DNS:portal.meddefense.local, DNS:login.meddefense.local, DNS:patient.meddefense.local
                X509v3 Key Usage: critical
                    Digital Signature
                X509v3 Extended Key Usage:
                    TLS Web Server Authentication
    Signature Algorithm: ecdsa-with-SHA256

-rw-rw-r--. 1 gomes gomes 472 Jul 27 16:13 openssl.cnf
-rw-rw-r--. 1 gomes gomes 725 Jul 27 16:13 portal.csr
-rw-------. 1 gomes gomes 241 Jul 27 16:13 portal_key.pem
```

---

# Security Conclusions

The CSR was generated successfully using an ECC P-256 private key and signed with ECDSA and SHA-256. Its Subject and SAN entries were inspected and confirmed, and the CSR signature verified successfully.

The certificate lifecycle does not end when the CSR is created. It includes:

1. CSR generation;
2. Submission to CA;
3. Validation process;
4. Certificate issuance;
5. Installation on the web server;
6. Verification that the new certificate is serving correctly;
7. Decommission of the old certificate;
8. Monitoring for the next renewal.

The internal `.local` hostname requires an internal enterprise CA. A real public patient portal should use a registered public hostname and automated issuance from a publicly trusted CA.

Strong certificate security depends on correct key generation, complete SAN coverage, trusted issuance, secure installation, chain verification, old-certificate removal, and continuous lifecycle monitoring.
