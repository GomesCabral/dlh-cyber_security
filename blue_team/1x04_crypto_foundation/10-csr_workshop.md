# 10. The CSR Workshop

## Goal

This workshop demonstrates the complete process of generating, inspecting, and preparing a Certificate Signing Request (CSR) for the MedDefense patient portal.

A Certificate Signing Request (CSR) is a PKCS#10 object that contains the identity of the server, its public key, and the requested X.509 certificate extensions. The CSR is digitally signed with the corresponding private key to prove ownership of that key before it is submitted to a Certificate Authority (CA).

> **Note:** The hostname `portal.meddefense.local` is an internal domain. A public CA such as Let's Encrypt cannot issue publicly trusted certificates for internal `.local` domains. Therefore, this CSR is intended for a MedDefense Internal Enterprise Certificate Authority. A public patient portal should instead use a public hostname such as `portal.meddefense.com`.

---

# Part 1 - Key Generation Decision

## Selected Algorithm

```text
ECC P-256
```

ECC P-256 was selected because it provides approximately 128-bit security while using much smaller keys than RSA. Smaller keys reduce CPU usage, bandwidth consumption, and TLS handshake time, making it ideal for the MedDefense patient portal serving approximately 800 HTTPS connections per day. ECC is fully supported by modern browsers and operating systems while maintaining excellent security. RSA-2048 would only be preferred if legacy systems without ECC support had to be accommodated.

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

## Why the Private Key Must Be Protected

The private key represents the identity of the MedDefense patient portal.

It must never be:

- committed to GitHub;
- emailed;
- copied to unsecured systems;
- shared with another administrator;
- exposed through backups without encryption.

Anyone who obtains this key can impersonate the MedDefense patient portal.

---

# Part 2 - CSR Generation

## Selected Subject Information

| Field | Value | Justification |
|-------|-------|---------------|
| Country | LU | MedDefense operates in Luxembourg |
| State | Wiltz | Scenario location |
| Locality | Wiltz | Scenario location |
| Organization | MedDefense Health Systems | Organization name |
| Organizational Unit | Information Technology | Department responsible for the portal |
| Common Name | portal.meddefense.local | Primary portal hostname |

---

## Subject Alternative Names

The CSR requests the following DNS names:

```text
portal.meddefense.local
login.meddefense.local
patient.meddefense.local
```

Modern browsers validate the SAN extension instead of relying only on the Common Name.

---

## OpenSSL Configuration

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

The CSR signature verifies successfully, proving that the request was signed using the private key corresponding to the public key contained inside the CSR.

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

## Display the Requested Extensions

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
        DNS:portal.meddefense.local,
        DNS:login.meddefense.local,
        DNS:patient.meddefense.local

    X509v3 Key Usage: critical
        Digital Signature

    X509v3 Extended Key Usage:
        TLS Web Server Authentication

Signature Algorithm: ecdsa-with-SHA256
```

---

## CSR Validation Checklist

| Validation | Result |
|------------|--------|
| CSR signature valid | ✅ Yes |
| Country | ✅ LU |
| State | ✅ Wiltz |
| Locality | ✅ Wiltz |
| Organization | ✅ MedDefense Health Systems |
| Organizational Unit | ✅ Information Technology |
| Common Name | ✅ portal.meddefense.local |
| SAN entries present | ✅ Yes |
| Key algorithm | ✅ ECC |
| Curve | ✅ P-256 |
| Signature algorithm | ✅ ECDSA with SHA-256 |
| Extended Key Usage | ✅ TLS Web Server Authentication |

---

# Part 4 - Certificate Lifecycle

## Step 1 – Generate the CSR

The administrator generates:

- Private Key (`portal_key.pem`)
- Configuration file (`openssl.cnf`)
- Certificate Signing Request (`portal.csr`)

The private key always remains under MedDefense control.

---

## Step 2 – Submit the CSR

Because the hostname ends with `.local`, the CSR should be submitted to the:

```text
MedDefense Internal Enterprise Certificate Authority
```

A public Certificate Authority such as Let's Encrypt cannot issue certificates for internal domains.

If the patient portal were publicly accessible, MedDefense should instead use:

```text
portal.meddefense.com
```

which could then use Let's Encrypt (ACME) or another commercial CA.

---

## Step 3 – CA Validation

The Certificate Authority verifies:

- the administrator is authorized;
- the requested hostname belongs to MedDefense;
- the SAN entries are correct;
- the CSR signature is valid;
- the requested key meets security policy.

For a public certificate, the CA additionally verifies ownership of the public DNS name through HTTP or DNS validation.

---

## Step 4 – Certificate Issuance

The CA signs the public key contained in the CSR and returns:

- the leaf certificate;
- the intermediate certificate(s);
- installation instructions.

The private key never leaves MedDefense.

---

## Step 5 – Install the Certificate

Install:

- portal certificate;
- intermediate certificate chain;
- portal private key.

The web server configuration must reference the complete certificate chain.

---

## Step 6 – Reload the Web Server

Validate the configuration before reloading.

Apache example:

```bash
sudo apachectl configtest
```

Nginx example:

```bash
sudo nginx -t
```

Reload the service after successful validation.

---

## Step 7 – Verify the Deployment

Inspect the live certificate:

```bash
openssl s_client \
    -connect portal.meddefense.local:443 \
    -servername portal.meddefense.local \
    -showcerts
```

Verify:

- Subject;
- SAN entries;
- certificate chain;
- validity period;
- trusted issuer;
- TLS Web Server Authentication.

---

## Step 8 – Remove the Old Certificate

Once the new certificate is confirmed:

- remove the previous certificate from the web server;
- archive it if required;
- revoke it immediately if the private key was compromised;
- verify that no secondary server is still presenting the old certificate.

---

## Step 9 – Monitor Future Renewals

Configure monitoring for:

- certificate expiration;
- failed renewals;
- invalid certificate chains;
- expired certificates;
- unexpected SAN changes.

Recommended alerts:

| Time Before Expiry | Severity |
|-------------------|----------|
| 60 days | Information |
| 30 days | Warning |
| 14 days | High |
| 7 days | Critical |

---

# MedDefense Recommendation

Although this exercise uses:

```text
portal.meddefense.local
```

a production patient portal should instead use:

```text
portal.meddefense.com
```

Recommended configuration:

| Component | Recommendation |
|------------|---------------|
| Certificate Type | Domain Validation (DV) |
| CA | Let's Encrypt (ACME) or Commercial CA |
| Key Algorithm | ECC P-256 |
| Signature Algorithm | ECDSA with SHA-256 |
| SAN Entries | All public portal hostnames |
| Renewal | Automatic (ACME) |
| Monitoring | Certificate expiration monitoring |

---

# Companion Script

The accompanying script is:

```text
10-generate_csr.sh
```

The script automatically:

1. Creates the OpenSSL configuration.
2. Generates an ECC P-256 private key.
3. Protects the private key.
4. Generates the CSR.
5. Verifies the CSR.
6. Displays the Subject and SAN entries.

Execute:

```bash
chmod +x 10-generate_csr.sh
./10-generate_csr.sh
```

---

# Conclusion

This laboratory demonstrated the complete Certificate Signing Request workflow. MedDefense selected ECC P-256 to balance strong security with high performance. The CSR was successfully generated, verified, and inspected, confirming the correct Subject information, Subject Alternative Names, and TLS server extensions. Finally, the complete certificate lifecycle—from key generation through issuance, deployment, verification, and renewal planning—was documented, providing a repeatable process for securely managing certificates within the MedDefense environment.
