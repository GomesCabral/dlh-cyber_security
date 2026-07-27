# 9. The Chain of Trust

## Goal

This laboratory captures and verifies a complete X.509 certificate chain. It demonstrates how trust propagates from a trusted Root Certificate Authority through an Intermediate Certificate Authority to a website certificate.

The laboratory also demonstrates what happens when an intermediate certificate is missing, explains certificate revocation mechanisms, and explores the trusted Root CA store on the local Linux system.

---

# Part 1 - Capture the Full Certificate Chain

## Selected Website

The website selected for this laboratory is:

```text
github.com
```

GitHub was selected because its TLS server sends a leaf certificate and at least one intermediate CA certificate.

---

## Step 1 - Connect to the Server and Display the Chain

Command:

```bash
openssl s_client \
  -connect github.com:443 \
  -servername github.com \
  -showcerts </dev/null
```

### Explanation

The options mean:

- `-connect github.com:443` connects to the HTTPS service.
- `-servername github.com` sends the hostname through Server Name Indication (SNI).
- `-showcerts` displays the certificate list sent by the server.
- `</dev/null` closes the input so the command does not remain interactive.

The `-showcerts` option displays the certificates sent by the server. It does not by itself prove that the chain is trusted or valid.

---

## Step 2 - Save the Entire Server-Supplied Chain

```bash
openssl s_client \
  -connect github.com:443 \
  -servername github.com \
  -showcerts </dev/null 2>/dev/null \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
  > github-chain.pem
```

Verify the file:

```bash
ls -lh github-chain.pem
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

Count the certificates:

```bash
grep -c "BEGIN CERTIFICATE" github-chain.pem
```

Output:

```text
[PASTE YOUR REAL NUMBER HERE]
```

The number above represents the certificates sent by the server. In most public TLS deployments, the server sends:

1. the leaf website certificate;
2. one or more intermediate CA certificates.

The trusted root certificate is normally not sent because the client is expected to already possess it in its trust store.

---

## Step 3 - Split the Chain into Separate Files

Create an output directory:

```bash
mkdir -p github-certificates
```

Split each PEM certificate:

```bash
awk '
/-----BEGIN CERTIFICATE-----/ {
    cert_number++
    output_file=sprintf("github-certificates/cert-%02d.pem", cert_number)
}
output_file {
    print > output_file
}
/-----END CERTIFICATE-----/ {
    close(output_file)
    output_file=""
}
' github-chain.pem
```

List the extracted certificates:

```bash
ls -lh github-certificates/
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

Count them again:

```bash
find github-certificates \
  -maxdepth 1 \
  -type f \
  -name 'cert-*.pem' \
  | wc -l
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

---

## Step 4 - Display the Subject and Issuer of Every Certificate

```bash
for cert in github-certificates/cert-*.pem
do
    echo
    echo "========================================"
    echo "CERTIFICATE: $cert"
    echo "========================================"

    openssl x509 \
      -in "$cert" \
      -noout \
      -subject \
      -issuer \
      -serial \
      -dates
done
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

---

## Step 5 - Identify the Role of Each Certificate

### Certificate 1

Inspect:

```bash
openssl x509 \
  -in github-certificates/cert-01.pem \
  -noout \
  -subject \
  -issuer \
  -ext basicConstraints
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

Expected role:

```text
Leaf certificate
```

The first certificate normally represents the website itself.

Typical indicators:

- Subject identifies `github.com`.
- Subject Alternative Name contains `github.com`.
- Basic Constraints contains `CA:FALSE`, or the certificate is not authorised as a CA.
- Extended Key Usage permits TLS Web Server Authentication.

---

### Certificate 2

Inspect:

```bash
openssl x509 \
  -in github-certificates/cert-02.pem \
  -noout \
  -subject \
  -issuer \
  -ext basicConstraints \
  -ext keyUsage
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

Expected role:

```text
Intermediate CA certificate
```

Typical indicators:

- The Subject matches the Issuer of the leaf certificate.
- Basic Constraints contains `CA:TRUE`.
- Key Usage includes `Certificate Sign` and possibly `CRL Sign`.
- The certificate signs leaf certificates but is itself signed by another CA.

---

## Step 6 - Demonstrate the Issuer-to-Subject Relationship

Display the leaf Issuer:

```bash
openssl x509 \
  -in github-certificates/cert-01.pem \
  -noout \
  -issuer
```

Display the intermediate Subject:

```bash
openssl x509 \
  -in github-certificates/cert-02.pem \
  -noout \
  -subject
```

Output:

```text
Leaf Issuer:
[PASTE YOUR REAL OUTPUT HERE]

Intermediate Subject:
[PASTE YOUR REAL OUTPUT HERE]
```

The Distinguished Names should match.

Conceptually:

```text
Leaf certificate Issuer
          =
Intermediate certificate Subject
```

This shows that the intermediate CA signed the leaf certificate.

---

## Step 7 - Identify the Root CA

Display the intermediate certificate's Issuer:

```bash
openssl x509 \
  -in github-certificates/cert-02.pem \
  -noout \
  -issuer
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

The Issuer identifies the next CA in the chain, normally the trusted root or another intermediate CA.

The server may not send the root certificate. The root is expected to exist in the operating system or browser trust store.

---

## Certificate Chain Structure

Complete this table with the real results:

| Position | File | Role | Subject | Issuer |
|---:|---|---|---|---|
| 1 | `cert-01.pem` | Leaf certificate | `[REAL SUBJECT]` | `[REAL ISSUER]` |
| 2 | `cert-02.pem` | Intermediate CA | `[REAL SUBJECT]` | `[REAL ISSUER]` |
| Trust store | System Root CA | Root CA | `[ROOT SUBJECT]` | `[ROOT ISSUER]` |

The root certificate is normally self-signed:

```text
Root Subject = Root Issuer
```

However, trust does not come merely from being self-signed. Trust comes from the root certificate being explicitly installed in the client's trusted CA store.

---

# Part 2 - Manual Chain Verification

## Step 1 - Identify the System CA Bundle

On Debian, Ubuntu, and Kali Linux, the CA bundle is commonly located at:

```text
/etc/ssl/certs/ca-certificates.crt
```

Confirm that it exists:

```bash
ls -lh /etc/ssl/certs/ca-certificates.crt
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

---

## Step 2 - Verify the Leaf with the Intermediate Certificate

For a chain containing one intermediate certificate:

```bash
openssl verify \
  -show_chain \
  -CAfile /etc/ssl/certs/ca-certificates.crt \
  -untrusted github-certificates/cert-02.pem \
  github-certificates/cert-01.pem
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

Expected successful format:

```text
github-certificates/cert-01.pem: OK
```

The `-show_chain` option may also display the chain that OpenSSL built.

### Explanation

The command uses:

- `cert-01.pem` as the target leaf certificate;
- `cert-02.pem` as the untrusted intermediate certificate;
- `/etc/ssl/certs/ca-certificates.crt` as the trusted root store.

The word `untrusted` does not mean that the intermediate is malicious. It means that the intermediate is provided as supporting chain material rather than as an independent trust anchor.

---

## More Than One Intermediate

If the server supplied multiple intermediate certificates, combine every intermediate except the leaf:

```bash
cat \
  github-certificates/cert-02.pem \
  github-certificates/cert-03.pem \
  > github-intermediates.pem
```

Then verify:

```bash
openssl verify \
  -show_chain \
  -CAfile /etc/ssl/certs/ca-certificates.crt \
  -untrusted github-intermediates.pem \
  github-certificates/cert-01.pem
```

Use this version only when your captured chain contains more than one intermediate.

---

## Step 3 - Verify Without the Intermediate

Now intentionally omit the intermediate certificate:

```bash
openssl verify \
  -show_chain \
  -CAfile /etc/ssl/certs/ca-certificates.crt \
  github-certificates/cert-01.pem
```

Output:

```text
[PASTE YOUR REAL ERROR HERE]
```

A common error is:

```text
error 20 at 0 depth lookup: unable to get local issuer certificate
```

The exact message depends on the local OpenSSL version and whether the intermediate certificate already exists in a local cache or CA store.

Check the exit code:

```bash
echo $?
```

Expected result on verification failure:

```text
2
```

Document the real value:

```text
[PASTE YOUR REAL EXIT CODE HERE]
```

---

## What This Demonstrates

The leaf certificate contains the name of its issuer, but it does not contain the issuer's complete certificate or public key. The client needs the intermediate certificate to verify the leaf signature and continue building the path to a trusted root. Therefore, a TLS server must send the leaf certificate together with the necessary intermediate certificates, while the root certificate is normally supplied by the client's trust store.

---

## Optional Live-Connection Verification

Verify the live GitHub connection against the operating system's trust store:

```bash
echo | openssl s_client \
  -connect github.com:443 \
  -servername github.com \
  -verify_return_error \
  -verify_hostname github.com 2>&1 \
  | tail -n 20
```

Look for:

```text
Verify return code: 0 (ok)
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

---

# Part 3 - Revocation Mechanisms

## Certificate Revocation List

A Certificate Revocation List is a digitally signed and time-stamped list of certificates revoked by a Certificate Authority before their normal expiration dates. Each revoked certificate is normally identified by its serial number, and clients download the CRL from a distribution point listed in the certificate. The client verifies the CRL signature and checks whether the certificate serial number appears in the list.

The principal limitations are size and freshness. A large CA may need to publish a large CRL containing many revoked certificates, creating bandwidth, storage, and processing overhead. Because CRLs are published periodically rather than continuously, a client may use an older CRL and temporarily miss a recent revocation.

### CRL Process

```text
Client receives certificate
          |
          v
Client downloads CRL
          |
          v
Client verifies CA signature on CRL
          |
          v
Client searches for certificate serial number
          |
          +--> Serial present: certificate revoked
          |
          +--> Serial absent: not listed as revoked
```

---

## Online Certificate Status Protocol

OCSP allows a client to ask an authorised responder for the status of a specific certificate rather than downloading a complete revocation list.

Possible responses include:

```text
good
revoked
unknown
```

OCSP reduces the amount of data transferred because the client requests the status of one certificate. It can also provide fresher status information than a periodically downloaded CRL.

A limitation is that ordinary OCSP introduces an additional network request and may reveal to the OCSP responder which website the user is visiting. It also creates a dependency on the availability and performance of the OCSP responder.

---

## OCSP Stapling

With OCSP Stapling, the web server periodically obtains a signed OCSP response from the CA and includes that response in the TLS handshake.

```text
Web server requests OCSP status from CA
                  |
                  v
CA returns signed status response
                  |
                  v
Server stores response temporarily
                  |
                  v
Server sends certificate + OCSP response to client
```

Advantages include:

- fewer client requests to the CA;
- improved privacy;
- reduced OCSP responder load;
- faster certificate-status validation;
- continued verification when the client cannot directly contact the responder.

The client must still verify that the stapled response is correctly signed and within its permitted validity period.

---

# MedDefense Private-Key Compromise Response

## Scenario

Assume the private key for:

```text
portal.meddefense.com
```

is accidentally exposed in a public or accessible Git repository.

The key must be treated as compromised immediately. Deleting the Git file alone is not sufficient because the key may already have been copied, cached, forked, cloned, or indexed.

---

## Required Response Sequence

### 1. Activate Incident Response

MedDefense must immediately create a security incident and notify:

- James Chen, Deputy CISO;
- Sarah Park, IT Director;
- the Security Analyst;
- the application owner;
- Legal and Compliance where required;
- the Certificate Authority account owner.

The incident should record:

- when the key was committed;
- where it was exposed;
- how long it was accessible;
- which systems used the key;
- whether the repository was public;
- whether there is evidence of unauthorised access.

---

### 2. Remove Public Exposure

Remove the private key from:

- the current repository;
- Git history;
- branches;
- tags;
- releases;
- build artefacts;
- CI/CD logs;
- backups where practical;
- developer workstations.

Repository history must be rewritten using an approved method.

However, removal does not restore trust in the key. The key remains permanently compromised.

---

### 3. Revoke the Existing Certificate

Use the CA's revocation process or ACME client to revoke the certificate.

The revocation reason should indicate:

```text
keyCompromise
```

where supported.

The certificate's serial number must be added to the CA's revocation information through CRL and/or OCSP.

The old certificate must never be reused.

---

### 4. Generate a New Private Key

Generate a completely new private key on the destination system or in an approved key-management platform.

Example RSA option:

```bash
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out portal-meddefense-new.key
```

Example ECC option:

```bash
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out portal-meddefense-new.key
```

Protect it:

```bash
chmod 600 portal-meddefense-new.key
```

The new private key must not be generated from, derived from, or copied from the compromised key.

---

### 5. Create a New CSR

Example:

```bash
openssl req \
  -new \
  -key portal-meddefense-new.key \
  -out portal-meddefense-new.csr \
  -subj "/CN=portal.meddefense.com" \
  -addext "subjectAltName=DNS:portal.meddefense.com,DNS:login.meddefense.com"
```

The real SAN list must match the production DNS design.

---

### 6. Request a Replacement Certificate

Submit the CSR to the approved public CA or use ACME automation.

The replacement certificate must:

- use the new public key;
- contain the correct SAN entries;
- permit TLS Web Server Authentication;
- use approved algorithms;
- build to a trusted CA root.

---

### 7. Install the New Certificate and Full Chain

Install:

- the new leaf certificate;
- all required intermediate certificates;
- the new private key.

Update the web-server or load-balancer configuration and reload the service.

Example validation:

```bash
openssl s_client \
  -connect portal.meddefense.com:443 \
  -servername portal.meddefense.com \
  -showcerts </dev/null
```

---

### 8. Verify the Replacement

Confirm:

- hostname validation;
- correct SAN entries;
- trusted chain;
- expected serial number;
- new public-key fingerprint;
- validity period;
- TLS server Extended Key Usage;
- successful OCSP or CRL status;
- no presentation of the revoked certificate;
- application availability.

---

### 9. Rotate Copies and Dependent Secrets

Search for and replace every copy of the compromised key on:

- production servers;
- staging systems;
- load balancers;
- reverse proxies;
- backup systems;
- deployment servers;
- developer workstations;
- secret stores;
- configuration-management platforms.

If the repository contained other credentials, tokens, or secrets, rotate them as well.

---

### 10. Monitor and Investigate

Review:

- Git access logs;
- web-server logs;
- Wazuh SIEM alerts;
- certificate transparency information;
- authentication events;
- proxy logs;
- network traffic;
- indicators of impersonation or MITM activity.

Continue monitoring for attempted use of the old certificate or key.

---

### 11. Prevent Recurrence

Implement:

- secret scanning in Git and CI/CD;
- pre-commit hooks;
- protected secret stores;
- restricted certificate-key access;
- automated certificate inventory;
- certificate expiration and revocation monitoring;
- documented certificate incident procedures;
- developer security training.

---

# Part 4 - Trust Store Exploration

## Step 1 - Locate the Linux Trust Store

Common locations include:

```text
/etc/ssl/certs/
/etc/ssl/certs/ca-certificates.crt
/usr/local/share/ca-certificates/
```

Inspect them:

```bash
ls -ld /etc/ssl/certs
```

```bash
ls -lh /etc/ssl/certs/ca-certificates.crt
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

---

## Step 2 - Count Trusted CA Certificates

Count the PEM certificates in the system CA bundle:

```bash
grep -c \
  "BEGIN CERTIFICATE" \
  /etc/ssl/certs/ca-certificates.crt
```

Output:

```text
[PASTE YOUR REAL NUMBER HERE]
```

This is the number of certificates contained in the selected CA bundle. The precise count depends on:

- the Linux distribution;
- installed CA packages;
- local organisational CAs;
- system updates;
- administrator configuration.

Do not assume every certificate in every trust-store implementation is necessarily an independent public root. The command documents the number of certificates in this specific PEM bundle.

---

## Step 3 - Select a Root CA Certificate

List hashed CA links:

```bash
find /etc/ssl/certs \
  -maxdepth 1 \
  -type l \
  -name '*.0' \
  | head
```

Select one candidate:

```bash
root_link="$(find /etc/ssl/certs \
  -maxdepth 1 \
  -type l \
  -name '*.0' \
  | head -n 1)"
```

Display the selected path:

```bash
echo "$root_link"
```

Resolve the actual file:

```bash
root_file="$(readlink -f "$root_link")"
echo "$root_file"
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

---

## Step 4 - Inspect the Selected CA Certificate

```bash
openssl x509 \
  -in "$root_file" \
  -noout \
  -subject \
  -issuer \
  -serial \
  -dates
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

Inspect CA properties:

```bash
openssl x509 \
  -in "$root_file" \
  -noout \
  -ext basicConstraints \
  -ext keyUsage
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

Inspect the public key and signature:

```bash
openssl x509 \
  -in "$root_file" \
  -text \
  -noout \
  | grep -E \
  "Signature Algorithm|Public Key Algorithm|Public-Key:"
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

---

## Step 5 - Confirm Whether It Is Self-Signed

Display the Subject:

```bash
openssl x509 \
  -in "$root_file" \
  -noout \
  -subject
```

Display the Issuer:

```bash
openssl x509 \
  -in "$root_file" \
  -noout \
  -issuer
```

For a typical root CA:

```text
Subject = Issuer
```

Verify its self-signature:

```bash
openssl verify \
  -CAfile "$root_file" \
  "$root_file"
```

Expected result:

```text
/root/path/certificate.pem: OK
```

Document the real output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

---

## Selected Root CA Profile

| Field | Value |
|---|---|
| File | `[REAL PATH]` |
| Subject | `[REAL SUBJECT]` |
| Issuer | `[REAL ISSUER]` |
| Serial Number | `[REAL SERIAL]` |
| Not Before | `[REAL DATE]` |
| Not After | `[REAL DATE]` |
| Signature Algorithm | `[REAL ALGORITHM]` |
| Public Key Algorithm | `[REAL ALGORITHM]` |
| Public Key Size | `[REAL SIZE]` |
| Basic Constraints | `[REAL VALUE]` |
| Key Usage | `[REAL VALUE]` |
| Self-Signed | Yes or No, based on evidence |

---

## Root CA Validity Analysis

Root CA certificates frequently have much longer validity periods than ordinary website certificates. A website certificate may last only weeks or months, while a root CA may remain valid for decades.

This initially appears surprising because shorter certificate validity is normally preferred. However, replacing a root CA affects operating systems, browsers, applications, appliances, and embedded devices worldwide. Root certificates therefore require long, carefully managed lifecycles, while their private keys are expected to receive exceptionally strong offline or hardware-backed protection.

A long validity period does not mean that the root can never be distrusted. Operating-system and browser vendors can remove a root from their trust stores if the CA is compromised, mismanaged, or no longer compliant.

---

# Chain-of-Trust Diagram

```text
Trusted Root CA
Stored in the Linux or browser trust store
Subject = Root CA
Issuer = Root CA
        |
        | Signs
        v
Intermediate CA
Sent by the TLS server
Subject = Intermediate CA
Issuer = Root CA
        |
        | Signs
        v
Leaf Certificate
Sent by the TLS server
Subject = github.com
Issuer = Intermediate CA
```

Trust flows downward:

```text
Client explicitly trusts Root
             |
             v
Root signature validates Intermediate
             |
             v
Intermediate signature validates Leaf
             |
             v
Leaf identity and usage are checked
             |
             v
TLS server is trusted
```

---

# Why Intermediate CAs Exist

Root CA private keys are highly sensitive trust anchors. They should not be used continuously to issue ordinary website certificates.

Intermediate CAs provide separation:

- the root key can remain offline or tightly controlled;
- the intermediate can perform operational certificate issuance;
- an intermediate can be revoked or replaced without replacing every root;
- different intermediates can enforce different policies;
- the impact of a compromised issuing CA is more contained than direct routine use of the root key.

---

# Final Conclusions

This laboratory demonstrates that a website certificate is not trusted independently. Trust is established through a certification path from the leaf certificate, through one or more intermediate CAs, to a root CA explicitly trusted by the client.

The server must send the leaf certificate and all necessary intermediate certificates. The root certificate is normally omitted because it already exists in the client's trust store. Removing the intermediate breaks manual path construction and commonly produces an `unable to get local issuer certificate` error.

CRLs and OCSP allow certificates to be invalidated before their expiration dates. CRLs distribute signed lists of revoked serial numbers, while OCSP provides certificate-specific status responses. OCSP Stapling allows the server to deliver a recent signed status response during the TLS handshake.

If a MedDefense private key is exposed, the certificate must be revoked, a new key pair must be generated, a replacement certificate must be issued and deployed, all copies of the old key must be removed, and the incident must be investigated. Simply deleting the exposed key from Git does not restore security.

The trust-store exploration demonstrates that operating systems trust many root CAs and that root certificates often have very long validity periods. This is necessary for global stability but also shows why root CA governance and trust-store management are critical security responsibilities.
